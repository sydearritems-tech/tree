"""
Uranium Insta-Lookup — standalone Instagram profile lookup API (Vercel Python).

v2: shared-key auth + one-time operation ids (nonce+timestamp) + replay lock.
Nothing on this endpoint is usable by anyone who does not hold the shared key,
and a captured request (e.g. via an HTTP spy on a leaked client) is worth
exactly one already-consumed operation id: it cannot be replayed by anyone,
including the original caller, after the 90s window or once used.

Endpoints:
  GET  /health                                  -> open uptime probe only
  POST / {"action":"instagram_lookup",
          "username":"...", "key":"...",
          "nonce":"...", "ts":<unix>}           -> the client path (Lua uses this)
  GET  /?username=... (headers x-insta-key,
       x-op-nonce, x-op-ts)                     -> same, for quick manual checks
  GET  /img?username=... (same auth)            -> 302 to HD profile picture

Everything else: 404 with no information. No usage text, no upstream error
details in responses (they stay in the instance log).

Upstreams (tried in order, first hit wins):
  1. i.instagram.com  web_profile_info   (rich JSON, no login)
  2. instagram.com    legacy ?__a=1      (regional leftovers)
  3. instagram.com    public OG scrape   (meta tags + embedded JSON regexes)
A definitive "user: null" short-circuits to 404 USER_NOT_FOUND.

Optimizations: keep-alive session with pooled connections, headers pre-built
once, cache-first (180s ok / 60s fail, bounded LRU), pure-function core (no
handler dependencies), .python-version pins the runtime, vercel.json caps
maxDuration. Rate limit: 40 req/min/IP (best-effort per warm instance).
"""

import hashlib
import hmac
import json
import os
import re
import threading
import time
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, quote

import requests

# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------
UPSTREAM_TIMEOUT = float(os.environ.get("IG_UPSTREAM_TIMEOUT", "12"))
CACHE_TTL_OK = int(os.environ.get("IG_CACHE_TTL_OK", "180"))
CACHE_TTL_FAIL = int(os.environ.get("IG_CACHE_TTL_FAIL", "60"))
CACHE_MAX_ENTRIES = 256
RATE_WINDOW = 60.0
RATE_MAX_PER_WINDOW = int(os.environ.get("IG_RATE_MAX", "40"))

# auth ---------------------------------------------------------------------
INSTA_SHARED_KEY = os.environ.get("INSTA_SHARED_KEY", "").strip()
OP_TS_WINDOW = 90  # seconds of validity for a client operation id
NONCE_STORE_TTL = 240  # keep seen nonces at least 2x the validity window

UPSTREAM_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "x-ig-app-id": os.environ.get("IG_APP_ID", "936619743392459"),
}
JSON_HEADERS = dict(UPSTREAM_HEADERS, **{"Accept": "application/json"})
HTML_HEADERS = dict(UPSTREAM_HEADERS, **{"Accept": "text/html,application/xhtml+xml"})

USERNAME_RE = re.compile(r"^[A-Za-z0-9._]{1,30}$")

# keep-alive session shared across warm invocations (Vercel reuses containers)
_SESSION = requests.Session()
try:
    _adapter = requests.adapters.HTTPAdapter(pool_connections=4, pool_maxsize=8)
    _SESSION.mount("https://", _adapter)
except Exception:
    pass


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def parse_count(value):
    """Normalize Instagram counters (int, '12.4k', '3,456', '2 million')."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return max(0, int(value))
    text = str(value).strip().lower().replace(",", "").replace(" ", "")
    text = re.sub(
        r"(million|billion|thousand)$",
        lambda m: {"million": "m", "billion": "b", "thousand": "k"}[m.group(1)],
        text,
    )
    match = re.match(r"^([\d.]+)([kmb])?$", text)
    if not match:
        return None
    try:
        number = float(match.group(1))
    except ValueError:
        return None
    mult = {"k": 1_000, "m": 1_000_000, "b": 1_000_000_000}.get(match.group(2), 1)
    return max(0, int(number * mult))


def clean_username(raw):
    if raw is None:
        return None
    text = str(raw).strip().lstrip("@").lower()
    text = re.sub(r"^https?://(www\.)?instagram\.com/", "", text)
    text = text.strip("/?.&").split("?")[0].split("/")[0]
    return text if USERNAME_RE.match(text) else None


def normalize_profile(user):
    if not isinstance(user, dict):
        return None
    username = str(user.get("username") or "").lower()
    if not username:
        return None
    external = ""
    link = user.get("external_url_link")
    if isinstance(link, dict):
        external = str(link.get("url") or "")
    if not external:
        external = str(user.get("external_url") or "")
    counts = user.get("edge_followed_by")
    following = user.get("edge_follow")
    media = user.get("edge_owner_to_timeline_media")
    return {
        "username": username,
        "full_name": str(user.get("full_name") or ""),
        "biography": str(user.get("biography") or ""),
        "external_url": external,
        "is_verified": bool(user.get("is_verified")),
        "is_private": bool(user.get("is_private")),
        "posts": media.get("count") if isinstance(media, dict) else None,
        "followers": parse_count(counts.get("count") if isinstance(counts, dict) else None),
        "following": parse_count(following.get("count") if isinstance(following, dict) else None),
        "avatar_url": str(user.get("profile_pic_url_hd") or user.get("profile_pic_url") or ""),
        "business_category": str(user.get("category_name") or ""),
    }


# --------------------------------------------------------------------------
# auth: shared key + one-time operation (nonce + ts)
# --------------------------------------------------------------------------
class _NonceStore:
    """Single-use operation ids with TTL pruning."""

    def __init__(self, lock):
        self._seen = OrderedDict()
        self._lock = lock

    def consume(self, nonce):
        """True if nonce is fresh; False if already used."""
        now = time.time()
        with self._lock:
            while self._seen:
                _, exp = next(iter(self._seen.values()))
                if exp >= now:
                    break
                self._seen.popitem(last=False)
            if nonce in self._seen:
                return False
            self._seen[nonce] = (hashlib.sha256(nonce.encode()).hexdigest()[:16], now + NONCE_STORE_TTL)
            while len(self._seen) > 50000:
                self._seen.popitem(last=False)
            return True


_NONCES = _NonceStore(threading.Lock())


def check_operation(key, nonce, ts):
    """-> (ok, error_code|None). Pure except for nonce consumption."""
    if not INSTA_SHARED_KEY:
        return False, "CONFIG_MISSING"
    if not isinstance(key, str) or not hmac.compare_digest(key.encode("utf-8", "ignore"), INSTA_SHARED_KEY.encode()):
        return False, "INVALID_KEY"
    try:
        ts_val = float(ts)
    except (TypeError, ValueError):
        return False, "MISSING_TIMESTAMP"
    if abs(time.time() - ts_val) > OP_TS_WINDOW:
        return False, "STALE_TIMESTAMP"
    if not isinstance(nonce, str) or len(nonce) < 8 or len(nonce) > 128:
        return False, "MISSING_NONCE"
    if not _NONCES.consume(nonce):
        return False, "REPLAY_DETECTED"
    return True, None


def _creds_from(headers, query, body):
    body = body if isinstance(body, dict) else {}
    key = str(body.get("key") or (headers.get("x-insta-key") if headers else "") or (query.get("k") or [""])[0])
    nonce = str(body.get("nonce") or (headers.get("x-op-nonce") if headers else "") or (query.get("n") or [""])[0])
    ts = body.get("ts") or (headers.get("x-op-ts") if headers else "") or (query.get("t") or [""])[0]
    return key, nonce, ts


# --------------------------------------------------------------------------
# upstream fetchers (all via the pooled session)
# --------------------------------------------------------------------------
def _fetch_web_profile(username):
    """(profile|None, err|None). 'NOT_FOUND' is a definitive answer."""
    try:
        resp = _SESSION.get(
            "https://i.instagram.com/api/v1/users/web_profile_info/",
            params={"username": username},
            headers=UPSTREAM_HEADERS,
            timeout=UPSTREAM_TIMEOUT,
        )
    except requests.RequestException:
        return None, "unreachable"
    if resp.status_code == 404:
        return None, "NOT_FOUND"
    if resp.status_code in (429, 503):
        return None, "rate_limited"
    if resp.status_code != 200:
        return None, f"http_{resp.status_code}"
    try:
        payload = resp.json()
    except ValueError:
        return None, "bad_json"
    user = (payload or {}).get("data", {}).get("user")
    if user is None:
        return None, "NOT_FOUND"
    return normalize_profile(user), None


def _fetch_private_api_json(username):
    url = f"https://www.instagram.com/{quote(username)}/"
    try:
        resp = _SESSION.get(url, params={"__a": "1", "__d": "dis"}, headers=JSON_HEADERS, timeout=UPSTREAM_TIMEOUT)
    except requests.RequestException:
        return None, "unreachable"
    if resp.status_code != 200:
        return None, f"http_{resp.status_code}"
    text = (resp.text or "").strip()
    brace = text.find("{")
    if brace < 0:
        return None, "not_json"
    try:
        payload = json.loads(text[brace:])
    except ValueError:
        return None, "bad_json"
    user = (payload or {}).get("data", {}).get("user") or (payload or {}).get("user") or {}
    if not isinstance(user, dict):
        return None, "no_user"
    profile = normalize_profile(user) or normalize_profile(user.get("graphql") or {})
    if not profile:
        return None, "no_user"
    return profile, None


_OG_TITLE_RE = re.compile(r"<meta\s+(?:property|name)=[\"']og:title[\"']\s+content=[\"']([^\"']*)[\"']", re.IGNORECASE)
_OG_DESC_RE = re.compile(r"<meta\s+(?:property|name)=[\"']og:description[\"']\s+content=[\"']([^\"']*)[\"']", re.IGNORECASE)
_OG_IMAGE_RE = re.compile(r"<meta\s+(?:property|name)=[\"']og:image[\"']\s+content=[\"']([^\"']*)[\"']", re.IGNORECASE)
_DESC_JSON_RE = re.compile(r'"biography"\s*:\s*"((?:[^"\\]|\\.)*)"')
_PIC_JSON_RE = re.compile(r'"profile_pic_url_hd"\s*:\s*"((?:[^"\\]|\\.)*)"')
_TITLE_NAME_RE = re.compile(r"^(.*?)\s*\(@([\w.]+)\)")
_OG_COUNTS_RE = re.compile(r"([\d.,kKmM]+)\s*Followers,\s*([\d.,kKmM]+)\s*Following,\s*([\d.,kKmM]+)\s*Posts")
_FULLNAME_JSON_RE = re.compile(r'"full_name"\s*:\s*"((?:[^"\\]|\\.)*)"')


def _json_escape_decode(text):
    try:
        return json.loads('"' + text + '"')
    except ValueError:
        return text.replace("\\/", "/").replace('\\"', '"')


def _fetch_og_scrape(username):
    url = f"https://www.instagram.com/{quote(username)}/"
    try:
        resp = _SESSION.get(url, headers=HTML_HEADERS, timeout=UPSTREAM_TIMEOUT)
    except requests.RequestException:
        return None, "unreachable"
    if resp.status_code == 404:
        return None, "NOT_FOUND"
    if resp.status_code != 200:
        return None, f"http_{resp.status_code}"
    html = resp.text or ""
    if "This account doesn't exist" in html or "Sorry, this page isn't available" in html:
        return None, "NOT_FOUND"
    profile = {
        "username": username,
        "full_name": "",
        "biography": "",
        "external_url": "",
        "is_verified": bool(re.search(r'"is_verified"\s*:\s*true', html)),
        "is_private": bool(re.search(r'"is_private"\s*:\s*true', html)),
        "posts": None,
        "followers": None,
        "following": None,
        "avatar_url": "",
        "business_category": "",
    }
    img = _OG_IMAGE_RE.search(html)
    if img:
        profile["avatar_url"] = _json_escape_decode(img.group(1))
    else:
        pic = _PIC_JSON_RE.search(html)
        if pic:
            profile["avatar_url"] = _json_escape_decode(pic.group(1))
    tmatch = _OG_TITLE_RE.search(html)
    if tmatch:
        raw_title = _json_escape_decode(tmatch.group(1))
        nmatch = _TITLE_NAME_RE.match(raw_title)
        if nmatch:
            profile["full_name"] = nmatch.group(1).strip(" ()").strip()
        elif raw_title:
            profile["full_name"] = re.sub(r"\s*.*Profile\s*•\s*Instagram.*$", "", raw_title).strip()
    desc_match = _OG_DESC_RE.search(html)
    if desc_match:
        desc = _json_escape_decode(desc_match.group(1))
        cmatch = _OG_COUNTS_RE.search(desc)
        if cmatch:
            profile["followers"] = parse_count(cmatch.group(1))
            profile["following"] = parse_count(cmatch.group(2))
            profile["posts"] = parse_count(cmatch.group(3))
    bio = _DESC_JSON_RE.search(html)
    if bio:
        profile["biography"] = _json_escape_decode(bio.group(1))[:2000]
    if not profile["full_name"]:
        fn = _FULLNAME_JSON_RE.search(html)
        if fn:
            profile["full_name"] = _json_escape_decode(fn.group(1))
    return profile, None


FETCH_CHAIN = (_fetch_web_profile, _fetch_private_api_json, _fetch_og_scrape)


# --------------------------------------------------------------------------
# cache + rate limiter
# --------------------------------------------------------------------------
class _TtlCache:
    def __init__(self, max_entries, lock):
        self._data = OrderedDict()
        self._max = max_entries
        self._lock = lock

    def get(self, key):
        with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            expires_at, value = item
            if expires_at < time.time():
                self._data.pop(key, None)
                return None
            self._data.move_to_end(key)
            return value

    def set(self, key, value, ttl):
        with self._lock:
            self._data[key] = (time.time() + ttl, value)
            self._data.move_to_end(key)
            while len(self._data) > self._max:
                self._data.popitem(last=False)


class _RateLimiter:
    def __init__(self, max_per_window, lock):
        self._hits = {}
        self._max = max_per_window
        self._lock = lock

    def allow(self, ip):
        now = time.time()
        with self._lock:
            bucket = self._hits.get(ip)
            if not bucket or now - bucket[1] > RATE_WINDOW:
                self._hits[ip] = [1, now]
                return True
            if bucket[0] >= self._max:
                return False
            bucket[0] += 1
            return True


_LOCK = threading.Lock()
_CACHE = _TtlCache(CACHE_MAX_ENTRIES, _LOCK)
_LIMITER = _RateLimiter(RATE_MAX_PER_WINDOW, _LOCK)


# --------------------------------------------------------------------------
# lookup core (pure; auth is layered on top by the handler)
# --------------------------------------------------------------------------
def lookup_instagram(raw_username):
    """-> (status:int, payload:dict)."""
    username = clean_username(raw_username)
    if not username:
        return 400, {"success": False, "error": "INVALID_USERNAME"}

    cached = _CACHE.get(username)
    if cached is not None:
        status, payload = cached
        payload = dict(payload)
        payload["cached"] = True
        return status, payload

    profile = None
    saw_rate = False
    for fetcher in FETCH_CHAIN:
        result, err = fetcher(username)
        if result:
            profile = result
            break
        if err == "NOT_FOUND":
            payload = {"success": False, "error": "USER_NOT_FOUND"}
            _CACHE.set(username, (404, payload), CACHE_TTL_FAIL)
            return 404, payload
        if err == "rate_limited":
            saw_rate = True

    if profile is None:
        payload = {"success": False, "error": "RATE_LIMITED" if saw_rate else "UPSTREAM_UNAVAILABLE"}
        print(f"[insta-lookup] upstream failure user={username} rate={saw_rate}")
        _CACHE.set(username, (502, payload), CACHE_TTL_FAIL)
        return 502, payload

    profile = {k: v for k, v in profile.items() if v not in (None, "")}
    profile.setdefault("username", username)
    profile["fetched_at"] = int(time.time())
    payload = {"success": True, "data": profile}
    _CACHE.set(username, (200, payload), CACHE_TTL_OK)
    return 200, payload


# --------------------------------------------------------------------------
# HTTP handler
# --------------------------------------------------------------------------
class handler(BaseHTTPRequestHandler):
    server_version = "UraniumInstaLookup/2.0"

    def log_message(self, fmt, *args):  # keep the runtime log quiet
        pass

    def _json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, x-insta-key, x-op-nonce, x-op-ts")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    _DENY_STATUS = {
        "INVALID_KEY": 401, "STALE_TIMESTAMP": 401, "MISSING_TIMESTAMP": 401,
        "MISSING_NONCE": 400, "REPLAY_DETECTED": 403, "CONFIG_MISSING": 503,
        "USER_NOT_FOUND": 404, "NOT_FOUND": 404, "BAD_BODY": 400,
        "BAD_JSON": 400, "UNKNOWN_ACTION": 400, "INTERNAL": 500,
    }

    def _deny(self, code):
        # no internals: one code, nothing else
        self._json({"success": False, "error": code}, self._DENY_STATUS.get(code, 400))

    def _client_ip(self):
        fwd = str(self.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        return fwd or (self.client_address[0] if self.client_address else "unknown")

    def _rate_ok(self):
        if not _LIMITER.allow(self._client_ip()):
            self._json({"success": False, "error": "RATE_LIMITED"}, 429)
            return False
        return True

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, x-insta-key, x-op-nonce, x-op-ts")
        self.send_header("Access-Control-Max-Age", "86400")
        self.end_headers()

    def do_GET(self):
        try:
            raw_path = self.headers.get("X-Matched-Path") or self.path
            parsed = urlparse(raw_path)
            if not (parsed.query or ""):
                parsed = parsed._replace(query=urlparse(self.path).query)
            path = parsed.path.rstrip("/") or "/"
            if path == "/health":
                self._json({"success": True, "ok": True, "t": int(time.time())})
                return
            if path in ("", "/", "/api/index.py", "/api", "/index"):
                params = parse_qs(parsed.query)
                username = (params.get("username") or params.get("u") or [""])[0]
                if not username:
                    self._json({"ok": True})  # liveness only; no usage disclosure
                    return
                if not self._rate_ok():
                    return
                ok, err = check_operation(*_creds_from(self.headers, params, None))
                if not ok:
                    self._deny(err)
                    return
                status, payload = lookup_instagram(username)
                self._json(payload, status)
                return
            if path == "/img":
                params = parse_qs(parsed.query)
                username = (params.get("username") or params.get("u") or [""])[0]
                if not username:
                    self._deny("NOT_FOUND")
                    return
                if not self._rate_ok():
                    return
                ok, err = check_operation(*_creds_from(self.headers, params, None))
                if not ok:
                    self._deny(err)
                    return
                status, payload = lookup_instagram(username)
                avatar = ((payload or {}).get("data") or {}).get("avatar_url") if status == 200 else None
                if avatar:
                    self.send_response(302)
                    self.send_header("Location", avatar)
                    self.send_header("Cache-Control", f"public, max-age={CACHE_TTL_OK}")
                    self.end_headers()
                    return
                self._deny("NOT_FOUND")
                return
            self._deny("NOT_FOUND")
        except Exception:
            self._json({"success": False, "error": "INTERNAL"}, 500)

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > 16384:
                self._json({"success": False, "error": "BAD_BODY"}, 400)
                return
            data = {}
            try:
                data = json.loads(self.rfile.read(length).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                self._json({"success": False, "error": "BAD_JSON"}, 400)
                return
            if not isinstance(data, dict):
                self._json({"success": False, "error": "BAD_BODY"}, 400)
                return
            action = str(data.get("action") or "instagram_lookup").lower().strip()
            if action not in ("instagram_lookup", "ig_lookup", "lookup", "instagram", "profile"):
                self._json({"success": False, "error": "UNKNOWN_ACTION"}, 400)
                return
            if not self._rate_ok():
                return
            # body credentials only here; the Lua client uses this path
            ok, err = check_operation(*_creds_from(self.headers, {}, data))
            if not ok:
                self._deny(err)
                return
            username = data.get("username") or data.get("query") or data.get("u")
            status, payload = lookup_instagram(username)
            self._json(payload, status)
        except Exception:
            self._json({"success": False, "error": "INTERNAL"}, 500)
