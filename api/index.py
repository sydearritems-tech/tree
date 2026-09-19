"""
Uranium Insta-Lookup — standalone Instagram profile lookup API (Vercel Python).

Completely independent from the main Uranium API (no keys, no plans, no
Supabase). One deployment, one job: username in -> normalized public profile
data out.

Endpoints (all public):
  GET  /?username=<handle>        -> lookup (handle may include a leading @)
  GET  /api/index.py?username=... -> same (direct-invocation fallback)
  GET  /img?username=<handle>     -> 302 to the HD profile picture (for
                                     clients that cannot follow CDN refs)
  GET  /health                    -> {"success": true, ...}
  POST / {"action":"instagram_lookup","username":"..."}

Upstreams (tried in order, first hit wins):
  1. i.instagram.com  web_profile_info  (rich JSON, no auth needed)
  2. instagram.com    legacy ?__a=1     (sometimes still serves JSON)
  3. instagram.com    public page       (Open Graph + embedded JSON scrape)
A definitive "user: null" from step 1 short-circuits to 404 USER_NOT_FOUND,
so missing accounts never trigger extra hammering.

Results are cached in-process (180s ok / 60s failures) with a bounded LRU,
plus a lightweight best-effort per-IP rate limit (serverless instances are
small buckets; put a real limiter in front if you ever need one).
"""

import json
import os
import re
import time
import threading
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

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
IG_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "x-ig-app-id": os.environ.get("IG_APP_ID", "936619743392459"),
}
USERNAME_RE = re.compile(r"^[A-Za-z0-9._]{1,30}$")

# "3.456", "12.4k", "1.2 million", "1200000" -> int
_COUNT_RE = re.compile(r"([\d.,]+)\s*([km])?|([\d.,]+)", re.IGNORECASE)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def parse_count(value):
    """Normalize Instagram follower counters (int, '12.4k', '3,456', ...)."""
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return max(0, int(value))
    text = str(value).strip().lower().replace(",", "").replace(" ", "")
    text = re.sub(r"(million|billion|thousand)$", lambda m: {"million": "m", "billion": "b", "thousand": "k"}[m.group(1)], text)
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
    """web_profile_info user object -> compact, GUI-ready payload."""
    if not isinstance(user, dict):
        return None
    username = str(user.get("username") or "").lower()
    if not username:
        return None
    full_name = str(user.get("full_name") or "")
    biography = str(user.get("biography") or "")
    external = ""
    for item in user.get("external_url_link") and [user.get("external_url_link")] or []:
        if isinstance(item, dict):
            external = str(item.get("url") or "")
            break
    if not external:
        external = str(user.get("external_url") or "")
    counts = user.get("edge_followed_by")
    following = user.get("edge_follow")
    media = user.get("edge_owner_to_timeline_media")
    return {
        "username": username,
        "full_name": full_name,
        "biography": biography,
        "external_url": external,
        "is_verified": bool(user.get("is_verified")),
        "is_private": bool(user.get("is_private")),
        "posts": (media or {}).get("count") if isinstance(media, dict) else None,
        "followers": parse_count(counts.get("count") if isinstance(counts, dict) else None),
        "following": parse_count(following.get("count") if isinstance(following, dict) else None),
        "avatar_url": str(user.get("profile_pic_url_hd") or user.get("profile_pic_url") or ""),
        "business_category": str(user.get("category_name") or ""),
    }


# --------------------------------------------------------------------------
# upstream fetchers
# --------------------------------------------------------------------------
def _fetch_web_profile(username):
    """(profile|None, error|None). error 'NOT_FOUND' is definitive."""
    try:
        resp = requests.get(
            "https://i.instagram.com/api/v1/users/web_profile_info/",
            params={"username": username},
            headers=IG_HEADERS,
            timeout=UPSTREAM_TIMEOUT,
        )
    except requests.RequestException as exc:
        return None, f"web_profile_unreachable:{type(exc).__name__}"
    if resp.status_code == 404:
        return None, "NOT_FOUND"
    if resp.status_code in (429, 503):
        return None, f"web_profile_rate_limited:{resp.status_code}"
    if resp.status_code != 200:
        return None, f"web_profile_http_{resp.status_code}"
    try:
        payload = resp.json()
    except ValueError:
        return None, "web_profile_bad_json"
    user = (payload or {}).get("data", {}).get("user")
    if user is None:
        return None, "NOT_FOUND"
    return normalize_profile(user), None


def _fetch_private_api_json(username):
    """Legacy ?__a=1 endpoint; works on some regions/rollouts only."""
    try:
        resp = requests.get(
            f"https://www.instagram.com/{quote(username)}/",
            params={"__a": "1", "__d": "dis"},
            headers={**IG_HEADERS, "Accept": "application/json"},
            timeout=UPSTREAM_TIMEOUT,
        )
    except requests.RequestException as exc:
        return None, f"legacy_unreachable:{type(exc).__name__}"
    if resp.status_code != 200:
        return None, f"legacy_http_{resp.status_code}"
    text = (resp.text or "").strip()
    brace = text.find("{")
    if brace < 0:
        return None, "legacy_not_json"
    try:
        payload = json.loads(text[brace:])
    except ValueError:
        return None, "legacy_bad_json"
    user = (payload or {}).get("data", {}).get("user") or (payload or {}).get("user") or {}
    graf = ((user.get("graphql") or {}) if isinstance(user, dict) else {})
    profile = normalize_profile(user) or normalize_profile(graf)
    if not profile:
        return None, "legacy_no_user"
    # legacy shape nests some fields under graphql
    extra = graf or {}
    def _pick(key, path_count):
        node = extra.get(path_count)
        return node.get("count") if isinstance(node, dict) else None
    for field, path in (("followers", "edge_followed_by"), ("following", "edge_follow"), ("posts", "edge_owner_to_timeline_media")):
        if profile.get(field) in (None, "") and _pick(field, path) is not None:
            profile[field] = parse_count(_pick(field, path))
    if not profile.get("avatar_url"):
        profile["avatar_url"] = str(extra.get("profile_pic_url_hd") or extra.get("profile_pic_url") or "")
    return profile, None


_OG_TITLE_RE = re.compile(r"<meta\s+(?:property|name)=[\"']og:title[\"']\s+content=[\"']([^\"']*)[\"']", re.IGNORECASE)
_OG_DESC_RE = re.compile(r"<meta\s+(?:property|name)=[\"']og:description[\"']\s+content=[\"']([^\"']*)[\"']", re.IGNORECASE)
_OG_IMAGE_RE = re.compile(r"<meta\s+(?:property|name)=[\"']og:image[\"']\s+content=[\"']([^\"']*)[\"']", re.IGNORECASE)
_DESC_JSON_RE = re.compile(r'"biography"\s*:\s*"((?:[^"\\]|\\.)*)"')
_PIC_JSON_RE = re.compile(r'"profile_pic_url_hd"\s*:\s*"((?:[^"\\]|\\.)*)"')
_TITLE_NAME_RE = re.compile(r"^(.*?)\s*\(@([\w.]+)\)")
_OG_COUNTS_RE = re.compile(r"([\d.,kKmM]+)\s*Followers,\s*([\d.,kKmM]+)\s*Following,\s*([\d.,kKmM]+)\s*Posts")


def _json_escape_decode(text):
    try:
        return json.loads('"' + text + '"')
    except ValueError:
        return text.replace("\\/", "/").replace('\\"', '"')


def _fetch_og_scrape(username):
    """Public profile page: Open Graph meta + first embedded JSON hits."""
    try:
        resp = requests.get(
            f"https://www.instagram.com/{quote(username)}/",
            headers={**IG_HEADERS, "Accept": "text/html,application/xhtml+xml"},
            timeout=UPSTREAM_TIMEOUT,
        )
    except requests.RequestException as exc:
        return None, f"og_unreachable:{type(exc).__name__}"
    if resp.status_code == 404:
        return None, "NOT_FOUND"
    if resp.status_code != 200:
        return None, f"og_http_{resp.status_code}"
    html = resp.text or ""
    if "This account doesn't exist" in html or "Sorry, this page isn't available" in html:
        return None, "NOT_FOUND"
    title = (_OG_TITLE_RE.search(html) or [None, ""])[1] if _OG_TITLE_RE.search(html) else ""
    desc = ""
    m = _OG_DESC_RE.search(html)
    if m:
        desc = _json_escape_decode(m.group(1))
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
            profile["full_name"] = nmatch.group(1).replace(" (@", "(").strip(" ()").strip()
        elif raw_title:
            profile["full_name"] = re.sub(r"\s*.*Profile\s*•\s*Instagram.*$", "", raw_title).strip()
    if desc:
        cmatch = _OG_COUNTS_RE.search(desc)
        if cmatch:
            profile["followers"] = parse_count(cmatch.group(1))
            profile["following"] = parse_count(cmatch.group(2))
            profile["posts"] = parse_count(cmatch.group(3))
        # og:description ends with the bio when one exists:
        # "123 Followers, 45 Following, 6 Posts - See Instagram photos and videos from X (@y)"
        bmatch = re.match(r"^(.*?)\s+-\s+See Instagram", desc)
        if bmatch and len(bmatch.group(1)) > 0 and not re.match(r"^[\d.,km]+\s*Followers$", bmatch.group(1), re.IGNORECASE):
            profile["biography"] = ""  # og bio text is the account name, not biography; keep clean
    bio = _DESC_JSON_RE.search(html)
    if bio:
        profile["biography"] = _json_escape_decode(bio.group(1))[:2000]
    if not profile["full_name"]:
        fn = re.search(r'"full_name"\s*:\s*"((?:[^"\\]|\\.)*)"', html)
        if fn:
            profile["full_name"] = _json_escape_decode(fn.group(1))
    return profile, None


FETCH_CHAIN = (_fetch_web_profile, _fetch_private_api_json, _fetch_og_scrape)


# --------------------------------------------------------------------------
# cache + rate limit
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
# lookup core
# --------------------------------------------------------------------------
def lookup_instagram(raw_username):
    """-> (status:int, payload:dict). Pure function; used by HTTP handler and tests."""
    username = clean_username(raw_username)
    if not username:
        return 400, {"success": False, "error": "INVALID_USERNAME", "detail": "1-30 chars, letters/digits/dot/underscore only"}

    cached = _CACHE.get(username)
    if cached is not None:
        status, payload = cached
        payload = dict(payload)
        payload["cached"] = True
        return status, payload

    profile = None
    errors = []
    not_found = False
    for fetcher in FETCH_CHAIN:
        result, err = fetcher(username)
        if result:
            profile = result
            break
        if err == "NOT_FOUND":
            not_found = True
            break
        if err:
            errors.append(err)

    if not_found:
        payload = {"success": False, "error": "USER_NOT_FOUND", "detail": f"@{username} yok veya erişilemiyor"}
        _CACHE.set(username, (404, payload), CACHE_TTL_FAIL)
        return 404, payload
    if profile is None:
        payload = {"success": False, "error": "UPSTREAM_UNAVAILABLE", "detail": "; ".join(errors) or "all fetchers failed"}
        _CACHE.set(username, (502, payload), CACHE_TTL_FAIL)
        return 502, payload

    profile = {k: v for k, v in profile.items() if v not in (None, "")}
    profile.setdefault("username", username)
    profile["fetched_at"] = int(time.time())
    payload = {"success": True, "data": profile}
    _CACHE.set(username, (200, payload), CACHE_TTL_OK)
    return 200, payload


# --------------------------------------------------------------------------
# HTTP handler (Vercel Python runtime: class `handler(BaseHTTPRequestHandler)`)
# --------------------------------------------------------------------------
class handler(BaseHTTPRequestHandler):
    server_version = "UraniumInstaLookup/1.0"

    def log_message(self, fmt, *args):  # keep the runtime log clean
        pass

    def _json(self, payload, status=200, extra_headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _client_ip(self):
        fwd = str(self.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        return fwd or (self.client_address[0] if self.client_address else "unknown")

    def _rate_checked(self):
        if not _LIMITER.allow(self._client_ip()):
            self._json({"success": False, "error": "RATE_LIMITED"}, 429, {"Retry-After": "30"})
            return False
        return True

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "86400")
        self.end_headers()

    def do_GET(self):
        try:
            # behind Vercel's rewrites the function receives the destination
            # path; x-matched-path carries the original request path.
            raw_path = self.headers.get("X-Matched-Path") or self.path
            parsed = urlparse(raw_path)
            if not (parsed.query or ""):
                parsed = parsed._replace(query=urlparse(self.path).query)
            path = parsed.path.rstrip("/") or "/"
            if path in ("/", "/api/index.py", "/api", "/index"):
                params = parse_qs(parsed.query)
                username = (params.get("username") or params.get("u") or [""])[0]
                if not username:
                    self._json({
                        "success": True,
                        "service": "uranium-insta-lookup",
                        "usage": "GET /?username=<handle> | GET /health | GET /img?username=<handle> | POST {\"action\":\"instagram_lookup\",\"username\":\"...\"}",
                    })
                    return
                if not self._rate_checked():
                    return
                status, payload = lookup_instagram(username)
                self._json(payload, status)
                return
            if path == "/health":
                self._json({"success": True, "ok": True, "time": int(time.time())})
                return
            if path == "/img":
                params = parse_qs(parsed.query)
                username = (params.get("username") or params.get("u") or [""])[0]
                if not self._rate_checked():
                    return
                status, payload = lookup_instagram(username)
                avatar = ((payload or {}).get("data") or {}).get("avatar_url") if status == 200 else None
                if avatar:
                    self.send_response(302)
                    self.send_header("Location", avatar)
                    self.send_header("Cache-Control", f"public, max-age={CACHE_TTL_OK}")
                    self.end_headers()
                    return
                self._json({"success": False, "error": "NO_AVATAR"}, 404)
                return
            self._json({"success": False, "error": "NOT_FOUND", "detail": "try /?username=... or /health"}, 404)
        except Exception as exc:  # never leak a stacktrace to the client
            self._json({"success": False, "error": "INTERNAL", "detail": str(exc)}, 500)

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > 16384:
                self._json({"success": False, "error": "BAD_BODY"}, 400)
                return
            raw = self.rfile.read(length)
            try:
                data = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                self._json({"success": False, "error": "BAD_JSON"}, 400)
                return
            if not isinstance(data, dict):
                self._json({"success": False, "error": "BAD_BODY"}, 400)
                return
            action = str(data.get("action") or "instagram_lookup").lower().strip()
            if action not in ("instagram_lookup", "ig_lookup", "lookup", "instagram", "profile"):
                self._json({"success": False, "error": "UNKNOWN_ACTION", "detail": "use action=instagram_lookup"}, 400)
                return
            if not self._rate_checked():
                return
            username = data.get("username") or data.get("query") or data.get("u")
            status, payload = lookup_instagram(username)
            self._json(payload, status)
        except Exception as exc:
            self._json({"success": False, "error": "INTERNAL", "detail": str(exc)}, 500)
