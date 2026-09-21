# insta-lookup API v2.5 (shared-key auth + one-time op-ids + wayback rescue + in-request replay + background warm)
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
from html import unescape as _html_unescape

# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------
UPSTREAM_TIMEOUT = float(os.environ.get("IG_UPSTREAM_TIMEOUT", "6"))
FETCH_DEADLINE = float(os.environ.get("IG_FETCH_DEADLINE", "10"))  # per pass
FETCH_BUDGET = float(os.environ.get("IG_FETCH_BUDGET", "18"))  # total incl. in-request retries
CACHE_TTL_OK = int(os.environ.get("IG_CACHE_TTL_OK", "180"))
CACHE_TTL_FAIL = int(os.environ.get("IG_CACHE_TTL_FAIL", "25"))  # absence cache
CACHE_TTL_BUSY = float(os.environ.get("IG_CACHE_TTL_BUSY", "5"))  # rate/upstream: brief guard only
STALE_TTL = int(os.environ.get("IG_STALE_TTL", "43200"))  # 12h grace copy
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
    "Accept-Encoding": "gzip, deflate",
    "x-ig-app-id": os.environ.get("IG_APP_ID", "936619743392459"),
    "x-ig-www-claim": "0",
    "x-asbd-id": "350685817",
    "x-instagram-ajax": "1",
    "sec-ch-ua": '"Chromium";v="124", "Not.A/Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
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
        external = str(user.get("external_url") or user.get("external_url_linkshimmed") or "")
    # Instagram serves two shapes: legacy graphql ("edge_followed_by":
    # {"count": N}) and modern flat ("follower_count": N). Accept both.
    def _count(*keys):
        for key in keys:
            value = user.get(key)
            if isinstance(value, dict):
                value = value.get("count")
            parsed = parse_count(value)
            if parsed is not None:
                return parsed
        return None
    def _pic():
        hd = user.get("hd_profile_pic_url_info")
        if isinstance(hd, dict) and hd.get("url"):
            return str(hd["url"])
        for key in ("profile_pic_url_hd", "profile_pic_url"):
            value = user.get(key)
            if value:
                return str(value)
        return ""
    bio = user.get("biography")
    if not bio:
        entities = user.get("biography_with_entities")
        if isinstance(entities, dict):
            bio = entities.get("raw_text")
    return {
        "username": username,
        "full_name": str(user.get("full_name") or ""),
        "biography": str(bio or ""),
        "external_url": external,
        "is_verified": bool(user.get("is_verified")),
        "is_private": bool(user.get("is_private")),
        "posts": _count("edge_owner_to_timeline_media", "media_count"),
        "followers": _count("edge_followed_by", "follower_count"),
        "following": _count("edge_follow", "following_count"),
        "avatar_url": _pic(),
        "business_category": str(user.get("category_name") or user.get("business_category_name") or ""),
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
    """(profile|None, err|None). 'NOT_FOUND' is a definitive answer.
    Tries the mobile-API host first, then the same endpoint on the web host
    (different edges; when datacenter IPs are blocked one of the two often
    still answers)."""
    referer = f"https://www.instagram.com/{username}/"
    headers = dict(UPSTREAM_HEADERS, **{"Referer": referer})
    last_err = "unreachable"
    saw_rate = False
    for host in ("https://i.instagram.com", "https://www.instagram.com"):
        try:
            resp = _SESSION.get(
                host + "/api/v1/users/web_profile_info/",
                params={"username": username},
                headers=headers,
                timeout=UPSTREAM_TIMEOUT,
            )
        except requests.RequestException:
            continue
        if resp.status_code == 404:
            # Only positive "not found" wording proves absence; a bare or
            # rate-limit-flavoured 404 (common when the caller IP is flagged)
            # must fall through to the other sources as a plain error.
            if _proves_absence(resp.text or ""):
                return None, "NOT_FOUND"
            last_err = "http_404"
            continue
        if resp.status_code in (429, 503):
            saw_rate = True
            last_err = "rate_limited"
            continue
        if resp.status_code != 200:
            last_err = f"http_{resp.status_code}"
            continue
        try:
            payload = resp.json()
        except ValueError:
            last_err = "bad_json"
            continue
        user = (payload or {}).get("data", {}).get("user")
        if user is None:
            return None, "NOT_FOUND" if (payload or {}).get("data") is not None or "data" in (payload or {}) else "SOFT_NOT_FOUND"
        return normalize_profile(user), None
    return None, "rate_limited" if saw_rate else last_err


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
_MISSING_RE = re.compile(r"(?:This account|Sorry, this page)[^<]{0,40}?(?:doesn|isn)['\u2019]?t", re.I)
_OG_COUNTS_RE = re.compile(r"([\d.,kKmM]+)\s*Followers,\s*([\d.,kKmM]+)\s*Following,\s*([\d.,kKmM]+)\s*Posts")
_FULLNAME_JSON_RE = re.compile(r'"full_name"\s*:\s*"((?:[^"\\]|\\.)*)"')


def _json_escape_decode(text):
    try:
        return json.loads('"' + text + '"')
    except ValueError:
        return text.replace("\\/", "/").replace('\\"', '"')


_ABSENCE_RE = re.compile(r"(?:user not found|not found with username|this account[^<]{0,30}doesn|isn\'t available|page isn\'t available)", re.I)


def _proves_absence(text):
    """Absence needs POSITIVE wording; bare 404s from walled hosts mean nothing."""
    return bool(_ABSENCE_RE.search(text or ""))


def _parse_missing(html):
    """Only an explicit 'account doesn't exist' page proves absence. A login
    wall / rate-limit page must never be read as USER_NOT_FOUND."""
    return bool(_MISSING_RE.search(html or ""))


def _parse_og_html(html, username):
    """Extract a profile from Instagram HTML/opengraph payloads (og meta tags
    + embedded JSON crumbs). Returns None when the page carries nothing
    (e.g. a login wall)."""
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
        profile["avatar_url"] = _json_escape_decode(_html_unescape(img.group(1)))
    else:
        pic = _PIC_JSON_RE.search(html)
        if pic:
            profile["avatar_url"] = _json_escape_decode(pic.group(1))
    tmatch = _OG_TITLE_RE.search(html)
    if tmatch:
        raw_title = _json_escape_decode(_html_unescape(tmatch.group(1)))
        nmatch = _TITLE_NAME_RE.match(raw_title)
        if nmatch:
            profile["full_name"] = nmatch.group(1).strip(" ()").strip()
        elif raw_title:
            profile["full_name"] = re.sub(r"\s*.*Profile\s*•\s*Instagram.*$", "", raw_title).strip()
    desc_match = _OG_DESC_RE.search(html)
    if desc_match:
        desc = _json_escape_decode(_html_unescape(desc_match.group(1)))
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
    # login-wall pages carry generic og tags: the word "Instagram" as title
    # and the app's own logo as og:image -- neither is real profile data
    if "/rsrc.php" in profile["avatar_url"]:
        profile["avatar_url"] = ""
    if re.fullmatch(
        r"(?:Login\s*[•·]\s*)?Instagram(?:\s*[•·]\s*[Pp]hoto\w*(?: and Videos)?)?",
        profile["full_name"].strip(),
    ):
        profile["full_name"] = ""
    if not profile["full_name"] and not profile["avatar_url"] and profile["followers"] is None:
        return None
    return profile


_EMBED_NAME_RE = re.compile(r'"full_name"\s*:\s*"((?:[^"\\]|\\.)*)"')
_EMBED_PIC_RE = re.compile(r'"(?:profile_pic_url|hd_profile_pic_url_info)"\s*:\s*"((?:[^"\\]|\\.)*)"|"(?:profile_pic_url_hd)"\s*:\s*"((?:[^"\\]|\\.)*)"')
_EMBED_URLS_RE = re.compile(r'"url"\s*:\s*"(https:[^"]*cdninstagram[^"]*)"')


def _parse_embed(html, username):
    """(profile|None, err|None) from an embed page's HTML."""
    if not html:
        return None, "empty_embed"
    if "\u0026" in html:
        html = html.encode("utf-8").decode("unicode_escape", "ignore")
    profile = {
        "username": "",
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
    if re.search(r'"username"\s*:\s*"' + re.escape(username) + '"', html, re.I):
        profile["username"] = username.lower()
    else:
        return None, "no_match"
    m = _EMBED_NAME_RE.search(html)
    if m:
        profile["full_name"] = _json_escape_decode(m.group(1))
    for pic in re.findall(r'"profile_pic_url(?:_hd)?"\s*:\s*"((?:[^"\\]|\\.)*)"', html):
        pic = _json_escape_decode(pic).replace("\\/", "/")
        if pic.startswith("http"):
            profile["avatar_url"] = pic
            break
    if not profile["avatar_url"]:
        found = _EMBED_URLS_RE.search(html)
        if found:
            profile["avatar_url"] = found.group(1)
    if not profile["full_name"] and not profile["avatar_url"]:
        return None, "empty_embed"
    return profile, None


def _fetch_embed(username):
    """Profile embed page: an iframe-embedding endpoint Instagram generally
    does NOT login-wall, even from datacenter IPs. Carries full_name,
    avatar and privacy flags (no counts/bio). Also the workaround for the
    current anonymous-API 400 schema bug on business/creator accounts."""
    url = f"https://www.instagram.com/{quote(username)}/embed/captioned/"
    try:
        resp = _SESSION.get(url, headers=HTML_HEADERS, timeout=UPSTREAM_TIMEOUT)
    except requests.RequestException:
        return None, "unreachable"
    if resp.status_code == 404 or resp.status_code != 200:
        if _proves_absence(getattr(resp, "text", "")):
            return None, "SOFT_NOT_FOUND"
        return None, f"http_{resp.status_code}"
    if _parse_missing(resp.text or ""):
        return None, "SOFT_NOT_FOUND"
    return _parse_embed(resp.text or "", username)


def _fetch_relay(username):
    """Optional operator relay (Cloudflare Worker) used FIRST when
    IG_RELAY_URL is configured: its egress IP is not the Vercel one, so it
    answers even while Vercel sits behind an Instagram wall. Expected reply:
    a web_profile_info JSON body or a flat/normalized profile object."""
    relay = os.environ.get("IG_RELAY_URL", "").strip().rstrip("/")
    if not relay:
        return None, "disabled"
    url = f"{relay}?username={quote(username)}"
    headers = {"Accept": "application/json"}
    secret = os.environ.get("IG_RELAY_SECRET", "").strip()
    if secret:
        headers["x-relay-secret"] = secret
    try:
        resp = _SESSION.get(url, headers=headers, timeout=UPSTREAM_TIMEOUT + 4)
    except requests.RequestException:
        return None, "unreachable"
    if resp.status_code == 404:
        return None, "NOT_FOUND"
    if resp.status_code != 200:
        return None, f"http_{resp.status_code}"
    try:
        payload = resp.json()
    except ValueError:
        return None, "bad_json"
    if not isinstance(payload, dict):
        return None, "bad_json"
    if payload.get("error"):
        return None, "relay_error"
    if payload.get("via") == "embed" and isinstance(payload.get("html"), str):
        return _parse_embed(payload["html"], username)
    user = ((payload.get("data") or {}).get("user")) or (payload.get("profile")) or (payload if payload.get("username") else None)
    profile = normalize_profile(user) if isinstance(user, dict) else None
    if not profile:
        return None, "no_user"
    return profile, None


def _fetch_wayback(username):
    """archive.org is crawler-friendly and answers from any IP; its snapshot
    of the profile page carries Instagram's own og-meta (name, counts, bio,
    avatar). Data can lag (hours-days) so it is a fallback, flagged archived."""
    try:
        avail = _SESSION.get(
            "https://archive.org/wayback/available",
            params={"url": f"https://www.instagram.com/{username}/"},
            headers={"Accept": "application/json"},
            timeout=UPSTREAM_TIMEOUT,
        )
        if avail.status_code != 200:
            return None, f"http_{avail.status_code}"
        snap = ((avail.json() or {}).get("archived_snapshots") or {}).get("closest") or {}
        snap_url = str(snap.get("url") or "")
        ts = str(snap.get("timestamp") or "")
    except (requests.RequestException, ValueError):
        return None, "unreachable"
    if not snap_url:
        return None, "no_snapshot"
    # Use archive.org's own URL (it knows the exact captured spelling, e.g. a
    # capitalised redirect target); only rewrite to the raw-content variant.
    targets = [re.sub(r"/web/(\d{14})/?", r"/web/\1id_/", snap_url.replace("http://", "https://", 1))]
    rebuilt = f"https://web.archive.org/web/{ts}id_/https://www.instagram.com/{username}/"
    if rebuilt not in targets:
        targets.append(rebuilt)
    resp = None
    last_target_err = "no_snapshot"
    for target in targets:
        try:
            cand = _SESSION.get(target, headers=HTML_HEADERS, timeout=UPSTREAM_TIMEOUT + 6)
        except requests.RequestException:
            last_target_err = "unreachable"
            continue
        if cand.status_code == 200:
            resp = cand
            break
        last_target_err = "no_snapshot" if cand.status_code == 404 else f"http_{cand.status_code}"
    if resp is None:
        return None, last_target_err
    if resp.status_code == 404:
        return None, "no_snapshot"
    if resp.status_code != 200:
        return None, f"http_{resp.status_code}"
    html = resp.text or ""
    if _parse_missing(html):
        return None, "NOT_FOUND"
    profile = _parse_og_html(html, username)
    if profile is None:
        return None, "empty_html"
    profile["archived"] = True
    try:
        profile["snapshot_at"] = int(time.mktime(time.strptime(ts, "%Y%m%d%H%M%S")))
    except (ValueError, TypeError):
        pass
    return profile, None


def _fetch_opengraph(username):
    """Crawler-facing og-meta endpoint; usually served even when the main
    HTML page sits behind a login wall."""
    url = f"https://www.instagram.com/{quote(username)}/opengraph"
    try:
        resp = _SESSION.get(url, headers=HTML_HEADERS, timeout=UPSTREAM_TIMEOUT)
    except requests.RequestException:
        return None, "unreachable"
    if resp.status_code == 404:
        if _proves_absence(resp.text or ""):
            return None, "SOFT_NOT_FOUND"
        return None, "http_404"
    if resp.status_code != 200:
        return None, f"http_{resp.status_code}"
    html = resp.text or ""
    if _parse_missing(html):
        return None, "SOFT_NOT_FOUND"
    profile = _parse_og_html(html, username)
    if profile is None:
        return None, "empty_html"
    return profile, None


def _fetch_og_scrape(username):
    url = f"https://www.instagram.com/{quote(username)}/"
    try:
        resp = _SESSION.get(url, headers=HTML_HEADERS, timeout=UPSTREAM_TIMEOUT)
    except requests.RequestException:
        return None, "unreachable"
    if resp.status_code == 404:
        if _proves_absence(resp.text or ""):
            return None, "SOFT_NOT_FOUND"
        return None, "http_404"
    if resp.status_code != 200:
        return None, f"http_{resp.status_code}"
    html = resp.text or ""
    if _parse_missing(html):
        return None, "SOFT_NOT_FOUND"
    profile = _parse_og_html(html, username)
    if profile is None:
        return None, "empty_html"
    return profile, None


_MIRROR_HOSTS = (
    ("https://imginn.com/p/api/profile/{u}/", "https://imginn.com"),
    ("https://www.pixnoy.com/p/api/profile/{u}/", "https://www.pixnoy.com"),
    ("https://appimginn.com/api/profile/{u}/", "https://imginn.com"),
)


def _fetch_mirror(username):
    """Viewer-network JSON APIs (imginn family): live data, no login, free.
    Usually Cloudflare-guarded; egress-dependent. On success returns the same
    normalized profile dict the other fetchers produce."""
    def _int(v):
        try:
            return int(v)
        except (TypeError, ValueError):
            return None

    last = "unreachable"
    for tpl, origin in _MIRROR_HOSTS:
        url = tpl.format(u=username)
        try:
            resp = _SESSION.get(url, timeout=9, headers={
                "Accept": "application/json",
                "Origin": origin,
                "Referer": origin + "/",
                "X-Requested-With": "XMLHttpRequest",
            })
        except requests.RequestException:
            last = "unreachable"
            continue
        if resp.status_code == 403:
            last = "cf_blocked"
            continue
        if resp.status_code in (429, 503):
            last = "rate_limited"
            continue
        if resp.status_code != 200:
            last = "http_%s" % resp.status_code
            continue
        try:
            payload = resp.json()
        except ValueError:
            last = "bad_json"
            continue
        prof_raw = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(prof_raw, dict) or not prof_raw.get("username"):
            last = "no_data"
            continue
        uname = str(prof_raw.get("username") or "").strip().lower()
        if uname != username.lower():
            last = "no_data"
            continue
        profile = {
            "username": uname,
            "full_name": prof_raw.get("full_name") or prof_raw.get("fullname") or "",
            "biography": prof_raw.get("biographie") or prof_raw.get("bio") or "",
            "followers": _int(prof_raw.get("followers_count") or prof_raw.get("edge_followed_by", {}).get("count") if isinstance(prof_raw.get("edge_followed_by"), dict) else prof_raw.get("followers_count")),
            "following": _int(prof_raw.get("following_count")),
            "posts": _int(prof_raw.get("media_count")),
            "avatar_url": prof_raw.get("profile_pic_url_hd") or prof_raw.get("profile_pic_url") or "",
            "is_private": bool(prof_raw.get("is_private")),
            "is_verified": bool(prof_raw.get("is_verified")),
            "external_url": prof_raw.get("external_url") or "",
            "mirror": True,
        }
        return profile, None
    return None, last


SC_BASE_URL = "https://www.socialcrawl.dev/v1/instagram/profile"
SC_TIMEOUT = float(os.environ.get("IG_SC_TIMEOUT", "16"))


def _socialcrawl_enabled():
    return bool((os.environ.get("SOCIALCRAWL_API_KEY") or "").strip())


def _fetch_socialcrawl(username):
    """SocialCrawl live profile (1 credit per profile read on a cold miss;
    cached reads and definitive 404s are refunded). Last fallback in the
    request chain when the key is configured; background warm never uses it
    so retries can never burn credits."""
    key = (os.environ.get("SOCIALCRAWL_API_KEY") or "").strip()
    if not key:
        return None, "sc_unconfigured"
    try:
        resp = _SESSION.get(SC_BASE_URL, params={"handle": username},
                            headers={"x-api-key": key, "Accept": "application/json"},
                            timeout=SC_TIMEOUT)
    except requests.RequestException:
        return None, "sc_unreachable"
    except Exception:
        return None, "sc_source_error"
    if resp.status_code == 404:
        etype = ""
        try:
            etype = str(((resp.json() or {}).get("error") or {}).get("type") or "")
        except ValueError:
            pass
        return None, "NOT_FOUND" if etype == "RESOURCE_NOT_FOUND" else "sc_http_404"
    # deliberate: SC-side 429/402 stay out of the retry buckets - an in-request
    # replay would spend a second credit while the free sources answer fine
    if resp.status_code == 402:
        return None, "sc_out_of_credits"
    if resp.status_code in (429, 503):
        return None, "sc_rate_limited"
    if resp.status_code != 200:
        return None, "sc_http_%s" % resp.status_code
    try:
        body = resp.json()
    except ValueError:
        return None, "sc_bad_json"
    if not isinstance(body, dict) or not body.get("success"):
        return None, "sc_error"
    author = ((body.get("data") or {}).get("author") or {})
    if not isinstance(author, dict) or not author.get("username"):
        return None, "sc_no_data"

    def _int(v):
        try:
            return int(v)
        except (TypeError, ValueError):
            return None

    profile = {
        "username": str(author.get("username") or "").lower(),
        "full_name": str(author.get("display_name") or author.get("full_name") or ""),
        "biography": str(author.get("bio") or author.get("biography") or ""),
        "followers": _int(author.get("followers")),
        "following": _int(author.get("following")),
        "posts": _int(author.get("posts_count") or author.get("media_count")),
        "avatar_url": str(author.get("avatar_url") or author.get("profile_pic_url") or ""),
        "is_private": bool(author.get("private")),
        "is_verified": bool(author.get("verified")),
        "external_url": str(author.get("url") or author.get("external_url") or ""),
        "source": "socialcrawl",
    }
    return profile, None


_BASE_CHAIN = (
    _fetch_relay, _fetch_web_profile, _fetch_private_api_json,
    _fetch_embed, _fetch_mirror, _fetch_wayback, _fetch_opengraph, _fetch_og_scrape,
)

# Credit safety: SC sits LAST so free sources answer everything they can
# (nba-class fills from wayback at zero cost); only accounts the entire free
# chain starves burn one credit. Warm retries skip SC entirely: no retry storm.
FETCH_CHAIN = _BASE_CHAIN + (_fetch_socialcrawl,) if _socialcrawl_enabled() else _BASE_CHAIN
FETCH_CHAIN_WARM = _BASE_CHAIN

# fields that make a profile "complete" -> stop querying more sources
_PRIMARY_FIELDS = ("full_name", "avatar_url", "followers", "following", "posts")


def _is_filled(value):
    return value not in (None, "")


def _merge_profile(base, extra):
    """Fill missing keys of `base` from `extra` (first source wins)."""
    if base is None:
        return dict(extra)
    for key, value in extra.items():
        if key == "username":
            if not base.get("username") and value:
                base["username"] = value
            continue
        if not _is_filled(base.get(key)) and _is_filled(value):
            base[key] = value
    return base


def _is_complete(profile):
    for key in _PRIMARY_FIELDS:
        if _is_filled(profile.get(key)):
            continue
        if key == "posts" and profile.get("source") == "socialcrawl":
            continue  # SC's profile endpoint omits posts_count; not worth a second credit call
        return False
    return True


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
_STALE = _TtlCache(CACHE_MAX_ENTRIES, _LOCK)
_LIMITER = _RateLimiter(RATE_MAX_PER_WINDOW, _LOCK)


# --------------------------------------------------------------------------
# background warming: when IG briefly 429s us, don't just fail - keep trying
# for a while in a daemon thread (Vercel keeps warm containers alive between
# invocations), so the user's NEXT click lands on fresh cached data.
# --------------------------------------------------------------------------
WARM_SECONDS = float(os.environ.get("IG_WARM_SECONDS", "150"))
WARM_INTERVAL = float(os.environ.get("IG_WARM_INTERVAL", "8"))
WARM_MAX_CONCURRENT = 8
_WARMING = set()
_WARM_LOCK = threading.Lock()


def _warm_pass(username):
    """One fresh pass through the fetch chain; returns merged profile|None."""
    profile = None
    started = time.monotonic()
    for fetcher in FETCH_CHAIN_WARM:
        if profile is not None and _is_complete(profile):
            break
        if time.monotonic() - started > FETCH_DEADLINE:
            break
        try:
            result, err = fetcher(username)
        except Exception:
            continue
        if result:
            profile = _merge_profile(profile, result)
    return profile


def _warm_loop(username):
    try:
        deadline = time.monotonic() + WARM_SECONDS
        while time.monotonic() < deadline:
            time.sleep(WARM_INTERVAL)
            profile = _warm_pass(username)
            if profile is not None:
                prof = {k: v for k, v in profile.items() if v not in (None, "")}
                prof.setdefault("username", username)
                prof["fetched_at"] = int(time.time())
                payload = {"success": True, "data": prof}
                if _is_complete(profile):
                    _CACHE.set(username, (200, payload), CACHE_TTL_OK)
                    _STALE.set(username, payload, STALE_TTL)
                else:
                    payload["partial"] = True
                    _CACHE.set(username, (200, payload), int(CACHE_TTL_OK / 2))
                print(f"[insta-lookup] warm success user={username}")
                return
    finally:
        with _WARM_LOCK:
            _WARMING.discard(username)


def _spawn_warm(username):
    with _WARM_LOCK:
        if username in _WARMING or len(_WARMING) >= WARM_MAX_CONCURRENT:
            return False
        _WARMING.add(username)
    threading.Thread(target=_warm_loop, args=(username,), daemon=True).start()
    return True


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
    saw_missing = False
    deadline = time.monotonic() + FETCH_BUDGET
    for _attempt in range(3):  # IG's 429 window jitters; quiet in-request replays win data
        started = time.monotonic()
        transient = False
        for fetcher in FETCH_CHAIN:
            if profile is not None and _is_complete(profile):
                break
            if time.monotonic() - started > FETCH_DEADLINE:
                break  # per-pass budget; stay under Vercel maxDuration + client timeout
            try:
                result, err = fetcher(username)
            except Exception as exc:  # one broken source must never 500 the request
                print(f"[insta-lookup] {getattr(fetcher, '__name__', 'fetcher')} error: {exc}")
                result, err = None, "source_error"
            if result:
                profile = _merge_profile(profile, result)
                continue
            if err in ("NOT_FOUND", "SOFT_NOT_FOUND"):
                # Absence is decided only at the END of the chain: a walled host
                # can fake a 404, and a later source can still prove existence.
                saw_missing = True
            elif err in ("rate_limited", "http_429", "http_503"):
                saw_rate = True
                transient = True
            elif err in ("unreachable", "source_error"):
                transient = True  # worth another pass, but not a rate verdict
        if profile is not None and _is_complete(profile):
            break
        if saw_missing and profile is None:
            break  # proven absence; waiting changes nothing
        if not transient:
            break
        if time.monotonic() + 1.6 > deadline:
            break
        time.sleep(1.2)

    if saw_missing and profile is None:
        payload = {"success": False, "error": "USER_NOT_FOUND"}
        _CACHE.set(username, (404, payload), CACHE_TTL_FAIL)
        return 404, payload

    if profile is None:
        stale = _STALE.get(username)
        if stale is not None:
            # upstream blocked/challenged us but we hold a recent clean copy;
            # serve it flagged so clients know counts may lag a few minutes
            payload = dict(stale)
            payload["stale"] = True
            _CACHE.set(username, (200, payload), CACHE_TTL_FAIL)
            return 200, payload
        payload = {"success": False, "error": "RATE_LIMITED" if saw_rate else "UPSTREAM_UNAVAILABLE"}
        print(f"[insta-lookup] upstream failure user={username} rate={saw_rate}")
        _CACHE.set(username, (502, payload), CACHE_TTL_BUSY)
        _spawn_warm(username)  # keep trying in the background for the next click
        return 502, payload

    profile = {k: v for k, v in profile.items() if v not in (None, "")}
    profile.setdefault("username", username)
    profile["fetched_at"] = int(time.time())
    payload = {"success": True, "data": profile}
    if not _is_complete(profile):
        payload["partial"] = True
        # incomplete data may become available seconds later - don't sit on
        # it for the full ok-ttl, and don't poison the 12h stale bucket
        _CACHE.set(username, (200, payload), min(CACHE_TTL_FAIL, 30))
        return 200, payload
    _CACHE.set(username, (200, payload), CACHE_TTL_OK)
    _STALE.set(username, payload, STALE_TTL)
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
            if action not in ("instagram_lookup", "ig_lookup", "lookup", "instagram", "profile", "mirror_probe"):
                self._json({"success": False, "error": "UNKNOWN_ACTION"}, 400)
                return
            if not self._rate_ok():
                return
            # body credentials only here; the Lua client uses this path
            ok, err = check_operation(*_creds_from(self.headers, {}, data))
            if not ok:
                self._deny(err)
                return
            if action == "mirror_probe":
                out = []
                for probe_user in ("nba", "empik"):
                    try:
                        prof, perr = _fetch_mirror(probe_user)
                    except Exception as exc:
                        prof, perr = None, "exc_" + type(exc).__name__
                    out.append({"u": probe_user, "err": perr, "data": prof})
                self._json({"success": True, "probe": out}, 200)
                return
            username = data.get("username") or data.get("query") or data.get("u")
            status, payload = lookup_instagram(username)
            self._json(payload, status)
        except Exception:
            self._json({"success": False, "error": "INTERNAL"}, 500)
