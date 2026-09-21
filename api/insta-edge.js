// insta-lookup EDGE v1.0 — same contract as api/index.py, Vercel Edge runtime.
// Edge egress = rotating Vercel network IPs: when IG walls the serverless
// region's shared IPs, edge requests often still answer. Cache/nonce stores are
// per-isolate: best-effort; correctness comes from the python origin anyway.
// Auth: {action,username,key,nonce,ts} POST; GET / returns {ok:"edge"}.
export const config = { runtime: "edge" };

const SHARED_KEY = (process.env.INSTA_SHARED_KEY || "").trim();
const OP_TS_WINDOW = 90;
const EDGE_APP_ID = process.env.IG_APP_ID || "936619743392459";
const FETCH_TIMEOUT = 7000;
const TOTAL_BUDGET = 19000;
const CACHE_TTL_OK = 43200;
const CACHE_TTL_NOT_FOUND = 25;
const CACHE_TTL_BUSY = 5;
const RATE_MAX = 60;
const RATE_WINDOW = 60;
const PROFILE_KEYS = ["username","full_name","biography","external_url","is_verified","is_private","posts","followers","following","avatar_url","business_category"];
const PRIMARY = ["full_name","avatar_url","followers","following","posts"];
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
const IG_HEADERS = {
  "User-Agent": UA, Accept: "*/*", "Accept-Language": "en-US,en;q=0.9",
  "x-ig-app-id": EDGE_APP_ID, "x-ig-www-claim": "0", "x-asbd-id": "350685817",
  "x-instagram-ajax": "1", "sec-fetch-dest": "empty", "sec-fetch-mode": "cors", "sec-fetch-site": "same-origin",
};
const HTML_HEADERS = { "User-Agent": UA, Accept: "text/html,application/xhtml+xml", "Accept-Language": "en-US,en;q=0.9" };
const CRAWLER_HEADERS = { "User-Agent": "facebookexternalhit/1.1;line=1.0", Accept: "*/*" };

const USERNAME_RE = /^[A-Za-z0-9._]{1,30}$/;
const OG_TITLE_RE = /<meta\s+(?:property|name)=["']og:title["']\s+content=["']([^"']*)["']/i;
const OG_DESC_RE = /<meta\s+(?:property|name)=["']og:description["']\s+content=["']([^"']*)["']/i;
const OG_IMAGE_RE = /<meta\s+(?:property|name)=["']og:image["']\s+content=["']([^"']*)["']/i;
const OG_COUNTS_RE = /([\d.,kKmM]+)\s*Followers,\s*([\d.,kKmM]+)\s*Following,\s*([\d.,kKmM]+)\s*Posts/;
const TITLE_NAME_RE = /^(.*?)\s*\(@([\w.]+)\)/;
const PIC_JSON_RE = /"profile_pic_url_hd"\s*:\s*"((?:[^"\\]|\\.)*)"/;
const DESC_JSON_RE = /"biography"\s*:\s*"((?:[^"\\]|\\.)*)"/;
const FULLNAME_JSON_RE = /"full_name"\s*:\s*"((?:[^"\\]|\\.)*)"/;
const MISSING_RE = /(?:This account|Sorry, this page)[^<]{0,40}?(?:doesn|isn)['’]?t/i;
const ABSENCE_RE = /(?:user not found|not found with username|this account[^<]{0,30}doesn|isn't available|page isn't available)/i;

// --- per-isolate stores -----------------------------------------------------
const cache = new Map(); // username -> [expiryMs, status, payload]
const seenNonces = new Map(); // nonce hash -> expiryMs
const rateBuckets = new Map(); // ip -> [windowStart, count]
let sweeps = 0;

function nowS() { return Date.now() / 1000; }
function cacheGet(u) {
  const hit = cache.get(u);
  if (!hit) return null;
  if (hit[0] < nowS()) { cache.delete(u); return null; }
  return [hit[1], hit[2]];
}
function cacheSet(u, status, payload, ttl) {
  cache.set(u, [nowS() + ttl, status, payload]);
  if (cache.size > 800) { const k = cache.keys().next().value; cache.delete(k); }
}
async function sha16(s) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("").slice(0, 16);
}
function rateOk(ip) {
  const now = nowS();
  const [start, count] = rateBuckets.get(ip) || [now, 0];
  if (now - start > RATE_WINDOW) { rateBuckets.set(ip, [now, 1]); return true; }
  if (count >= RATE_MAX) return false;
  rateBuckets.set(ip, [start, count + 1]);
  return true;
}
function cleanUsername(raw) {
  if (raw === null || raw === undefined) return null;
  let text = String(raw).trim().replace(/^@+/, "").toLowerCase();
  text = text.replace(/^https?:\/\/(?:www\.)?instagram\.com\//, "").replace(/^instagram\.com\//, "");
  text = text.replace(/[\/\?&.]+$/g, "");
  text = text.split("?")[0].split("/")[0];
  return USERNAME_RE.test(text) ? text : null;
}
function parseCount(value) {
  if (value === null || value === undefined || typeof value === "boolean") return null;
  if (typeof value === "number") return Math.max(0, Math.trunc(value));
  let text = String(value).trim().toLowerCase().replace(/,/g, "").replace(/ /g, "");
  text = text.replace(/(million|billion|thousand)$/, m => ({ million: "m", billion: "b", thousand: "k" })[m]);
  const m = text.match(/^([\d.]+)([kmb])?$/);
  if (!m) return null;
  const number = parseFloat(m[1]);
  if (!isFinite(number)) return null;
  const mult = { k: 1e3, m: 1e6, b: 1e9 }[m[2]] || 1;
  return Math.max(0, Math.trunc(number * mult));
}
function htmlUnescape(s) {
  return String(s).replace(/&#0?([0-9]+);/g, (_, d) => String.fromCodePoint(parseInt(d, 10)))
    .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">");
}
function jsonEscapeDecode(s) {
  return String(s).replace(/\\u0026/g, "&").replace(/\\\//g, "/").replace(/\\u002F/g, "/").replace(/\\n/g, " ").replace(/\\r/g, "").replace(/\\t/g, " ").replace(/\\"/g, '"').replace(/\\\\/g, "\\");
}
function filled(v) { return v !== null && v !== undefined && v !== ""; }
function isComplete(p) { return !!p && PRIMARY.every(k => filled(p[k])); }

function normalizeProfile(user) {
  if (!user || typeof user !== "object") return null;
  const username = String(user.username || "").toLowerCase();
  if (!username) return null;
  const count = (...keys) => {
    for (const key of keys) {
      let v = user[key];
      if (v && typeof v === "object") v = v.count;
      const parsed = parseCount(v);
      if (parsed !== null) return parsed;
    }
    return null;
  };
  let external = "";
  if (user.external_url_link && typeof user.external_url_link === "object") external = String(user.external_url_link.url || "");
  if (!external) external = String(user.external_url || user.external_url_linkshimmed || "");
  let avatar = "";
  if (user.hd_profile_pic_url_info && user.hd_profile_pic_url_info.url) avatar = String(user.hd_profile_pic_url_info.url);
  else if (user.profile_pic_url_hd) avatar = String(user.profile_pic_url_hd);
  else if (user.profile_pic_url) avatar = String(user.profile_pic_url);
  return {
    username,
    full_name: String(user.full_name || ""),
    biography: String(user.biography || "").slice(0, 2000),
    external_url: external,
    is_verified: user.is_verified === true,
    is_private: user.is_private === true,
    posts: count("edge_owner_to_timeline_media", "media_count"),
    followers: count("edge_followed_by", "edge_followed_count", "follower_count"),
    following: count("edge_follow", "following_count"),
    avatar_url: avatar,
    business_category: String((user.category_name) || (user.category && user.category.name) || ""),
  };
}

function parseOgHtml(html, username) {
  const profile = { username, full_name: "", biography: "", external_url: "", is_verified: /"is_verified"\s*:\s*true/.test(html), is_private: /"is_private"\s*:\s*true/.test(html), posts: null, followers: null, following: null, avatar_url: "", business_category: "" };
  const img = html.match(OG_IMAGE_RE);
  if (img) profile.avatar_url = jsonEscapeDecode(htmlUnescape(img[1]));
  else { const pic = html.match(PIC_JSON_RE); if (pic) profile.avatar_url = jsonEscapeDecode(pic[1]); }
  const t = html.match(OG_TITLE_RE);
  if (t) {
    const rawTitle = jsonEscapeDecode(htmlUnescape(t[1]));
    const nm = rawTitle.match(TITLE_NAME_RE);
    if (nm) profile.full_name = String(nm[1]).replace(/^[ ()]+|[ ()]+$/g, "");
    else if (rawTitle) profile.full_name = rawTitle.replace(/\s*.*Profile\s*•\s*Instagram.*$/, "").trim();
  }
  const d = html.match(OG_DESC_RE);
  if (d) {
    const desc = jsonEscapeDecode(htmlUnescape(d[1]));
    const c = desc.match(OG_COUNTS_RE);
    if (c) { profile.followers = parseCount(c[1]); profile.following = parseCount(c[2]); profile.posts = parseCount(c[3]); }
  }
  const bio = html.match(DESC_JSON_RE);
  if (bio) profile.biography = jsonEscapeDecode(bio[1]).slice(0, 2000);
  if (!profile.full_name) { const fn = html.match(FULLNAME_JSON_RE); if (fn) profile.full_name = jsonEscapeDecode(fn[1]); }
  if (profile.avatar_url.includes("/rsrc.php")) profile.avatar_url = "";
  if (/^(?:Login\s*[•·]\s*)?Instagram(?:\s*[•·]\s*[Pp]hoto\w*(?: and Videos)?)?$/.test(profile.full_name.trim())) profile.full_name = "";
  if (!profile.full_name && !profile.avatar_url && profile.followers === null) return null;
  return profile;
}

function mergeProfile(base, extra) {
  if (!base) return extra;
  if (!extra) return base;
  for (const key of PROFILE_KEYS) {
    if (!filled(base[key]) && filled(extra[key])) base[key] = extra[key];
  }
  if (extra.archived && !base.archived) base.archived = true;
  if (extra.snapshot_at && !base.snapshot_at) base.snapshot_at = extra.snapshot_at;
  return base;
}

// --- fetch helpers -----------------------------------------------------------
async function fetchWithDeadline(url, opts) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT);
  try {
    return await fetch(url, Object.assign({}, opts, { signal: ctrl.signal, redirect: "follow" }));
  } finally { clearTimeout(timer); }
}
async function fetchText(url, opts) {
  try {
    const r = await fetchWithDeadline(url, opts);
    return { status: r.status, text: r.status === 200 ? await r.text() : "" };
  } catch { return { status: 0, text: "" }; }
}

async function fetchWebProfile(username) {
  let lastErr = "unreachable"; let sawRate = false;
  for (const host of ["https://i.instagram.com", "https://www.instagram.com"]) {
    let r, body;
    try {
      const url = host + "/api/v1/users/web_profile_info/?username=" + encodeURIComponent(username);
      r = await fetchWithDeadline(url, { headers: Object.assign({}, IG_HEADERS, { Referer: "https://www.instagram.com/" + username + "/" }), method: "GET" });
      body = r.status === 200 ? await r.text() : "";
    } catch { continue; }
    if (r.status === 404) {
      if (ABSENCE_RE.test(body || "")) return [null, "NOT_FOUND"];
      lastErr = "http_404"; continue;
    }
    if (r.status === 429 || r.status === 503) { sawRate = true; lastErr = "rate_limited"; continue; }
    if (r.status !== 200) { lastErr = "http_" + r.status; continue; }
    let payload = null;
    try { payload = JSON.parse(body); } catch { lastErr = "bad_json"; continue; }
    const user = payload && payload.data && payload.data.user;
    if (!user) return [null, (payload && (payload.data !== undefined || "data" in payload)) ? "NOT_FOUND" : "SOFT_NOT_FOUND"];
    const prof = normalizeProfile(user);
    if (prof) return [prof, null];
    lastErr = "bad_shape";
  }
  return [null, sawRate ? "rate_limited" : lastErr];
}

async function fetchOpengraph(username) {
  const r = await fetchText("https://www.instagram.com/" + encodeURIComponent(username) + "/opengraph/", { headers: CRAWLER_HEADERS, method: "GET" });
  if (r.status === 429 || r.status === 503) return [null, "rate_limited"];
  if (r.status === 404) return ABSENCE_RE.test(r.text) ? [null, "NOT_FOUND"] : [null, "http_404"];
  if (r.status !== 200 || !r.text) return [null, "http_" + r.status];
  if (MISSING_RE.test(r.text)) return [null, "NOT_FOUND"];
  const prof = parseOgHtml(r.text, username);
  return prof ? [prof, null] : [null, "empty_html"];
}

async function fetchWayback(username) {
  let avail;
  try {
    const r = await fetchWithDeadline("https://archive.org/wayback/available?url=" + encodeURIComponent("https://www.instagram.com/" + username + "/"), { headers: { Accept: "application/json" }, method: "GET" });
    avail = r.status === 200 ? await r.json() : null;
  } catch { return [null, "unreachable"]; }
  const snap = (avail && avail.archived_snapshots && avail.archived_snapshots.closest) || {};
  let snapUrl = String(snap.url || "");
  const ts = String(snap.timestamp || "");
  if (!snapUrl) return [null, "no_snapshot"];
  snapUrl = snapUrl.replace(/^http:\/\//, "https://").replace(/\/web\/(\d{14})\/?$/, "/web/$1id_/");
  const targets = [snapUrl];
  const rebuilt = "https://web.archive.org/web/" + ts + "id_/https://www.instagram.com/" + username + "/";
  if (!targets.includes(rebuilt)) targets.push(rebuilt);
  let html = ""; let lastErr = "no_snapshot";
  for (const target of targets) {
    const r = await fetchText(target, { headers: HTML_HEADERS, method: "GET" });
    if (r.status === 200 && r.text) { html = r.text; break; }
    lastErr = r.status === 404 ? "no_snapshot" : "http_" + r.status;
  }
  if (!html) return [null, lastErr];
  if (MISSING_RE.test(html)) return [null, "NOT_FOUND"];
  const prof = parseOgHtml(html, username);
  if (!prof) return [null, "empty_html"];
  prof.archived = true;
  const tsDigits = parseInt(ts, 10);
  if (tsDigits && ts.length >= 14) {
    const y = +ts.slice(0,4), mo = +ts.slice(4,6)-1, da = +ts.slice(6,8), h = +ts.slice(8,10), mi = +ts.slice(10,12), se = +ts.slice(12,14);
    prof.snapshot_at = Math.floor(Date.UTC(y, mo, da, h, mi, se) / 1000);
  }
  return [prof, null];
}

async function fetchEmbed(username) {
  const r = await fetchText("https://www.instagram.com/" + encodeURIComponent(username) + "/embed/captioned/", { headers: HTML_HEADERS, method: "GET" });
  if (r.status !== 200 || !r.text) return [null, "http_" + r.status];
  if (!new RegExp('"username"\\s*:\\s*"' + username.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + '"', "i").test(r.text)) return [null, "no_match"];
  let html = r.text;
  if (html.includes("\\u0026")) { try { html = Buffer.from(html, "latin1").toString("utf8"); } catch {} }
  const prof = parseOgHtml(html, username);
  return prof ? [prof, null] : [null, "empty_embed"];
}

const CHAIN = [fetchWebProfile, fetchOpengraph, fetchWayback, fetchEmbed];

async function lookupImpl(username) {
  let profile = null, sawRate = false, sawMissing = false;
  const deadline = Date.now() + TOTAL_BUDGET;
  let attempt = 0;
  while (true) {
    attempt += 1;
    let transient = false;
    for (const source of CHAIN) {
      if (isComplete(profile)) break;
      if (Date.now() > deadline) { transient = false; break; }
      let res, err;
      try { [res, err] = await source(username); } catch { res = null; err = "source_error"; }
      if (res) { profile = mergeProfile(profile, res); continue; }
      if (err === "NOT_FOUND" || err === "SOFT_NOT_FOUND") sawMissing = true;
      else if (err === "rate_limited" || err === "http_429" || err === "http_503") { sawRate = true; transient = true; }
      else if (err === "unreachable" || err === "source_error" || err === "http_0") transient = true;
    }
    if ((profile && isComplete(profile)) || (sawMissing && !profile) || !transient) break;
    if (attempt >= 2 || Date.now() + 1500 > deadline) break;
    await new Promise(r => setTimeout(r, 1200));
  }
  return [profile, sawRate, sawMissing];
}

function jsonOut(status, obj) {
  return new Response(JSON.stringify(obj), {
    status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Insta-Edge": "1" },
  });
}

async function handle(request) {
  const url = new URL(request.url);
  if (request.method !== "POST") {
    if (url.pathname === "/health" || url.pathname === "/") return jsonOut(200, { ok: "edge", ts: Math.floor(Date.now() / 1000) });
    return jsonOut(405, { success: false, error: "METHOD_NOT_ALLOWED" });
  }
  let body = {};
  try { body = await request.json(); } catch { return jsonOut(400, { success: false, error: "BAD_JSON" }); }

  // auth: shared key + one-time operation id (per-isolate replay store)
  if (!SHARED_KEY) return jsonOut(500, { success: false, error: "CONFIG_MISSING" });
  const key = String(body.key || request.headers.get("x-insta-key") || "");
  if (key.length !== SHARED_KEY.length || key !== SHARED_KEY) return jsonOut(403, { success: false, error: "INVALID_KEY" });
  const ts = Number(body.ts);
  if (!isFinite(ts) || Math.abs(Date.now() / 1000 - ts) > OP_TS_WINDOW) return jsonOut(403, { success: false, error: "STALE_TIMESTAMP" });
  const nonce = String(body.nonce || "");
  if (nonce.length < 8 || nonce.length > 128) return jsonOut(403, { success: false, error: "MISSING_NONCE" });
  const nonceHash = await sha16(nonce);
  const nowSec = nowS();
  if (seenNonces.get(nonceHash)) return jsonOut(403, { success: false, error: "REPLAY_DETECTED" });
  seenNonces.set(nonceHash, nowSec + 240);
  if (++sweeps % 64 === 0) { for (const [n, exp] of seenNonces) if (exp < nowSec) seenNonces.delete(n); for (const [ip, [st]] of rateBuckets) if (nowSec - st > RATE_WINDOW * 2) rateBuckets.delete(ip); }

  const ip = (request.headers.get("x-forwarded-for") || "edge").split(",")[0].trim();
  if (!rateOk(ip)) return jsonOut(429, { success: false, error: "CLIENT_RATE_LIMITED" });

  const username = cleanUsername(body.username);
  if (!username) return jsonOut(400, { success: false, error: "INVALID_USERNAME" });

  const hit = cacheGet(username);
  if (hit) { const [st, pl] = hit; return jsonOut(st, Object.assign({}, pl, { cached: true })); }

  const [profile, sawRate, sawMissing] = await lookupImpl(username);
  if (profile && isComplete(profile)) {
    const data = Object.assign({}, profile, { fetched_at: Math.floor(Date.now() / 1000) });
    for (const k of PROFILE_KEYS) if (!filled(data[k])) delete data[k];
    const payload = { success: true, data };
    cacheSet(username, 200, payload, CACHE_TTL_OK);
    return jsonOut(200, payload);
  }
  if (profile) {
    const data = Object.assign({}, profile, { fetched_at: Math.floor(Date.now() / 1000) });
    for (const k of PROFILE_KEYS) if (!filled(data[k])) delete data[k];
    const payload = { success: true, data, partial: true };
    cacheSet(username, 200, payload, CACHE_TTL_OK / 2);
    return jsonOut(200, payload);
  }
  if (sawMissing) {
    const payload = { success: false, error: "USER_NOT_FOUND" };
    cacheSet(username, 404, payload, CACHE_TTL_NOT_FOUND);
    return jsonOut(404, payload);
  }
  const payload = { success: false, error: sawRate ? "RATE_LIMITED" : "UPSTREAM_UNAVAILABLE" };
  cacheSet(username, 502, payload, CACHE_TTL_BUSY);
  return jsonOut(502, payload);
}

export default handle;
