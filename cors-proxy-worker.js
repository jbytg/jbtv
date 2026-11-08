// JB TV – hardened CORS proxy for Cloudflare Workers.
// Deploy: dash.cloudflare.com → Workers & Pages → your worker → Edit code → paste this → Deploy.
// In index.html:  const PROXY = 'https://jb-proxy.johanbiju15.workers.dev/?url=';
//
// Protections: only your site (exact origin) may use it · GET/HEAD only · blocks private, local and
// metadata addresses (also after redirects) · blocks risky ports and URLs with passwords · only passes
// video / audio / playlist data (HTML, JSON, scripts … are refused) · size and time limits · per-visitor
// rate limit (best effort) · strips cookies and unknown headers · no logging or storage.

const ALLOWED = ['https://tv.jbhub.ryzn.pro']; // exact origins allowed to use this proxy. Empty list = nobody.
const MAX_BYTES = 80 * 1024 * 1024;   // largest single response that is passed through
const MAX_PLAYLIST = 2 * 1024 * 1024; // largest playlist that is rewritten
const MAX_REDIRECTS = 4;
const TIMEOUT_MS = 20000;             // wait for the stream server's first reply
const RATE_PER_MIN = 600;             // requests per visitor address per minute (best effort, per server location)
const BAD_PORTS = new Set([21, 22, 23, 25, 53, 110, 111, 135, 139, 143, 445, 465, 587, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017]);
const BLOCKED_TYPE = /html|json|xml|javascript|ecmascript|css|svg|pdf|zip|x-www-form|multipart/i;
const KEEP = ['content-type', 'content-range', 'accept-ranges', 'etag', 'last-modified', 'cache-control', 'expires'];

const hits = new Map();
function limited(ip) {
  const now = Date.now(), e = hits.get(ip);
  if (!e || now - e.t > 60000) { if (hits.size > 5000) hits.clear(); hits.set(ip, { t: now, n: 1 }); return false; }
  return ++e.n > RATE_PER_MIN;
}

function badHost(host) {
  host = host.toLowerCase().replace(/^\[|\]$/g, '');
  if (!host || host === 'localhost' || /\.(localhost|local|internal|lan|home|corp|intranet)$/.test(host) || host === 'metadata.google.internal') return true;
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = +m[1], b = +m[2];
    return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && (b === 168 || b === 0)) || (a === 100 && b >= 64 && b <= 127) || (a === 198 && (b === 18 || b === 19));
  }
  if (host.includes(':')) return host === '::' || host === '::1' || /^(fc|fd|fe[89ab]|ff)/.test(host) || host.startsWith('::ffff:') || host.startsWith('64:ff9b');
  return /^\d+$/.test(host) || /^0x[0-9a-f]+$/i.test(host);
}
function checkTarget(str, selfHost) { // returns an error text, or '' when the address is fine
  let t; try { t = new URL(str); } catch (e) { return 'Bad address'; }
  if (t.protocol !== 'http:' && t.protocol !== 'https:') return 'Only http and https are allowed';
  if (t.username || t.password) return 'Addresses with a login are not allowed';
  if (t.port && BAD_PORTS.has(+t.port)) return 'Port not allowed';
  if (badHost(t.hostname) || t.hostname === selfHost) return 'Address not allowed';
  return '';
}
function requestOrigin(req) {
  const o = req.headers.get('Origin'); if (o) return o;
  try { return new URL(req.headers.get('Referer') || '').origin; } catch (e) { return ''; }
}
async function readText(stream, max) {
  const rd = stream.getReader(), parts = []; let n = 0;
  for (;;) {
    const { done, value } = await rd.read(); if (done) break;
    n += value.length; if (n > max) { rd.cancel(); return null; }
    parts.push(value);
  }
  const all = new Uint8Array(n); let o = 0; for (const p of parts) { all.set(p, o); o += p.length; }
  return new TextDecoder().decode(all);
}
const capped = (stream, max) => { let n = 0; return stream.pipeThrough(new TransformStream({ transform(c, ctl) { n += c.length; if (n > max) ctl.error(new Error('too large')); else ctl.enqueue(c); } })); };

async function fetchUpstream(target, headers, selfHost) {
  let url = target;
  for (let i = 0; i <= MAX_REDIRECTS; i++) { // every hop is checked, so a redirect cannot lead to a private address
    const bad = checkTarget(url, selfHost); if (bad) return { error: bad, status: 403 };
    const ctl = new AbortController(), timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
    let res;
    try { res = await fetch(url, { headers, redirect: 'manual', signal: ctl.signal }); }
    catch (e) { return { error: 'The proxy could not reach the stream', status: 502 }; }
    finally { clearTimeout(timer); }
    const loc = res.headers.get('location');
    if (res.status >= 300 && res.status < 400 && loc) {
      try { url = new URL(loc, url).href; } catch (e) { return { error: 'Bad redirect', status: 502 }; }
      if (res.body) res.body.cancel();
      continue;
    }
    return { res, url };
  }
  return { error: 'Too many redirects', status: 508 };
}

export default {
  async fetch(req) {
    const u = new URL(req.url);
    const origin = requestOrigin(req), ok = ALLOWED.includes(origin);
    const sec = { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Robots-Tag': 'noindex', 'Content-Security-Policy': "default-src 'none'; sandbox" };
    const cors = ok ? { 'Access-Control-Allow-Origin': origin, 'Vary': 'Origin', 'Access-Control-Expose-Headers': 'Content-Length, Content-Range, Content-Type' } : {};
    const send = (body, status, extra = {}) => new Response(body, { status, headers: { ...sec, ...cors, ...extra } });

    if (req.method === 'OPTIONS') {
      return ok ? send(null, 204, { 'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS', 'Access-Control-Allow-Headers': 'Range', 'Access-Control-Max-Age': '86400' }) : send('Forbidden or missing ?url=', 403);
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') return send('Method not allowed', 405, { Allow: 'GET, HEAD, OPTIONS' });
    if (!ok || u.pathname !== '/') return send('Forbidden or missing ?url=', 403);
    if (limited(req.headers.get('CF-Connecting-IP') || 'unknown')) return send('Too many requests', 429, { 'Retry-After': '30' });
    if (u.searchParams.has('ping')) return send('jb-proxy-ok', 200, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' });

    const target = u.searchParams.get('url');
    if (!target || target.length > 4096) return send('Missing ?url=', 400);
    const headers = { 'User-Agent': 'Mozilla/5.0', 'Accept': '*/*' };
    const range = req.headers.get('Range'); if (range && /^bytes=\d*-\d*$/.test(range)) headers.Range = range;

    const got = await fetchUpstream(target, headers, u.hostname);
    if (got.error) return send(got.error, got.status);
    const { res: up, url: finalUrl } = got;
    const pass = {}; KEEP.forEach(k => { const x = up.headers.get(k); if (x) pass[k] = x; });

    if (!up.ok) { if (up.body) up.body.cancel(); return send('The stream server answered ' + up.status, up.status); }
    const ct = up.headers.get('content-type') || '';
    if (BLOCKED_TYPE.test(ct) && !/dash\+xml/i.test(ct)) { if (up.body) up.body.cancel(); return send('This content type is not allowed', 415); }
    const len = +up.headers.get('content-length') || 0;
    if (len > MAX_BYTES) { if (up.body) up.body.cancel(); return send('Too large', 413); }
    if (req.method === 'HEAD') { if (up.body) up.body.cancel(); return send(null, up.status, pass); }

    const looksM3U8 = /mpegurl/i.test(ct) || /\.m3u8?(\?|$)/i.test(finalUrl);
    const directMedia = /\.(ts|m4s|mp4|m4v|aac|m4a|mp3|key|vtt|webvtt|jpe?g|png|webp)(\?|$)/i.test(finalUrl) || /^(video|audio|image)\//i.test(ct) || /text\/vtt/i.test(ct);
    const isPlaylist = s => /^\uFEFF?#EXTM3U/.test(s);
    let text = null, body = up.body;
    if (looksM3U8) {
      text = await readText(up.body, MAX_PLAYLIST);
      if (text === null) return send('Playlist too large', 413);
      if (!isPlaylist(text)) return send('Not a playlist', 415);
    } else if (!directMedia && up.body) { // unknown type: look at the first bytes
      const [a, b] = up.body.tee(), rd = a.getReader(), { value } = await rd.read(); rd.cancel();
      if (value && isPlaylist(new TextDecoder().decode(value.slice(0, 10)))) {
        text = await readText(b, MAX_PLAYLIST);
        if (text === null) return send('Playlist too large', 413);
      } else if (/octet-stream|mpegts|mp2t|mp4|ogg/i.test(ct)) body = b;
      else { b.cancel(); return send('This content type is not allowed', 415); }
    }

    if (text !== null) { // rewrite the playlist so every piece also goes through this proxy
      const self = u.origin + '/?url=';
      const abs = x => { try { return self + encodeURIComponent(new URL(x, finalUrl).href); } catch (e) { return x; } };
      text = text.split('\n').map(line => {
        const t = line.trim();
        if (!t) return line;
        if (t.startsWith('#')) return line.replace(/URI="([^"]+)"/g, (_, x) => `URI="${abs(x)}"`);
        return abs(t);
      }).join('\n');
      return send(text, up.status, { 'Content-Type': 'application/vnd.apple.mpegurl', 'Cache-Control': 'no-store' });
    }
    if (len && !up.headers.get('content-encoding')) pass['content-length'] = String(len);
    return send(up.body ? capped(body, MAX_BYTES) : null, up.status, pass);
  },
};
