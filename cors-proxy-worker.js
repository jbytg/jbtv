// JB TV – tiny CORS proxy for Cloudflare Workers (free plan is enough to start)
// Deploy: dash.cloudflare.com → Workers & Pages → Create → Create Worker → Edit code → paste this → Deploy.
// Then in index.html set:  const PROXY = 'https://YOUR-WORKER.workers.dev/?url=';
// Only your own site can use it: your domains are listed in ALLOWED (leave [] to allow everyone).
const ALLOWED = ['https://tv.jbhub.ryzn.pro', 'https://jbhub.ryzn.pro'];

export default {
  async fetch(req) {
    const u = new URL(req.url);
    const origin = req.headers.get('Origin') || '';
    const ok = !ALLOWED.length || ALLOWED.includes(origin);
    const cors = {
      'Access-Control-Allow-Origin': ok ? (origin || '*') : 'null',
      'Access-Control-Allow-Headers': '*',
      'Access-Control-Expose-Headers': '*',
    };
    if (req.method === 'OPTIONS') return new Response(null, { headers: cors });
    const target = u.searchParams.get('url');
    if (!ok || !target || !/^https?:\/\//i.test(target)) return new Response('Forbidden or missing ?url=', { status: 403, headers: cors });

    const headers = { 'User-Agent': 'Mozilla/5.0' };
    if (req.headers.get('Range')) headers.Range = req.headers.get('Range');
    let up;
    try { up = await fetch(target, { headers, redirect: 'follow' }); }
    catch (e) { return new Response('Proxy could not reach the stream: ' + e.message, { status: 502, headers: cors }); }

    const h = new Headers(up.headers);
    Object.entries(cors).forEach(([k, v]) => h.set(k, v));
    const ct = up.headers.get('content-type') || '';
    const looksM3U8 = /mpegurl/i.test(ct) || /\.m3u8?(\?|$)/i.test(target);
    const isMedia = /^(video|audio|image)\//i.test(ct) || /\.(ts|m4s|mp4|aac|m4a|key|vtt|jpe?g|png)(\?|$)/i.test(target);

    let body = up.body, text = null;
    if (looksM3U8) text = await up.text();
    else if (!isMedia && up.body) { // unknown type: peek at the first bytes to spot playlists with odd names
      const [a, b] = up.body.tee();
      const reader = a.getReader(), { value } = await reader.read();
      reader.cancel();
      if (value && new TextDecoder().decode(value.slice(0, 10)).replace(/^\uFEFF/, '').startsWith('#EXTM3U')) text = await new Response(b).text();
      else body = b;
    }
    if (text === null) return new Response(body, { status: up.status, headers: h });

    // Rewrite the playlist so every segment / sub-playlist also goes through this proxy
    const self = u.origin + u.pathname + '?url=';
    const base = up.url || target;
    const abs = x => { try { return self + encodeURIComponent(new URL(x, base).href); } catch (e) { return x; } };
    text = text.split('\n').map(line => {
      const t = line.trim();
      if (!t) return line;
      if (t.startsWith('#')) return line.replace(/URI="([^"]+)"/g, (_, x) => `URI="${abs(x)}"`);
      return abs(t);
    }).join('\n');
    h.delete('content-length'); h.delete('content-encoding');
    h.set('content-type', 'application/vnd.apple.mpegurl'); h.set('cache-control', 'no-store');
    return new Response(text, { status: up.status, headers: h });
  },
};
