const http = require('http');
const fs   = require('fs');
const path = require('path');

const PORT = process.env.PORT || 5502;
const MIME = {
  '.html': 'text/html',
  '.css':  'text/css',
  '.js':   'text/javascript',
  '.ico':  'image/x-icon',
};

// Only these paths are allowed — everything else returns 404
const ALLOWED = new Set(['/', '/index.html', '/js/supabase.js', '/js/app.js', '/config.js', '/favicon.ico']);

function loadEnv() {
  try {
    const env = fs.readFileSync(path.join(__dirname, '.env'), 'utf8');
    env.split('\n').forEach(line => {
      const [key, ...rest] = line.split('=');
      if (key && rest.length) process.env[key.trim()] = rest.join('=').trim();
    });
  } catch (_) {}
}
loadEnv();

// ── Rate limiter: max 30 requests per IP per minute (stricter than public site) ──
const rateMap = new Map();
setInterval(() => {
  const cutoff = Date.now() - 60_000;
  for (const [ip, entry] of rateMap) {
    if (entry.start < cutoff) rateMap.delete(ip);
  }
}, 60_000);

function isRateLimited(ip) {
  const now   = Date.now();
  const entry = rateMap.get(ip) || { count: 0, start: now };
  if (now - entry.start > 60_000) {
    rateMap.set(ip, { count: 1, start: now });
    return false;
  }
  entry.count++;
  rateMap.set(ip, entry);
  return entry.count > 30;
}

// ── Security headers ───────────────────────────────────────────
const SEC = {
  'X-Content-Type-Options':  'nosniff',
  'X-Frame-Options':         'DENY',
  'X-XSS-Protection':        '1; mode=block',
  'Referrer-Policy':         'no-referrer',
  'Permissions-Policy':      'geolocation=(), microphone=(), camera=()',
  'Cache-Control':           'no-store',
  'Content-Security-Policy': [
    "default-src 'self'",
    "script-src 'self' https://cdn.jsdelivr.net",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src https://fonts.gstatic.com",
    "img-src 'self' data:",
    "connect-src 'self' https://*.supabase.co wss://*.supabase.co https://cdn.jsdelivr.net",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join('; '),
};

http.createServer((req, res) => {
  const ip      = (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
                  || req.socket.remoteAddress;
  const urlPath = req.url.split('?')[0];

  // HTTPS redirect in production
  if (process.env.NODE_ENV === 'production'
      && req.headers['x-forwarded-proto']
      && req.headers['x-forwarded-proto'].split(',')[0].trim() !== 'https') {
    const host = req.headers['host'] || '';
    res.writeHead(301, { Location: `https://${host}${req.url}`, ...SEC });
    res.end();
    return;
  }

  // Rate limit
  if (isRateLimited(ip)) {
    res.writeHead(429, { 'Content-Type': 'text/plain', ...SEC });
    res.end('Too many requests.');
    return;
  }

  // Config endpoint — injects Supabase credentials for the browser
  if (urlPath === '/config.js') {
    const config = `window.__ENV__ = {
  SUPABASE_URL: ${JSON.stringify(process.env.SUPABASE_URL || '')},
  SUPABASE_ANON_KEY: ${JSON.stringify(process.env.SUPABASE_ANON_KEY || '')}
};`;
    res.writeHead(200, { 'Content-Type': 'text/javascript', ...SEC });
    res.end(config);
    return;
  }

  // Allowlist — reject anything not explicitly permitted
  if (!ALLOWED.has(urlPath)) {
    res.writeHead(404, { 'Content-Type': 'text/plain', ...SEC });
    res.end('Not found');
    return;
  }

  const filePath = path.join(__dirname, urlPath === '/' ? 'index.html' : urlPath);

  // Block path traversal
  if (!path.resolve(filePath).startsWith(path.resolve(__dirname))) {
    res.writeHead(403, { 'Content-Type': 'text/plain', ...SEC });
    res.end('Forbidden');
    return;
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain', ...SEC });
      res.end('Not found');
      return;
    }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(filePath)] || 'text/plain', ...SEC });
    res.end(data);
  });
}).listen(PORT, () => console.log(`FranchiseForest Admin → http://localhost:${PORT}`));
