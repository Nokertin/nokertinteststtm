import express from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import fetch from 'node-fetch';
import morgan from 'morgan';
import helmet from 'helmet';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import * as cheerio from 'cheerio';
import HttpsProxyAgent from 'https-proxy-agent';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// --- Security & utils
app.use(helmet({ contentSecurityPolicy: false }));
app.use(morgan('dev'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// --- Пользователи для входа
const USERS = {
  Biba: 'Biba1Boba',
  Boba: 'Boba1Biba',
};

// --- Config (удален users.json, теперь пользователи в коде)
let UPSTREAMS = JSON.parse(fs.readFileSync(path.join(__dirname, 'config', 'upstreams.json'), 'utf-8'));
UPSTREAMS.push({ id: 'direct', http: null, https: null });

// --- Прокси с логином/паролем
const PROXIES = [
  { id: '185.39.8.196', host: '185.39.8.196', port: '5853', auth: 'xggsmdrf:se2wmii8b1qh' },
  { id: '77.83.233.196', host: '77.83.233.196', port: '6814', auth: 'xggsmdrf:se2wmii8b1qh' },
  { id: '216.173.78.200', host: '216.173.78.200', port: '6020', auth: 'xggsmdrf:se2wmii8b1qh' },
  { id: '92.112.227.247', host: '92.112.227.247', port: '6419', auth: 'xggsmdrf:se2wmii8b1qh' },
  { id: '64.137.104.248', host: '64.137.104.248', port: '5858', auth: 'xggsmdrf:se2wmii8b1qh' }
];

// --- DB
const db = await open({ filename: path.join(__dirname, 'data.db'), driver: sqlite3.Database });
await db.exec(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL
)`);
for (const username of Object.keys(USERS)) {
  try { await db.run('INSERT INTO users(username) VALUES (?)', username); } catch {}
}
await db.exec(`CREATE TABLE IF NOT EXISTS settings (
  user_id INTEGER PRIMARY KEY,
  selected_proxy_id TEXT
)`);

// --- Session
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax' }
}));

// --- Auth middleware
function requireAuth(req, res, next) {
  if (req.session.user) return next();
  res.redirect('/login');
}

// --- Routes
app.get('/login', (req, res) => res.render('login', { error: null }));

app.post('/login', async (req, res) => {
  const { user, pass } = req.body;
  if (USERS[user] && USERS[user] === pass) {
    const row = await db.get('SELECT id FROM users WHERE username = ?', user);
    req.session.user = { id: row.id, username: user };
    return res.redirect('/');
  }
  res.status(401).render('login', { error: 'Неверные данные' });
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/', requireAuth, async (req, res) => {
  const proxies = UPSTREAMS;
  const setting = await db.get('SELECT selected_proxy_id FROM settings WHERE user_id = ?', req.session.user.id);
  res.render('home', { user: req.session.user, proxies, selected: setting?.selected_proxy_id || null });
});

app.post('/select-proxy', requireAuth, async (req, res) => {
  const { proxyId } = req.body;
  const exists = PROXIES.find(p => p.id === proxyId) || { id: 'direct' };
  await db.run(
    'INSERT INTO settings(user_id, selected_proxy_id) VALUES (?, ?) ON CONFLICT(user_id) DO UPDATE SET selected_proxy_id=excluded.selected_proxy_id',
    req.session.user.id, exists.id
  );
  res.redirect('/browser?start=https://duckduckgo.com/');
});

app.get('/browser', requireAuth, async (req, res) => {
  const start = req.query.start;
  if (!start || start.trim() === '') return res.status(400).send('Missing url');
  let startProxyPath;
  try {
    const u = new URL(start);
    startProxyPath = `/proxy/${u.protocol.slice(0, -1)}/${u.host}${u.pathname}${u.search}`;
  } catch {
    const searchQuery = encodeURIComponent(start.trim());
    startProxyPath = `/proxy/https/duckduckgo.com/?q=${searchQuery}`;
  }
  res.render('browser', { startProxyPath, startUrl: start });
});

// --- Helper для переписывания HTML
function rewriteHtml(html, baseUrl, req) {
  const $ = cheerio.load(html);
  const base = new URL(baseUrl);

  const createProxiedUrl = (originalUrl) => {
    try {
      if (originalUrl.startsWith('data:')) return originalUrl;
      const absoluteUrl = new URL(originalUrl, base);
      let proxied = `/proxy/${absoluteUrl.protocol.slice(0, -1)}/${absoluteUrl.host}${absoluteUrl.pathname}`;
      if (absoluteUrl.search) proxied += `?${absoluteUrl.search.slice(1)}`;
      return `${req.protocol}://${req.headers.host}${proxied}`;
    } catch {
      return originalUrl;
    }
  };

  $('[src], [href], [action]').each(function() {
    const el = $(this);
    const originalUrl = el.attr('src') || el.attr('href') || el.attr('action');
    if (originalUrl) {
      const proxiedUrl = createProxiedUrl(originalUrl);
      if (el.is('[href]')) el.attr('href', proxiedUrl);
      else if (el.is('[src]')) el.attr('src', proxiedUrl);
      else if (el.is('[action]')) el.attr('action', proxiedUrl);
    }
  });

  $('style').each(function() {
    let css = $(this).html();
    css = css.replace(/url\(['"]?(.*?)['"]?\)/g, (match, p1) => `url('${createProxiedUrl(p1)}')`);
    $(this).html(css);
  });

  return $.html();
}

// --- Proxy endpoint
app.all('/proxy/:protocol/:host/*', requireAuth, async (req, res) => {
  const { protocol, host } = req.params;
  const reqPath = req.params[0] ? '/' + req.params[0] : '/';
  let target;
  try {
    target = new URL(`${protocol}://${host}${reqPath}`);
    const searchParams = new URLSearchParams(target.search);
    for (const [key, value] of Object.entries(req.query)) searchParams.append(key, value);
    target.search = searchParams.toString();
  } catch {
    return res.status(400).send('Bad URL');
  }

  const setting = await db.get('SELECT selected_proxy_id FROM settings WHERE user_id = ?', req.session.user.id);
  let agent = null;

  if (setting?.selected_proxy_id && setting.selected_proxy_id !== 'direct') {
    const selectedProxy = PROXIES.find(p => p.id === setting.selected_proxy_id);
    if (selectedProxy) {
      const proxyUrl = `http://${selectedProxy.auth}@${selectedProxy.host}:${selectedProxy.port}`;
      agent = new HttpsProxyAgent(proxyUrl);
    }
  }

  const headers = { ...req.headers };
  delete headers['host'];
  delete headers['cookie'];
  delete headers['accept-encoding'];
  headers['referer'] = target.toString();

  try {
    const opts = { method: req.method, headers, redirect: 'manual', agent };
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      if (req.is('application/x-www-form-urlencoded')) opts.body = new URLSearchParams(req.body).toString();
      else if (req.is('application/json')) opts.body = JSON.stringify(req.body);
    }

    const resp = await fetch(target, opts);

    if (resp.status >= 300 && resp.status < 400 && resp.headers.get('location')) {
      const locUrl = new URL(resp.headers.get('location'), target);
      const proxied = `/proxy/${locUrl.protocol.slice(0, -1)}/${locUrl.host}${locUrl.pathname}${locUrl.search}`;
      res.set('Location', `${req.protocol}://${req.headers.host}${proxied}`);
      return res.status(resp.status).end();
    }

    const ct = resp.headers.get('content-type') || '';
    res.status(resp.status);
    if (ct.includes('text/html')) {
      const text = await resp.text();
      const rewritten = rewriteHtml(text, target.toString(), req);
      res.set('content-type', 'text/html; charset=utf-8');
      return res.send(rewritten);
    }

    const buf = Buffer.from(await resp.arrayBuffer());
    if (ct) res.set('content-type', ct);
    return res.send(buf);

  } catch (e) {
    console.error(e);
    return res.status(502).send(`Proxy error: ${e.message}`);
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Web proxy listening on http://localhost:${port}`));