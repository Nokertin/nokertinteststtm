// ─────────────────────────────────────────────
// server.js  (обновлён с Cheerio)
// ─────────────────────────────────────────────

// ---------- Библиотеки ----------
require('dotenv').config();
const express      = require('express');
const session      = require('express-session');
const MongoStore   = require('connect-mongo');
const { createProxyMiddleware } = require('http-proxy-middleware');
const basicAuth    = require('basic-auth');          // (не используется, но оставим)
const mongoose     = require('mongoose');
const { HttpsProxyAgent } = require('https-proxy-agent');
const fs           = require('fs');
const path         = require('path');
const cheerio      = require('cheerio');

// ---------- Инициализация ----------
const app   = express();
const PORT  = process.env.PORT || 3000;

// ---------- MongoDB ----------
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});
const mongoClient = mongoose.connection.getClient();

const HistorySchema = new mongoose.Schema({
  userId:    String,
  url:       String,
  method:    String,
  status:    Number,
  timestamp: { type: Date, default: Date.now },
});
const History = mongoose.model('History', HistorySchema);

// ---------- Сессии ----------
app.use(
  session({
    store: MongoStore.create({
      client: mongoClient,
      collectionName: 'sessions',
    }),
    secret: process.env.SESSION_SECRET || 'very_secret_key',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: true,           // если вы разворачиваете под HTTPS
      sameSite: 'lax',
    },
  })
);

// ---------- Middleware ----------
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');

// ---------- Auth users ----------
const USERS = {
  Biba: 'Biba1Boba',
  Boba: 'Boba1Biba',
};

// ---------- Проверка авторизации ----------
function isAuthenticated(req, res, next) {
  if (req.session.userId) return next();
  res.redirect('/login');
}

// ---------- Страницы ----------
app.get('/', (req, res) => res.redirect('/login'));

app.get('/login', (req, res) =>
  res.sendFile(__dirname + '/views/login.html')
);

app.post('/login', (req, res) => {
  const { user, pass } = req.body;
  if (USERS[user] && USERS[user] === pass) {
    req.session.userId = user;
    return res.redirect('/proxy.html');
  }
  res.status(401).send('Invalid credentials.');
});

app.use(isAuthenticated);

// ------------------------------------------------------------------
// 1️⃣ Перезаписываем proxy.html через Cheerio
// ------------------------------------------------------------------
app.get('/proxy.html', (req, res) => {
  const filePath = path.join(__dirname, 'views/proxy.html');
  let html = fs.readFileSync(filePath, 'utf8');

  // Парсим с помощью Cheerio
  const $ = cheerio.load(html);

  function proxyEncode(url) {
    return `/proxy/${encodeURIComponent(url)}`;
  }

  // Меняем все href/src/action, которые являются абсолютными URL‑ами
  $('a[href], img[src], script[src], link[href], form[action]').each((i, el) => {
    const tag = $(el).get(0).tagName.toLowerCase();
    const attr = tag === 'form'
      ? 'action'
      : (tag === 'img' || tag === 'script')
        ? 'src'
        : 'href';

    let url = $(el).attr(attr);
    if (!url) return;

    try {
      // Создаём абсолютный URL относительно текущего хоста
      const u = new URL(url, `${req.protocol}://${req.get('host')}`);
      if (u.protocol === 'http:' || u.protocol === 'https:') {
        $(el).attr(attr, proxyEncode(u.toString()));
      }
    } catch (_) {
      // Не‑валидный URL – оставляем как есть
    }
  });

  res.send($.html());
});

// ------------------------------------------------------------------
// 2️⃣ Маршрут /proxy/:encodedUrl* (прокси)
// ------------------------------------------------------------------
app.use('/proxy/:encodedUrl*', (req, res, next) => {
  const decoded = decodeURIComponent(req.params.encodedUrl);

  // Конфигурация внешнего прокси
  const externalProxyUrl = `http://xggsmdrf:se2wmii8b1qh@185.39.8.196:5853`;
  const agent = new HttpsProxyAgent(externalProxyUrl);

  const hist = new History({
    userId: req.session.userId,
    url: decoded,
    method: 'GET',
  });
  hist.save().then(() => (req.historyId = hist._id));

  const proxyMiddleware = createProxyMiddleware({
    target: decoded,
    changeOrigin: true,
    secure: false,
    agent,                                 // добавлено
    onProxyReq: proxyReq => {
      if (req.session.cookies) {
        proxyReq.setHeader('Cookie', req.session.cookies.join('; '));
      }
    },
    onProxyRes: async (_, _proxyRes, res) => {
      const setCookies = _proxyRes.headers['set-cookie'];
      if (setCookies) req.session.cookies = setCookies;
      await History.updateOne(
        { _id: req.historyId },
        { status: _proxyRes.statusCode }
      );
    },
  });

  proxyMiddleware(req, res, next);
});

// ------------------------------------------------------------------
// 3️⃣ История
// ------------------------------------------------------------------
app.get('/history', async (req, res) => {
  const records = await History.find({ userId: req.session.userId })
    .sort({ timestamp: -1 })
    .limit(50);
  res.json(records);
});

// ------------------------------------------------------------------
// 4️⃣ Healthcheck
// ------------------------------------------------------------------
app.get('/healthz', (_, res) => res.send('ok'));

// ------------------------------------------------------------------
// Запуск сервера
// ------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`🚀 Web‑proxy running on http://localhost:${PORT}`);
});
