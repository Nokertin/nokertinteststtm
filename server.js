// server.js
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const connectRedis = require('connect-redis');
const redis = require('redis');
const { createProxyMiddleware } = require('http-proxy-middleware');
const basicAuth = require('basic-auth');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- MongoDB (History) ----------
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});
const HistorySchema = new mongoose.Schema({
  userId: String,
  url: String,
  method: String,
  status: Number,
  timestamp: { type: Date, default: Date.now }
});
const History = mongoose.model('History', HistorySchema);

// ---------- Redis (sessions) ----------
const redisClient = redis.createClient({ url: process.env.REDIS_URL });
redisClient.connect().catch(console.error);

const RedisStore = connectRedis.default || connectRedis(session);

app.use(
  session({
    store: new RedisStore({ client: redisClient }),
    secret: 'very_secret_key', // можно вынести в env
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: true }
  })
);

// ---------- Middleware ----------
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');

// ---------- Basic Auth (pre‑generated users) ----------
const USERS = {
  alpha: 'alpha123',
  beta:  'beta456'
};

function authMiddleware(req, res, next) {
  const user = basicAuth(req);
  if (!user || !USERS[user.name] || USERS[user.name] !== user.pass) {
    res.set('WWW-Authenticate', 'Basic realm="proxy"');
    return res.status(401).send('Authentication required.');
  }
  req.session.userId = user.name;
  next();
}
app.use(authMiddleware);

// ---------- Routes ----------
app.get('/', (req, res) => {
  res.redirect('/proxy.html');
});

app.get('/login', (req, res) => {
  res.sendFile(__dirname + '/views/login.html');
});

app.post('/login', (req, res) => {
  const { user, pass } = req.body;
  if (USERS[user] && USERS[user] === pass) {
    req.session.userId = user;
    return res.redirect('/proxy.html');
  }
  res.status(401).send('Invalid credentials.');
});

app.get('/proxy.html', (req, res) => {
  res.sendFile(__dirname + '/views/proxy.html');
});

// ---------- History API ----------
app.get('/history', async (req, res) => {
  const records = await History.find({ userId: req.session.userId })
    .sort({ timestamp: -1 })
    .limit(50);
  res.json(records);
});

// ---------- Proxy endpoint ----------
app.use('/proxy/:encodedUrl*', (req, res, next) => {
  const decoded = decodeURIComponent(req.params.encodedUrl);
  
  // Сохраняем запись истории
  const hist = new History({
    userId: req.session.userId,
    url: decoded,
    method: 'GET'
  });
  hist.save().then(() => (req.historyId = hist._id));

  // Перенаправляем middleware прокси с нужным target
  const proxyMiddleware = createProxyMiddleware({
    target: decoded,
    changeOrigin: true,
    secure: true,
    onProxyReq: (proxyReq) => {
      if (req.session.cookies) {
        proxyReq.setHeader('Cookie', req.session.cookies.join('; '));
      }
    },
    onProxyRes: async (proxyRes, _, res) => {
      const setCookies = proxyRes.headers['set-cookie'];
      if (setCookies) req.session.cookies = setCookies;
      await History.updateOne(
        { _id: req.historyId },
        { status: proxyRes.statusCode }
      );
    }
  });
  proxyMiddleware(req, res, next);
});

// ---------- Healthcheck ----------
app.get('/healthz', (_, res) => res.send('ok'));

// ---------- Запуск ----------
app.listen(PORT, () => {
  console.log(`🚀 Web‑proxy running on http://localhost:${PORT}`);
});