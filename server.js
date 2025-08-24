require('dotenv').config();

const express    = require('express');
const session    = require('express-session');
const MongoStore = require('connect-mongo');
const { createProxyMiddleware } = require('http-proxy-middleware');
const mongoose   = require('mongoose');

const app  = express();
const PORT = process.env.PORT || 3000;

// ---------- MongoDB ----------
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
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
      // `secure` должен быть **false** только при работе по HTTP
      secure: process.env.NODE_ENV === 'production',   // <-- 1
      sameSite: 'lax',
    },
  })
);

// ---------- Middleware ----------
app.use(express.urlencoded({ extended: true }));
app.use(express.json());               // <--- добавили
app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');

// ---------- Пользователи для входа ----------
const USERS = {
  Biba: 'Biba1Boba',
  Boba: 'Boba1Biba',
};

// Middleware для проверки аутентификации
function isAuthenticated(req, res, next) {
  if (req.session.userId) return next();
  res.redirect('/login');
}

// ---------- Routes ----------
app.get('/', (req, res) => res.redirect('/login'));

app.get('/login', (req, res) =>
  res.sendFile(__dirname + '/views/login.html')
);

app.post('/login', (req, res) => {
  const { user, pass } = req.body;
  if (USERS[user] && USERS[user] === pass) {
    req.session.userId = user;          // сохраняем id
    return res.redirect('/proxy.html');
  }
  res.status(401).send('Invalid credentials.');
});

// Защищенные маршруты (требуют аутентификации)
app.use(isAuthenticated);

app.get('/proxy.html', (req, res) =>
  res.sendFile(__dirname + '/views/proxy.html')
);

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

  // Сохраняем запрос в истории
  const hist = new History({
    userId: req.session.userId,
    url: decoded,
    method: 'GET',
  });
  hist.save().then(() => (req.historyId = hist._id));

  const proxyMiddleware = createProxyMiddleware({
    target: decoded,
    changeOrigin: true,
    secure: false,          // можно оставить false – для dev
    onProxyReq: (proxyReq) => {
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

// ---------- Healthcheck ----------
app.get('/healthz', (_, res) => res.send('ok'));

// ---------- Запуск ----------
app.listen(PORT, () => {
  console.log(`🚀 Web‑proxy running on http://localhost:${PORT}`);
});
