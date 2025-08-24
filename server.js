import express from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import morgan from 'morgan';
import helmet from 'helmet';

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
    req.session.user = { username: user };
    return res.redirect('/');
  }
  res.status(401).render('login', { error: 'Неверные данные' });
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/', requireAuth, async (req, res) => {
  // Теперь эта страница будет работать
  res.send(`Welcome, ${req.session.user.username}!`);
});

// Добавим заглушку для /browser, чтобы избежать ошибок
app.get('/browser', requireAuth, async (req, res) => {
  res.send(`Proxy browser for ${req.session.user.username}`);
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Web proxy listening on http://localhost:${port}`));