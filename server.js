// سرور اصلی سایت کلینیک المپیک
// این فایل هم سایت اصلی را نمایش می‌دهد و هم API پنل مدیریت را فراهم می‌کند.

require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'change-me-123';
const SESSION_SECRET = process.env.SESSION_SECRET || 'a-random-secret-change-this';

const CONTENT_PATH = path.join(__dirname, 'data', 'content.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

app.use(express.json());
app.use(cookieParser());

// جلوگیری از کش‌شدن صفحات و API توسط مرورگر — تا تغییرات پنل مدیریت همیشه فوراً روی سایت دیده شود
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});

app.use('/uploads', express.static(UPLOADS_DIR));
app.use(express.static(path.join(__dirname, 'public'), { etag: false, lastModified: false }));       // سایت اصلی
app.use('/admin', express.static(path.join(__dirname, 'admin'), { etag: false, lastModified: false })); // پنل مدیریت (رابط کاربری)

// ---------- ابزار ساخت و بررسی توکن ورود ----------
function makeToken() {
  return crypto.createHmac('sha256', SESSION_SECRET).update(ADMIN_USER + Date.now()).digest('hex');
}
let validTokens = new Set(); // در حافظه؛ با ری‌استارت سرور همه باید دوباره لاگین کنند

function requireAuth(req, res, next) {
  const token = req.cookies.admin_token;
  if (token && validTokens.has(token)) return next();
  return res.status(401).json({ error: 'برای این عملیات باید وارد پنل مدیریت شوید.' });
}

// ---------- ورود به پنل ----------
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    const token = makeToken();
    validTokens.add(token);
    res.cookie('admin_token', token, { httpOnly: true, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 12 }); // 12 ساعت
    return res.json({ ok: true });
  }
  return res.status(401).json({ error: 'نام کاربری یا رمز عبور اشتباه است.' });
});

app.post('/api/logout', (req, res) => {
  const token = req.cookies.admin_token;
  if (token) validTokens.delete(token);
  res.clearCookie('admin_token');
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const token = req.cookies.admin_token;
  res.json({ loggedIn: !!(token && validTokens.has(token)) });
});

// ---------- خواندن محتوای سایت (عمومی - همه می‌توانند بخوانند) ----------
app.get('/api/content', (req, res) => {
  try {
    const data = fs.readFileSync(CONTENT_PATH, 'utf-8');
    res.json(JSON.parse(data));
  } catch (e) {
    res.status(500).json({ error: 'خطا در خواندن محتوا' });
  }
});

// ---------- ذخیره محتوای سایت (فقط پنل مدیریت لاگین‌شده) ----------
app.put('/api/content', requireAuth, (req, res) => {
  try {
    const incoming = req.body;
    if (!incoming || typeof incoming !== 'object') {
      return res.status(400).json({ error: 'داده نامعتبر است.' });
    }
    fs.writeFileSync(CONTENT_PATH, JSON.stringify(incoming, null, 2), 'utf-8');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'خطا در ذخیره محتوا' });
  }
});

// ---------- آپلود تصویر (مثلاً برای تعویض لوگو یا عکس‌ها) ----------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + '-' + Math.round(Math.random() * 1e6) + ext);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // حداکثر ۵ مگابایت
  fileFilter: (req, file, cb) => {
    if (/^image\/(png|jpe?g|webp|svg\+xml)$/.test(file.mimetype)) cb(null, true);
    else cb(new Error('فقط فایل تصویری مجاز است.'));
  }
});

app.post('/api/upload', requireAuth, upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'فایلی ارسال نشد.' });
  res.json({ ok: true, url: '/uploads/' + req.file.filename });
});

app.listen(PORT, () => {
  console.log(`سرور کلینیک المپیک روی پورت ${PORT} اجرا شد.`);
  console.log(`سایت:  http://localhost:${PORT}`);
  console.log(`پنل مدیریت: http://localhost:${PORT}/admin`);
});
