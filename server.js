const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';

// ── DB INIT ──
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      display_name VARCHAR(100),
      password_hash VARCHAR(255) NOT NULL,
      color VARCHAR(20) DEFAULT '#7c6fff',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS app_data (
      id INTEGER PRIMARY KEY DEFAULT 1,
      data JSONB NOT NULL DEFAULT '[]',
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS changelog (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50),
      action TEXT,
      detail TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) NOT NULL,
      title VARCHAR(255),
      body TEXT,
      read BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    INSERT INTO app_data (id, data) VALUES (1, '[]') ON CONFLICT (id) DO NOTHING;
  `);
  console.log('Database initialized');
}

// ── MIDDLEWARE AUTH ──
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token mancante' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token non valido' });
  }
}

// ── AUTH ROUTES ──
app.post('/api/register', async (req, res) => {
  const { email, username, display_name, password, color } = req.body;
  if (!email || !username || !password) return res.status(400).json({ error: 'Campi obbligatori mancanti' });
  if (password.length < 4) return res.status(400).json({ error: 'Password minimo 4 caratteri' });

  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, email, display_name, password_hash, color) VALUES ($1, $2, $3, $4, $5) RETURNING id, username, display_name, color',
      [username.toLowerCase(), email.toLowerCase(), display_name || username, hash, color || '#7c6fff']
    );
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, username: user.username, display: user.display_name, color: user.color }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { username: user.username, display: user.display_name, color: user.color } });
  } catch (e) {
    if (e.code === '23505') {
      if (e.constraint?.includes('email')) return res.status(409).json({ error: 'email_exists' });
      if (e.constraint?.includes('username')) return res.status(409).json({ error: 'username_exists' });
    }
    console.error(e);
    res.status(500).json({ error: 'Errore server' });
  }
});

app.post('/api/login', async (req, res) => {
  const { login, password } = req.body;
  if (!login || !password) return res.status(400).json({ error: 'Campi obbligatori mancanti' });

  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE username = $1 OR email = $1',
      [login.toLowerCase()]
    );
    if (!result.rows.length) return res.status(401).json({ error: 'user_not_found' });
    const user = result.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'wrong_password' });

    const token = jwt.sign({ id: user.id, username: user.username, display: user.display_name, color: user.color }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { username: user.username, display: user.display_name, color: user.color } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Errore server' });
  }
});

// ── DATA ROUTES ──
app.get('/api/data', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT data, updated_at FROM app_data WHERE id = 1');
    res.json({ data: result.rows[0]?.data || [], updated_at: result.rows[0]?.updated_at });
  } catch (e) { res.status(500).json({ error: 'Errore server' }); }
});

app.put('/api/data', authMiddleware, async (req, res) => {
  const { data } = req.body;
  if (!Array.isArray(data)) return res.status(400).json({ error: 'Data deve essere un array' });
  try {
    await pool.query('UPDATE app_data SET data = $1, updated_at = NOW() WHERE id = 1', [JSON.stringify(data)]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Errore server' }); }
});

// ── CHANGELOG ROUTES ──
app.get('/api/changelog', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM changelog ORDER BY created_at ASC LIMIT 500');
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: 'Errore server' }); }
});

app.post('/api/changelog', authMiddleware, async (req, res) => {
  const { action, detail } = req.body;
  try {
    await pool.query('INSERT INTO changelog (username, action, detail) VALUES ($1, $2, $3)', [req.user.username, action, detail || '']);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Errore server' }); }
});

app.delete('/api/changelog', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM changelog');
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Errore server' }); }
});

// ── NOTIFICATIONS ROUTES ──
app.get('/api/notifications', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM notifications WHERE username = $1 ORDER BY created_at DESC LIMIT 50', [req.user.username]);
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: 'Errore server' }); }
});

app.post('/api/notifications', authMiddleware, async (req, res) => {
  const { username, title, body } = req.body;
  try {
    await pool.query('INSERT INTO notifications (username, title, body) VALUES ($1, $2, $3)', [username || req.user.username, title, body]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Errore server' }); }
});

app.put('/api/notifications/read', authMiddleware, async (req, res) => {
  try {
    await pool.query('UPDATE notifications SET read = TRUE WHERE username = $1', [req.user.username]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Errore server' }); }
});

app.delete('/api/notifications', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM notifications WHERE username = $1', [req.user.username]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Errore server' }); }
});

// ── SERVE FRONTEND ──
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── START ──
const PORT = process.env.PORT || 3000;
initDb().then(() => {
  app.listen(PORT, () => console.log(`Server avviato su porta ${PORT}`));
}).catch(err => {
  console.error('Errore inizializzazione DB:', err);
  process.exit(1);
});
