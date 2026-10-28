import express from 'express';
import multer from 'multer';
import { db } from './db.js';
import { makeSalt, hashPassword, verifyPassword, deriveKey, encrypt, decrypt } from './crypto.js';
import { createSession, sessionMiddleware, requireCsrf, requireLogin, logout } from './sessions.js';

export const app = express();
const origin = process.env.APP_ORIGIN || 'https://localhost:3000';
const attempts = new Map();

app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
  if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && req.get('Origin') !== origin) {
    return res.status(403).json({ error: 'Invalid request origin.' });
  }
  next();
});
app.use('/api', sessionMiddleware);
app.use('/api', requireCsrf);
app.use(express.json({ limit: '20kb' }));
app.use(express.static(new URL('./public', import.meta.url).pathname));

function limitAuthentication(req, res, next) {
  const now = Date.now();
  for (const [ip, value] of attempts) {
    if (value.expires <= now) attempts.delete(ip);
  }
  const value = attempts.get(req.ip) || { count: 0, expires: now + 15 * 60 * 1000 };
  value.count += 1;
  attempts.set(req.ip, value);
  if (value.count > 10) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  next();
}

function validCredentials(username, password) {
  return typeof username === 'string' && /^[a-zA-Z0-9_]{3,50}$/.test(username)
    && typeof password === 'string' && password.length >= 12 && password.length <= 128;
}

app.get('/api/session', (req, res) => {
  const session = req.session || createSession(req, res);
  res.json({ username: session.username || null, csrf: session.csrf });
});

app.post('/api/register', limitAuthentication, async (req, res) => {
  const { username, password } = req.body || {};
  if (!validCredentials(username, password)) {
    return res.status(400).json({ error: 'Use a 3–50 character username (letters, numbers, underscore) and a 12–128 character master password.' });
  }
  const passwordSalt = makeSalt();
  const encryptionSalt = makeSalt();
  const hash = await hashPassword(password, passwordSalt);
  try {
    await db.execute('INSERT INTO users (username, password_hash, password_salt, encryption_salt) VALUES (?, ?, ?, ?)',
      [username, hash, passwordSalt, encryptionSalt]);
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Username is not available.' });
    throw error;
  }
  res.status(201).json({ ok: true });
});

app.post('/api/login', limitAuthentication, async (req, res) => {
  const { username, password } = req.body || {};
  if (!validCredentials(username, password)) return res.status(401).json({ error: 'Incorrect username or password.' });
  const [users] = await db.execute('SELECT * FROM users WHERE username = ?', [username]);
  const user = users[0];
  const valid = await verifyPassword(password, user?.password_salt || '00000000000000000000000000000000',
    user?.password_hash || '0'.repeat(64));
  if (!user || !valid) return res.status(401).json({ error: 'Incorrect username or password.' });
  const key = await deriveKey(password, user.encryption_salt);
  const session = createSession(req, res, { userId: user.id, username: user.username, key });
  res.json({ username: user.username, csrf: session.csrf });
});

app.post('/api/logout', requireLogin, logout);

app.use('/api/entries', requireLogin);

function validateEntry(req, res, next) {
  const { website, username, password } = req.body || {};
  if (typeof website !== 'string' || !website.trim() || website.length > 100
    || typeof username !== 'string' || !username.trim() || username.length > 100
    || typeof password !== 'string' || !password || password.length > 256) {
    return res.status(400).json({ error: 'Enter a website, username and password within the field limits.' });
  }
  req.entryData = Buffer.from(JSON.stringify({ website: website.trim(), username: username.trim(), password }));
  next();
}

function validId(req, res, next) {
  if (!/^[1-9][0-9]{0,9}$/.test(req.params.id)) return res.status(400).json({ error: 'Invalid ID.' });
  next();
}

app.get('/api/entries', async (req, res) => {
  const [rows] = await db.execute('SELECT id, encrypted_data FROM entries WHERE user_id = ? ORDER BY id DESC', [req.session.userId]);
  const entries = rows.map(row => ({ id: row.id,
    ...JSON.parse(decrypt(row.encrypted_data, req.session.key, `entry:${req.session.userId}`).toString('utf8')) }));
  res.json(entries);
});

app.post('/api/entries', validateEntry, async (req, res) => {
  const encrypted = encrypt(req.entryData, req.session.key, `entry:${req.session.userId}`);
  const [result] = await db.execute('INSERT INTO entries (user_id, encrypted_data) VALUES (?, ?)', [req.session.userId, encrypted]);
  res.status(201).json({ id: result.insertId });
});

app.put('/api/entries/:id', validId, validateEntry, async (req, res) => {
  const encrypted = encrypt(req.entryData, req.session.key, `entry:${req.session.userId}`);
  const [result] = await db.execute('UPDATE entries SET encrypted_data = ? WHERE id = ? AND user_id = ?',
    [encrypted, req.params.id, req.session.userId]);
  if (!result.affectedRows) return res.status(404).json({ error: 'Entry not found.' });
  res.json({ ok: true });
});

app.delete('/api/entries/:id', validId, async (req, res) => {
  const [result] = await db.execute('DELETE FROM entries WHERE id = ? AND user_id = ?', [req.params.id, req.session.userId]);
  if (!result.affectedRows) return res.status(404).json({ error: 'Entry not found.' });
  res.json({ ok: true });
});

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 1024 * 1024, files: 1, fields: 0, parts: 1 } });
app.use('/api/files', requireLogin);

app.get('/api/files', async (req, res) => {
  const [rows] = await db.execute('SELECT id, encrypted_name FROM files WHERE user_id = ? ORDER BY id DESC', [req.session.userId]);
  res.json(rows.map(row => ({ id: row.id,
    name: decrypt(row.encrypted_name, req.session.key, `filename:${req.session.userId}`).toString('utf8') })));
});

app.post('/api/files', upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Choose a file, maximum 1 MiB.' });
  const name = req.file.originalname.split(/[\\/]/).pop().replace(/[\x00-\x1f\x7f]/g, '').slice(0, 200) || 'download.bin';
  const encryptedName = encrypt(Buffer.from(name), req.session.key, `filename:${req.session.userId}`);
  const encryptedData = encrypt(req.file.buffer, req.session.key, `file:${req.session.userId}`);
  const [result] = await db.execute('INSERT INTO files (user_id, encrypted_name, encrypted_data) VALUES (?, ?, ?)',
    [req.session.userId, encryptedName, encryptedData]);
  res.status(201).json({ id: result.insertId });
});

app.get('/api/files/:id', validId, async (req, res) => {
  const [rows] = await db.execute('SELECT encrypted_name, encrypted_data FROM files WHERE id = ? AND user_id = ?',
    [req.params.id, req.session.userId]);
  if (!rows.length) return res.status(404).json({ error: 'File not found.' });
  const name = decrypt(rows[0].encrypted_name, req.session.key, `filename:${req.session.userId}`).toString('utf8');
  const data = decrypt(rows[0].encrypted_data, req.session.key, `file:${req.session.userId}`);
  res.attachment(name).type('application/octet-stream').send(data);
});

app.delete('/api/files/:id', validId, async (req, res) => {
  const [result] = await db.execute('DELETE FROM files WHERE id = ? AND user_id = ?', [req.params.id, req.session.userId]);
  if (!result.affectedRows) return res.status(404).json({ error: 'File not found.' });
  res.json({ ok: true });
});

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));

app.use((error, req, res, next) => {
  console.error(error.code || error.name || 'Request failed');
  if (error instanceof multer.MulterError) return res.status(400).json({ error: 'Upload one file, maximum 1 MiB.' });
  if (error.type === 'entity.too.large') return res.status(413).json({ error: 'Request is too large.' });
  if (error.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON.' });
  res.status(500).json({ error: 'Request failed. Please try again.' });
});
