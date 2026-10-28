import { test } from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { readFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { app } from '../app.js';
import { db, initializeDatabase } from '../db.js';
import { sessions, sessionLifetime, destroySession } from '../sessions.js';

test('checkpoint 2 with HTTPS and a real MySQL database', async t => {
  await initializeDatabase();
  const key = await readFile(new URL('../certs/localhost-key.pem', import.meta.url));
  const cert = await readFile(new URL('../certs/localhost-cert.pem', import.meta.url));
  const server = https.createServer({ key, cert }, app);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const suffix = randomBytes(5).toString('hex');
  const usernameA = `test_a_${suffix}`;
  const usernameB = `test_b_${suffix}`;
  const password = 'test master password 123';
  let userId;

  function client() {
    return {
      cookie: '', csrf: '',
      async send(path, method = 'GET', data, extraHeaders = {}) {
        const headers = { Origin: process.env.APP_ORIGIN || 'https://localhost:3000', Cookie: this.cookie };
        if (method !== 'GET') headers['X-CSRF-Token'] = this.csrf;
        let body;
        if (Buffer.isBuffer(data)) body = data;
        else if (data !== undefined) {
          body = Buffer.from(JSON.stringify(data));
          headers['Content-Type'] = 'application/json';
        }
        if (body) headers['Content-Length'] = body.length;
        Object.assign(headers, extraHeaders);
        const result = await new Promise((resolve, reject) => {
          const req = https.request({ hostname: '127.0.0.1', port, path, method, headers, rejectUnauthorized: false }, res => {
            const chunks = [];
            res.on('data', chunk => chunks.push(chunk));
            res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
          });
          req.on('error', reject);
          req.end(body);
        });
        if (result.headers['set-cookie']) this.cookie = result.headers['set-cookie'][0].split(';')[0];
        if (result.headers['content-type']?.includes('application/json')) result.json = JSON.parse(result.body);
        if (result.json?.csrf) this.csrf = result.json.csrf;
        return result;
      }
    };
  }

  function multipart(data, field = 'file') {
    const boundary = 'test-boundary-12345';
    return {
      body: Buffer.concat([Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${field}"; filename="example.bin"\r\nContent-Type: application/octet-stream\r\n\r\n`),
        data, Buffer.from(`\r\n--${boundary}--\r\n`)]),
      headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` }
    };
  }

  const a = client();
  const b = client();
  let entryId;
  let fileId;
  const secret = 'saved-secret-123';
  const originalFile = Buffer.concat([Buffer.from('private test file'), Buffer.from([0, 128, 255])]);

  try {
    await t.test('authentication, hash storage, cookie flags and session rotation', async () => {
      assert.equal((await a.send('/api/entries')).status, 401);
      const initial = await a.send('/api/session');
      const anonymousCookie = a.cookie;
      const cookieHeader = initial.headers['set-cookie'][0];
      for (const flag of ['HttpOnly', 'Secure', 'SameSite=Strict', 'Path=/', 'Max-Age=1800']) assert.ok(cookieHeader.includes(flag));
      assert.equal((await a.send('/api/register', 'POST', { username: usernameA, password })).status, 201);
      assert.equal((await a.send('/api/login', 'POST', { username: usernameA, password: 'incorrect password' })).status, 401);
      assert.equal((await a.send('/api/login', 'POST', { username: usernameA, password })).status, 200);
      assert.notEqual(a.cookie, anonymousCookie);
      assert.equal(sessions.has(anonymousCookie.split('=')[1]), false);
      const [rows] = await db.execute('SELECT * FROM users WHERE username = ?', [usernameA]);
      userId = rows[0].id;
      assert.notEqual(rows[0].password_hash, password);
      assert.match(rows[0].password_hash, /^[a-f0-9]{64}$/);
      assert.notEqual(rows[0].password_salt, rows[0].encryption_salt);
      assert.equal(JSON.stringify(rows).includes(password), false);
    });

    await t.test('CSRF, origin, input validation and parameterized login', async () => {
      assert.equal((await a.send('/api/entries', 'POST', {}, { 'X-CSRF-Token': 'wrong' })).status, 403);
      assert.equal((await a.send('/api/entries', 'POST', {}, { Origin: 'https://attacker.example' })).status, 403);
      assert.equal((await a.send('/api/entries', 'POST', {})).status, 400);
      assert.equal((await a.send('/api/login', 'POST', { username: "' OR 1=1 --", password })).status, 401);
      const response = await a.send('/api/entries');
      assert.equal(response.headers['cache-control'], 'no-store');
      assert.ok(response.headers['content-security-policy'].includes("script-src 'self'"));
    });

    await t.test('encrypted password CRUD and persistent decryption after a new login', async () => {
      const created = await a.send('/api/entries', 'POST', { website: '<img src=x onerror=alert(1)>', username: 'demo', password: secret });
      assert.equal(created.status, 201);
      entryId = created.json.id;
      const [stored] = await db.execute('SELECT encrypted_data FROM entries WHERE id = ?', [entryId]);
      assert.equal(stored[0].encrypted_data.includes(Buffer.from(secret)), false);
      assert.equal(stored[0].encrypted_data.includes(Buffer.from('demo')), false);
      const list = await a.send('/api/entries');
      assert.equal(list.json[0].password, secret);
      assert.equal(list.json[0].website, '<img src=x onerror=alert(1)>');
      assert.equal((await a.send(`/api/entries/${entryId}`, 'PUT', { website: 'Updated service', username: 'demo', password: secret })).status, 200);
      await a.send('/api/logout', 'POST');
      await a.send('/api/session');
      await a.send('/api/login', 'POST', { username: usernameA, password });
      assert.equal((await a.send('/api/entries')).json[0].password, secret);
    });

    await t.test('file upload encrypts bytes and filename, download restores exact bytes', async () => {
      const upload = multipart(originalFile);
      const created = await a.send('/api/files', 'POST', upload.body, upload.headers);
      assert.equal(created.status, 201);
      fileId = created.json.id;
      const [rows] = await db.execute('SELECT encrypted_name, encrypted_data FROM files WHERE id = ?', [fileId]);
      assert.equal(rows[0].encrypted_name.includes(Buffer.from('example.bin')), false);
      assert.equal(rows[0].encrypted_data.includes(originalFile), false);
      assert.equal((await a.send('/api/files')).json[0].name, 'example.bin');
      const download = await a.send(`/api/files/${fileId}`);
      assert.equal(download.status, 200);
      assert.deepEqual(download.body, originalFile);
      assert.ok(download.headers['content-disposition'].startsWith('attachment;'));
      assert.equal(download.headers['content-type'], 'application/octet-stream');
      const tooLarge = multipart(Buffer.alloc(1024 * 1024 + 1));
      assert.equal((await a.send('/api/files', 'POST', tooLarge.body, tooLarge.headers)).status, 400);
      const unexpected = multipart(Buffer.from('test'), 'unexpected');
      assert.equal((await a.send('/api/files', 'POST', unexpected.body, unexpected.headers)).status, 400);
    });

    await t.test('a second user cannot read, modify or delete another user data', async () => {
      await b.send('/api/session');
      assert.equal((await b.send('/api/register', 'POST', { username: usernameB, password })).status, 201);
      assert.equal((await b.send('/api/login', 'POST', { username: usernameB, password })).status, 200);
      assert.deepEqual((await b.send('/api/entries')).json, []);
      assert.deepEqual((await b.send('/api/files')).json, []);
      assert.equal((await b.send(`/api/entries/${entryId}`, 'PUT', { website: 'test', username: 'test', password: 'test' })).status, 404);
      assert.equal((await b.send(`/api/entries/${entryId}`, 'DELETE')).status, 404);
      assert.equal((await b.send(`/api/files/${fileId}`)).status, 404);
      assert.equal((await b.send(`/api/files/${fileId}`, 'DELETE')).status, 404);
    });

    await t.test('tampered ciphertext fails without returning plaintext', async () => {
      const [rows] = await db.execute('SELECT encrypted_data FROM files WHERE id = ?', [fileId]);
      const damaged = Buffer.from(rows[0].encrypted_data);
      damaged[damaged.length - 1] ^= 1;
      await db.execute('UPDATE files SET encrypted_data = ? WHERE id = ?', [damaged, fileId]);
      const response = await a.send(`/api/files/${fileId}`);
      assert.equal(response.status, 500);
      assert.equal(response.body.includes(originalFile), false);
    });

    await t.test('delete, idle extension, logout revocation and server-side expiry', async () => {
      assert.equal((await a.send(`/api/entries/${entryId}`, 'DELETE')).status, 200);
      assert.equal((await a.send(`/api/files/${fileId}`, 'DELETE')).status, 200);
      const activeId = a.cookie.split('=')[1];
      sessions.get(activeId).expires = Date.now() + 1000;
      await a.send('/api/entries');
      assert.ok(sessions.get(activeId).expires >= Date.now() + sessionLifetime - 1000);
      const oldCookie = a.cookie;
      const oldKey = sessions.get(activeId).key;
      const logoutResponse = await a.send('/api/logout', 'POST');
      assert.ok(logoutResponse.headers['set-cookie'][0].includes('Max-Age=0'));
      assert.equal(sessions.has(activeId), false);
      assert.deepEqual(oldKey, Buffer.alloc(32));
      a.cookie = oldCookie;
      assert.equal((await a.send('/api/entries')).status, 401);
      const bId = b.cookie.split('=')[1];
      const bKey = sessions.get(bId).key;
      sessions.get(bId).expires = Date.now() - 1;
      assert.equal((await b.send('/api/entries')).status, 401);
      assert.equal(sessions.has(bId), false);
      assert.deepEqual(bKey, Buffer.alloc(32));
    });

    await t.test('authentication requests are rate limited', async () => {
      const c = client();
      await c.send('/api/session');
      let last;
      for (let i = 0; i < 11; i += 1) last = await c.send('/api/login', 'POST', { username: 'unknown', password: 'wrong' });
      assert.equal(last.status, 429);
    });
  } finally {
    await db.execute('DELETE FROM users WHERE username IN (?, ?)', [usernameA, usernameB]);
    for (const id of sessions.keys()) destroySession(id);
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    await db.end();
  }
});
