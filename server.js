import https from 'node:https';
import { readFile } from 'node:fs/promises';
import { app } from './app.js';
import { initializeDatabase, db } from './db.js';
import { sessions, destroySession } from './sessions.js';

try {
  await initializeDatabase();
  const key = await readFile(new URL('./certs/localhost-key.pem', import.meta.url));
  const cert = await readFile(new URL('./certs/localhost-cert.pem', import.meta.url));
  const port = Number(process.env.PORT || 3000);
  const server = https.createServer({ key, cert, minVersion: 'TLSv1.2' }, app);
  server.listen(port, '0.0.0.0', () => console.log(`Open https://localhost:${port}`));
  async function shutdown() {
    server.close();
    server.closeAllConnections();
    for (const id of sessions.keys()) destroySession(id);
    await db.end();
  }
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
} catch (error) {
  console.error('Startup failed:', error.code || error.message);
  await db.end();
  process.exitCode = 1;
}
