import { randomBytes } from 'node:crypto';

export const sessions = new Map();
export const sessionLifetime = 30 * 60 * 1000;
const cookieName = '__Host-session';

function setCookie(res, id, seconds) {
  res.setHeader('Set-Cookie', `${cookieName}=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${seconds}`);
}

export function destroySession(id) {
  const session = sessions.get(id);
  if (session?.key) session.key.fill(0);
  sessions.delete(id);
}

export function createSession(req, res, user = {}) {
  if (req.sessionId) destroySession(req.sessionId);
  const id = randomBytes(32).toString('hex');
  const session = { ...user, csrf: randomBytes(32).toString('hex'), expires: Date.now() + sessionLifetime };
  sessions.set(id, session);
  req.sessionId = id;
  req.session = session;
  setCookie(res, id, sessionLifetime / 1000);
  return session;
}

export function sessionMiddleware(req, res, next) {
  const match = (req.headers.cookie || '').match(/(?:^|;\s*)__Host-session=([a-f0-9]{64})(?:;|$)/);
  const id = match?.[1];
  const session = sessions.get(id);
  if (session && session.expires <= Date.now()) {
    destroySession(id);
    setCookie(res, '', 0);
  } else if (session) {
    session.expires = Date.now() + sessionLifetime;
    req.sessionId = id;
    req.session = session;
    setCookie(res, id, sessionLifetime / 1000);
  }
  next();
}

export function requireLogin(req, res, next) {
  if (!req.session?.userId) return res.status(401).json({ error: 'Please log in.' });
  next();
}

export function requireCsrf(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (!req.session || req.get('X-CSRF-Token') !== req.session.csrf) {
    return res.status(403).json({ error: 'Invalid request. Refresh the page.' });
  }
  next();
}

export function logout(req, res) {
  destroySession(req.sessionId);
  setCookie(res, '', 0);
  res.json({ ok: true });
}

const cleanup = setInterval(() => {
  for (const [id, session] of sessions) {
    if (session.expires <= Date.now()) destroySession(id);
  }
}, 60000);
cleanup.unref();
