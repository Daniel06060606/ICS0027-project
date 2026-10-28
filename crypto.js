import { randomBytes, scrypt, timingSafeEqual, createCipheriv, createDecipheriv } from 'node:crypto';
import { promisify } from 'node:util';

const scryptAsync = promisify(scrypt);

export function makeSalt() {
  return randomBytes(16).toString('hex');
}

export async function deriveKey(password, salt) {
  return scryptAsync(password, salt, 32, { N: 32768, r: 8, p: 3, maxmem: 64 * 1024 * 1024 });
}

export async function hashPassword(password, salt) {
  return (await deriveKey(password, salt)).toString('hex');
}

export async function verifyPassword(password, salt, hash) {
  const actual = await deriveKey(password, salt);
  return timingSafeEqual(actual, Buffer.from(hash, 'hex'));
}

export function encrypt(data, key, context) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(context));
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), encrypted]);
}

export function decrypt(data, key, context) {
  if (data.length < 28) throw new Error('Invalid encrypted data');
  const decipher = createDecipheriv('aes-256-gcm', key, data.subarray(0, 12));
  decipher.setAAD(Buffer.from(context));
  decipher.setAuthTag(data.subarray(12, 28));
  return Buffer.concat([decipher.update(data.subarray(28)), decipher.final()]);
}
