import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeSalt, hashPassword, verifyPassword, deriveKey, encrypt, decrypt } from '../crypto.js';

test('master password hashing and separate encryption keys', async () => {
  const password = 'a long test password';
  const salt = makeSalt();
  const otherSalt = makeSalt();
  assert.notEqual(salt, otherSalt);
  const hash = await hashPassword(password, salt);
  assert.notEqual(hash, password);
  assert.equal(await verifyPassword(password, salt, hash), true);
  assert.equal(await verifyPassword('wrong password', salt, hash), false);
  assert.notEqual((await deriveKey(password, otherSalt)).toString('hex'), hash);
});

test('AES-GCM round trip, random IV and tamper detection', async () => {
  const key = await deriveKey('a long test password', makeSalt());
  const data = Buffer.from([0, 1, 2, 10, 127, 128, 255]);
  const encrypted = encrypt(data, key, 'file:1');
  assert.deepEqual(decrypt(encrypted, key, 'file:1'), data);
  assert.notDeepEqual(encrypt(data, key, 'file:1'), encrypted);
  const damaged = Buffer.from(encrypted);
  damaged[damaged.length - 1] ^= 1;
  assert.throws(() => decrypt(damaged, key, 'file:1'));
  assert.throws(() => decrypt(encrypted, Buffer.alloc(32), 'file:1'));
  assert.throws(() => decrypt(encrypted, key, 'file:2'));
  assert.throws(() => decrypt(encrypted, key, 'entry:1'));
  assert.throws(() => decrypt(Buffer.alloc(12), key, 'file:1'));
});
