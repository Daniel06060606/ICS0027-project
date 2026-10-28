import { mkdirSync, existsSync, chmodSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

const directory = new URL('../certs/', import.meta.url);
const key = new URL('localhost-key.pem', directory);
const cert = new URL('localhost-cert.pem', directory);
mkdirSync(directory, { recursive: true, mode: 0o700 });
if (!existsSync(key) || !existsSync(cert)) {
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', key.pathname, '-out', cert.pathname, '-days', '365',
    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'], { stdio: 'ignore' });
  chmodSync(key, 0o600);
  console.log('Created a local development TLS certificate.');
}
