# Web-Based Secure Password Manager

Web Application Security, Checkpoint 2.

## Run with Docker

Install Docker Desktop with Docker Compose. On Windows, use Linux containers and start Docker Desktop first. No separate Node.js, MySQL or OpenSSL installation is needed for this option.

Extract the archive, open a terminal inside `password-manager`, and run:

```sh
docker compose up --build
```

The first run downloads the images and dependencies. Wait until the app prints `Open https://localhost:3000`.

Open **https://localhost:3000**, accept the local self-signed certificate warning, and register an account. Use `localhost`, because the allowed request origin is `https://localhost:3000`. This development certificate encrypts traffic but is not trusted by the browser automatically.

The tables and local TLS certificate are created automatically. Use a username with 3–50 letters, numbers or underscores and a master password with 12–128 characters. Register first, then log in with the same password.

Stop with Ctrl+C or `docker compose down`. Start again with `docker compose up`. Database data and the development certificate remain in Docker volumes. Sessions are held in memory, so an app restart requires a new login.

The default database password is for local development only. The app is published on the local machine only, and the database has no published port. To use a different database password, copy `.env.example` to `.env` and change `DB_PASSWORD` **before the first start**. Changing that value later does not change an existing MySQL user's password.

## Run without Docker

Requirements: Node.js 24, MySQL 8.0 or 8.4, and OpenSSL available in PATH.

Create a database and application user using a MySQL administrator account:

```sql
CREATE DATABASE password_manager CHARACTER SET utf8mb4;
CREATE USER 'password_manager'@'localhost' IDENTIFIED BY 'local-development-password';
GRANT ALL PRIVILEGES ON password_manager.* TO 'password_manager'@'localhost';
```

Copy `.env.example` to `.env`. Set the connection details if your local MySQL uses different values. Run:

```sh
npm ci
npm start
```

Open **https://localhost:3000** and accept the local certificate warning. `npm start` generates the certificate through OpenSSL before starting the HTTPS server. If the certificate expires, stop the app, remove the two files inside `certs`, and start again.

## Features

- Register, log in and log out with a username and master password.
- Add, show, hide, edit and delete saved passwords.
- Upload a file of up to 1 MiB, list it, download the decrypted original, or delete it.
- Keep each user's entries and files separate with server-side ownership checks.

## Security design

The backend is Node.js with Express. The frontend is plain HTML, CSS and JavaScript. MySQL stores accounts, encrypted password entries and encrypted files. SQL values use placeholders through `mysql2`.

The master password is also the login password. Node.js `crypto.scrypt` hashes the login password and derives the vault key. These two operations use different random 16-byte salts. The settings are `N=32768`, `r=8`, `p=3`, with a 32-byte output. Password hash verification uses `timingSafeEqual`. The database stores the login hash and both salts; it does not store the master password or vault key.

AES-256-GCM encrypts the complete password entry, each filename and each file's contents. Every encryption uses a fresh random 12-byte IV and a 16-byte authentication tag. The stored binary layout is `IV | tag | ciphertext`. Additional authenticated data binds encryption to the user and data type. A modified ciphertext fails decryption.

Sessions use random 32-byte IDs in a `__Host-session` cookie with `HttpOnly`, `Secure`, `SameSite=Strict` and `Path=/`. The ID changes on login. The server checks a 30-minute inactivity timeout and refreshes it on API requests. Logout removes the server session and clears the cookie. The key is held in that server session and its Buffer is overwritten on session removal. Expired sessions are also removed by a one-minute cleanup timer. This is not a guarantee of complete memory erasure in a managed runtime.

State-changing requests need a session CSRF token and the expected Origin. The server validates inputs, applies a basic limit of 10 authentication requests per IP per 15 minutes, and checks `user_id` on each data operation. The frontend uses `textContent` and input values to display user data. A Content Security Policy blocks inline scripts.

HTTPS is provided by Node.js directly. The app does not start an HTTP listener.

## Checks

For a native setup, with MySQL running:

```sh
node scripts/create-cert.js
npm test
```

For the Docker setup, with the app already running:

```sh
docker compose exec app npm test
```

Tests need the same database permissions as the app. They create randomly named test accounts and remove only those accounts afterwards. They check encryption and tamper detection, login, cookie flags, session ID rotation, CSRF, input validation, password CRUD, binary file round trips, file size limits, cross-user access, logout, idle expiry and rate limiting. Expiry is checked by moving the test session's expiry timestamp into the past.

For a manual demonstration, see `DEMO_RU.md`. The short submission progress note is `PROGRESS.md`.

## Repository

The archive contains a local Git repository with incremental implementation commits. Extract all files, including `.git`. Check the history with:

```sh
git log --oneline
```

The commits were created during this implementation session, without backdating. They do not represent work across previous weeks. To publish in a new, empty course repository:

```sh
git remote add origin YOUR_REPOSITORY_URL
git push -u origin main
```

Replace `YOUR_REPOSITORY_URL` with your actual empty repository URL. If the course repository already has commits, integrate these files into that repository and preserve its history; do not force-push over it.

## Checkpoint limits

This is a small, single-server development project. It has no password recovery, master-password change, MFA, sharing, browser extension, password generator, or production deployment. Losing the master password means losing access to the encrypted data.

Encryption and decryption happen on the server. This is not a zero-knowledge password manager: the server handles the master password during login and the decrypted vault data during requests. Sessions and the basic rate limiter are in memory and are reset on restart. The development database password and self-signed certificate are not production configuration. Use test passwords and test files for the demonstration.

The first-checkpoint documents did not specify an algorithm or a file format. This implementation chooses scrypt and AES-256-GCM. The file flow is included to satisfy Checkpoint 2's explicit server-side file encryption/decryption requirement.

## References

- [Node.js crypto](https://nodejs.org/api/crypto.html)
- [Express API](https://expressjs.com/en/5x/api.html)
- [MySQL Docker image](https://hub.docker.com/_/mysql)
