# Secure Password Manager

Web Application Security project, Checkpoint 2.

The app uses HTML, CSS, JavaScript, Node.js and MySQL.

## Run

Install and start Docker Desktop. On Windows, use Linux containers.
Open a terminal in the project folder and run:

```sh
docker compose up --build
```

Wait for `Open https://localhost:3000`, then open https://localhost:3000.
Accept the certificate warning. The certificate is self-signed for local development.
The database tables and certificate are created automatically.

Register an account, then log in. The username must contain 3–50 letters, numbers or underscores. The master password must be 12–128 characters long.

To stop the app:

```sh
docker compose down
```

Start it again with `docker compose up`. Saved data stays in the database. Log in again after an app restart.

## Features

- Register, log in and log out.
- Add, view, edit and delete saved passwords.
- Upload files up to 1 MiB and download the decrypted originals.

## Security

The master password is used for login and to derive the encryption key. Login passwords are hashed with scrypt. Saved entries and files are encrypted on the server with AES-256-GCM before being stored in MySQL.

Sessions use HttpOnly, Secure and SameSite=Strict cookies and expire after 30 minutes of inactivity. The server checks that entries and files belong to the logged-in user. SQL queries use parameters, and changes require a CSRF token.

This is a local development setup. Sessions are stored in memory. There is no master-password recovery, and the default database password is only for local use.

## Tests

With the app running:

```sh
docker compose exec app npm test
```
