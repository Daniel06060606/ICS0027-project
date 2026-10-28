# Checkpoint 2 progress note

The core application is implemented using the stack agreed in Checkpoint 1: plain HTML/CSS/JavaScript, Node.js, MySQL, Node.js crypto and HTTPS.

Users can register, log in, add, view, edit and delete password entries, and log out. A small file flow supports upload, server-side encryption, and download of the decrypted original. Entries, filenames and file contents are stored encrypted in MySQL using AES-256-GCM. The encryption key is derived from the master password with scrypt. Login passwords are stored as scrypt hashes with separate random salts.

Sessions are stored on the server and use HttpOnly, Secure and SameSite=Strict cookies. The session ID changes after login, sessions expire after 30 minutes of inactivity, and logout invalidates the session. Server-side validation, parameterized SQL, ownership checks, CSRF tokens and safe text rendering cover the basic threats identified in Checkpoint 1.

The development application runs over HTTPS with a locally generated self-signed certificate. The repository includes Docker Compose and native run instructions, automated checks, and incremental Git commits made during this implementation session.

Validation: all 11 automated checks passed with Node.js 24.22.1 and a real MySQL 8.0.46 database, including authenticated HTTPS requests and exact binary file recovery. The native HTTPS server also started successfully and served the interface. `npm audit --omit=dev` reported no known dependency vulnerabilities at the time of testing. Docker Compose configuration was parsed and reviewed, but a full Docker build/run was not executed because Docker is unavailable in the build environment. Chrome could not start in that environment, so the manual browser walkthrough in `DEMO_RU.md` still needs to be completed on the submission machine.

The scope remains small. Sessions are in memory; there is no password recovery, master-password change, sharing or production hosting. Further work before the final checkpoint is broader manual security testing and fixing any issues found.
