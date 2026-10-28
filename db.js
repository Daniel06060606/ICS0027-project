import mysql from 'mysql2/promise';
import { readFile } from 'node:fs/promises';

export const db = mysql.createPool({
  host: process.env.DB_HOST || '127.0.0.1',
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || 'password_manager',
  password: process.env.DB_PASSWORD || 'local-development-password',
  database: process.env.DB_NAME || 'password_manager',
  connectionLimit: 5
});

export async function initializeDatabase() {
  const schema = await readFile(new URL('./schema.sql', import.meta.url), 'utf8');
  for (const statement of schema.split(';').filter(value => value.trim())) {
    await db.query(statement);
  }
}
