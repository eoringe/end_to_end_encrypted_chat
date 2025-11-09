'use strict';

const sqlite3 = require('sqlite3').verbose(); 
const DB_FILE = './chat.db';

const db = new sqlite3.Database(DB_FILE, (err) => {
  if (err) {
    console.error(err.message);
    throw err;
  }
  
  console.log('Connected to the SQLite database.');

  db.serialize(() => {
    // 1. Create the 'users' table
    const createUserTableSql = `
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
      )
    `;
    db.run(createUserTableSql, (err) => {
      if (err) console.error('Error creating users table:', err.message);
      else console.log('Table "users" is ready.');
    });

    // 2. Create the 'certificates' table
    const createCertsTableSql = `
      CREATE TABLE IF NOT EXISTS certificates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        certificate_json TEXT NOT NULL,
        FOREIGN KEY (username) REFERENCES users (username)
      )
    `;
    db.run(createCertsTableSql, (err) => {
      if (err) console.error('Error creating certificates table:', err.message);
      else console.log('Table "certificates" is ready.');
    });

    // --- NEW TABLE ---
    // 3. Create the 'messages' table
    const createMessagesTableSql = `
      CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL,
        recipient TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        header_json TEXT NOT NULL,
        ciphertext_b64 TEXT NOT NULL
      )
    `;
    db.run(createMessagesTableSql, (err) => {
      if (err) console.error('Error creating messages table:', err.message);
      else console.log('Table "messages" is ready.');
    });
  });

  db.close((err) => {
    if (err) return console.error(err.message);
    console.log('Closed the database connection.');
  });
});
