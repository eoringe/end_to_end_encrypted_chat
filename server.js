'use strict';

const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3');
const bcrypt = require('bcrypt');
const { generateECDSA, signWithECDSA, cryptoKeyToJSON } = require('./lib.js');

const { createServer } = require('http'); 
const { Server } = require('socket.io'); 

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, { /* options */ });

const PORT = 3000;
const DB_FILE = './chat.db';
const SALT_ROUNDS = 10;

let caKeyPair = {};
let caPublicKeyJwk = {};

(async () => {
  try {
    caKeyPair = await generateECDSA();
    caPublicKeyJwk = await cryptoKeyToJSON(caKeyPair.pub);
    console.log('Certificate Authority (CA) keys generated.');
  } catch (err) {
    console.error('Failed to generate CA keys:', err);
    process.exit(1);
  }
})();

const db = new sqlite3.Database(DB_FILE, (err) => {
  if (err) console.error('Error connecting to database:', err.message);
  else console.log('Server connected to the database.');
});

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- API Endpoints ---
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required.' });
    }
    const password_hash = await bcrypt.hash(password, SALT_ROUNDS);
    const sql = 'INSERT INTO users (username, password_hash) VALUES (?, ?)';
    db.run(sql, [username, password_hash], function (err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return res.status(409).json({ error: 'Username already taken.' });
        }
        return res.status(500).json({ error: err.message });
      }
      console.log(`User ${username} registered successfully.`);
      res.status(201).json({ message: 'User registered successfully!' });
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error during registration.' });
  }
});
app.post('/api/login', (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required.' });
    }
    const sql = 'SELECT * FROM users WHERE username = ?';
    db.get(sql, [username], async (err, user) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!user) return res.status(404).json({ error: 'User not found.' });
      const isMatch = await bcrypt.compare(password, user.password_hash);
      if (isMatch) {
        console.log(`User ${username} logged in successfully.`);
        res.status(200).json({ message: 'Login successful!' });
      } else {
        res.status(401).json({ error: 'Invalid credentials.' });
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error during login.' });
  }
});
app.get('/api/ca-public-key', (req, res) => {
  if (!caPublicKeyJwk) {
    return res.status(500).json({ error: 'CA key not ready.' });
  }
  res.status(200).json(caPublicKeyJwk);
});
app.post('/api/upload-certificate', (req, res) => {
  const { username, certificate_json } = req.body;
  if (!username || !certificate_json) {
    return res.status(400).json({ error: 'Username and certificate_json are required.' });
  }
  let certObj;
  try {
    certObj = JSON.parse(certificate_json);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid certificate JSON.' });
  }
  if (certObj.username !== username) {
     return res.status(403).json({ error: 'Certificate username does not match posting user.' });
  }
  // Use "REPLACE INTO" to avoid 409 error, just update the cert
  const sql = 'REPLACE INTO certificates (username, certificate_json) VALUES (?, ?)';
  db.run(sql, [username, certificate_json], function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    console.log(`Certificate uploaded/replaced for ${username}`);
    res.status(201).json({ message: 'Certificate uploaded successfully.' });
  });
});
app.get('/api/get-certificate/:username', (req, res) => {
  const { username } = req.params;
  const sql = 'SELECT certificate_json FROM certificates WHERE username = ?';
  db.get(sql, [username], async (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: 'Certificate not found for user.' });
    try {
      const certificate_string = row.certificate_json;
      const signature = await signWithECDSA(caKeyPair.sec, certificate_string);
      const signatureBase64 = Buffer.from(signature).toString('base64');
      res.status(200).json({
        certificate: JSON.parse(certificate_string),
        signature: signatureBase64
      });
    } catch (e) {
      console.error('Error signing certificate:', e);
      res.status(500).json({ error: 'Server error during certificate signing.' });
    }
  });
});
app.get('/api/users', (req, res) => {
  const sql = 'SELECT username FROM users';
  db.all(sql, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    const usernames = rows.map(row => row.username);
    res.status(200).json(usernames);
  });
});

// --- NEW ENDPOINT: Get Message History ---
app.get('/api/messages/:user1/:user2', (req, res) => {
  const { user1, user2 } = req.params;
  
  const sql = `
    SELECT sender, recipient, header_json, ciphertext_b64, timestamp
    FROM messages
    WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?)
    ORDER BY timestamp ASC
  `;
  
  db.all(sql, [user1, user2, user2, user1], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.status(200).json(rows);
  });
});


// --- WebSocket Logic (Updated) ---
const userSockets = new Map(); 
const socketUsers = new Map(); 

io.on('connection', (socket) => {
  console.log(`A user connected: ${socket.id}`);

  socket.on('store_username', (username) => {
    console.log(`User ${username} is associated with socket ${socket.id}`);
    userSockets.set(username, socket.id);
    socketUsers.set(socket.id, username);
  });

  socket.on('private_message', ({ toUsername, encryptedData }) => {
    const fromUsername = socketUsers.get(socket.id);
    console.log(`Forwarding message from ${fromUsername} to ${toUsername}`);
    
    // 1. Store the encrypted message in the database
    const [header, ciphertextBase64] = encryptedData;
    const header_json = JSON.stringify(header);
    
    const sql = `
      INSERT INTO messages (sender, recipient, header_json, ciphertext_b64)
      VALUES (?, ?, ?, ?)
    `;
    db.run(sql, [fromUsername, toUsername, header_json, ciphertextBase64], (err) => {
      if (err) {
        console.error('Failed to store message in DB:', err);
      }
    });

    // 2. Forward the message to the recipient if they are online
    const recipientSocketId = userSockets.get(toUsername);
    if (recipientSocketId) {
      io.to(recipientSocketId).emit('new_message', {
        from: fromUsername,
        data: encryptedData 
      });
    } else {
      console.log(`User ${toUsername} is not connected.`);
    }
  });

  socket.on('disconnect', () => {
    console.log(`User disconnected: ${socket.id}`);
    const username = socketUsers.get(socket.id);
    if (username) {
      userSockets.delete(username);
      socketUsers.delete(socket.id);
    }
  });
});

httpServer.listen(PORT, () => {
  console.log(`Server (with WebSockets) is running at http://localhost:${PORT}`);
});