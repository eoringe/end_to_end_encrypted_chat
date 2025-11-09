// public/client.js (FIXED - No Historical Message Loading)

import { MessengerClient } from './messenger.mjs';

// --- Global State ---
let messenger;
let socket;
let myUsername = '';
let recipientUsername = ''; 

// --- DOM Elements ---
const loginScreen = document.getElementById('login-screen');
const userListScreen = document.getElementById('user-list-screen'); 
const chatScreen = document.getElementById('chat-screen');

const loginButton = document.getElementById('login-button');
const registerButton = document.getElementById('register-button');
const logoutButton = document.getElementById('logout-button');
const sendButton = document.getElementById('send-button');

const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const textInput = document.getElementById('text-input');
const messagesDiv = document.getElementById('messages');
const authError = document.getElementById('auth-error');
const chatStatus = document.getElementById('chat-status');

// --- WebSocket Connection ---
socket = io();

// === 1. Event Listeners ===

registerButton.addEventListener('click', async () => {
  const user = usernameInput.value;
  const pass = passwordInput.value;
  if (!user || !pass) {
    authError.textContent = 'Please enter username and password.';
    return;
  }
  
  try {
    await apiRegister(user, pass);
    await handleLogin(user, pass);
  } catch (err) {
    authError.textContent = `Registration failed: ${err.message}`;
    console.error("Registration failed:", err);
  }
});

loginButton.addEventListener('click', async () => {
  const user = usernameInput.value;
  const pass = passwordInput.value;
  if (!user || !pass) {
    authError.textContent = 'Please enter username and password.';
    return;
  }

  try {
    await handleLogin(user, pass);
  } catch (err) {
    authError.textContent = `Login failed: ${err.message}`;
    console.error("Login failed:", err);
  }
});

logoutButton.addEventListener('click', () => {
  localStorage.removeItem('chat_username');
  window.location.reload(); 
});

sendButton.addEventListener('click', async () => {
  const plaintext = textInput.value;
  if (!plaintext || !messenger || !recipientUsername) {
    return;
  }

  try {
    chatStatus.textContent = '';
    const [header, ciphertext] = await messenger.sendMessage(recipientUsername, plaintext);
    const ciphertextBase64 = arrayBufferToBase64(ciphertext);
    
    socket.emit('private_message', {
      toUsername: recipientUsername,
      encryptedData: [header, ciphertextBase64]
    });

    addMessageToUI('Me', plaintext);
    textInput.value = '';
  } catch (err) {
    chatStatus.textContent = `Error sending: ${err.message}`;
    console.error("Error sending:", err);
  }
});

// === 2. WebSocket Listeners ===

socket.on('new_message', async ({ from, data }) => {
  if (from === recipientUsername) {
    try {
      chatStatus.textContent = '';
      const [header, ciphertextBase64] = data;
      const ciphertext = base64ToArrayBuffer(ciphertextBase64);

      const plaintext = await messenger.receiveMessage(from, [header, ciphertext]);
      addMessageToUI(from, plaintext);
    } catch (err) {
      chatStatus.textContent = `Error receiving: ${err.message}`;
      console.error("----------- ERROR RECEIVING MESSAGE -----------");
      console.error("Full error object:", err);
      console.error("-----------------------------------------------");
    }
  } else {
    console.warn(`%cNew message from ${from} (not in active chat)`, "color: blue;");
  }
});

// === 3. Initialization Functions ===

function checkForActiveSession() {
  // Temporarily disabled for testing - remove this comment and uncomment below to re-enable
  // const savedUser = localStorage.getItem('chat_username');
  // if (savedUser) {
  //   console.log(`Found saved session for ${savedUser}. Initializing...`);
  //   initializeCryptoAndUserList(savedUser, false);
  // }
}

async function handleLogin(username, password) {
  await initializeCryptoAndUserList(username, true, password);
}

async function initializeCryptoAndUserList(username, doLogin, password) {
  try {
    if (doLogin) {
      await apiLogin(username, password);
    }
    
    localStorage.setItem('chat_username', username);
    myUsername = username;
    
    socket.emit('store_username', myUsername);

    const caPublicKey = await apiGetCaPublicKey();
    messenger = new MessengerClient(caPublicKey, null); 

    const certificate = await messenger.generateCertificate(myUsername);
    try {
      await apiUploadCertificate(myUsername, JSON.stringify(certificate));
      console.log('Certificate uploaded successfully.');
    } catch (err) {
      console.error('Failed to upload certificate:', err.message);
    }
    
    console.log('Client initialized. Fetching user list...');
    loginScreen.style.display = 'none';
    userListScreen.style.display = 'block';
    document.getElementById('welcome-username').textContent = myUsername;

    await populateUserList();
  
  } catch (err) {
    authError.textContent = `Login/Init failed: ${err.message}`;
    console.error("Login/Init failed:", err);
    localStorage.removeItem('chat_username'); 
  }
}

async function populateUserList() {
  const userListDiv = document.getElementById('user-list');
  userListDiv.innerHTML = ''; 
  
  const users = await apiGetUsers();
  
  for (const user of users) {
    if (user === myUsername) {
      continue;
    }
    const userItem = document.createElement('div');
    userItem.className = 'user-item';
    userItem.textContent = user;
    userItem.addEventListener('click', () => {
      startChatWith(user);
    });
    userListDiv.appendChild(userItem);
  }
}

async function startChatWith(username) {
  recipientUsername = username;
  console.log(`Starting chat with ${recipientUsername}...`);
  
  document.getElementById('my-username').textContent = myUsername;
  document.getElementById('recipient-username').textContent = recipientUsername;
  
  messagesDiv.innerHTML = '';
  chatStatus.textContent = `Initializing secure session with ${recipientUsername}...`;

  try {
    // IMPORTANT: Do NOT reset messenger - reuse the existing one
    // This ensures we keep using the same keypair that matches our uploaded certificate
    
    // Fetch the recipient's latest certificate
    const { certificate: recipientCert, signature: sigBase64 } = await apiGetCertificate(recipientUsername);
    const signature = base64ToArrayBuffer(sigBase64);
    
    // Add or update the recipient's certificate
    await messenger.receiveCertificate(recipientCert, signature);

    console.log('E2E chat session initialized successfully.');
    
    // Display notice about historical messages
    messagesDiv.innerHTML = '<p style="color: #999; font-style: italic; padding: 10px; background: #f9f9f9; border-radius: 5px; margin: 10px 0;">🔒 New secure session started. Previous messages cannot be decrypted due to forward secrecy.</p>';
    
    chatStatus.textContent = ''; 
    userListScreen.style.display = 'none';
    chatScreen.style.display = 'block';
    
  } catch (err) {
    chatStatus.textContent = `Error starting chat: ${err.message}`;
    console.error('Failed to start chat:', err);
  }
}

// === 4. UI Helper Functions ===
function addMessageToUI(sender, message, isHistory = false) {
  const p = document.createElement('p');
  p.innerHTML = `<b>${sender}:</b> ${message}`;
  if (isHistory) {
    p.style.color = '#777'; 
  }
  messagesDiv.appendChild(p);
  
  if (!isHistory) {
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
  }
}

// === 5. API Client Functions ===
async function apiRegister(username, password) {
  const response = await fetch('/api/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  if (!response.ok) {
    const err = await response.json();
    throw new Error(err.error);
  }
  return await response.json();
}

async function apiLogin(username, password) {
  const response = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  if (!response.ok) {
    const err = await response.json();
    throw new Error(err.error);
  }
  return await response.json();
}

async function apiGetCaPublicKey() {
  const response = await fetch('/api/ca-public-key');
  if (!response.ok) throw new Error('Could not get CA public key');
  const jwk = await response.json();
  return await window.crypto.subtle.importKey(
    'jwk', jwk,
    { name: 'ECDSA', namedCurve: 'P-384' },
    true, ['verify']
  );
}

async function apiUploadCertificate(username, certificate_json) {
  const response = await fetch('/api/upload-certificate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, certificate_json })
  });
  if (!response.ok) {
    // If certificate already exists, delete and re-upload
    if (response.status === 409) {
      console.log('Certificate exists, replacing with new one...');
      await fetch('/api/delete-certificate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
      });
      // Retry upload
      const retryResponse = await fetch('/api/upload-certificate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, certificate_json })
      });
      if (!retryResponse.ok) {
        const err = await retryResponse.json();
        throw new Error(err.error);
      }
      return await retryResponse.json();
    }
    const err = await response.json();
    throw new Error(err.error);
  }
  return await response.json();
}

async function apiGetCertificate(username) {
  const response = await fetch(`/api/get-certificate/${username}`);
  if (!response.ok) {
    const err = await response.json();
    throw new Error(err.error);
  }
  return await response.json();
}

async function apiGetUsers() {
  const response = await fetch('/api/users');
  if (!response.ok) {
    const err = await response.json();
    throw new Error(err.error);
  }
  return await response.json();
}

// === 6. Utility Helpers ===
function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binaryString = window.atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

// --- Start the app ---
checkForActiveSession();