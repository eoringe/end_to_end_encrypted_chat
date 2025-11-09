// public/lib.mjs

const { subtle } = window.crypto;

// --- Helper Functions ---
function bufferToString(arr) {
  return new TextDecoder().decode(arr);
}

function genRandomSalt(len = 16) {
  return window.crypto.getRandomValues(new Uint8Array(len));
}

async function cryptoKeyToJSON(cryptoKey) {
  const key = await subtle.exportKey('jwk', cryptoKey);
  return key;
}

// --- Text/Buffer Encoders ---
const enc = new TextEncoder();
const dec = new TextDecoder();

// --- Main Crypto Functions (Browser-Friendly) ---

async function generateEG() {
  const keypair = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, true, ['deriveKey']);
  return { pub: keypair.publicKey, sec: keypair.privateKey };
}

/**
 * --- THIS IS THE FIX ---
 * The output key MUST have 'sign' and 'verify' usages, just like
 * the original lib.js file. This was the root cause of the state
 * corruption.
 */
async function computeDH(myPrivateKey, theirPublicKey) {
  return await subtle.deriveKey(
    { name: 'ECDH', public: theirPublicKey },
    myPrivateKey,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    true,
    ['sign', 'verify'] // THIS WAS THE BUG. IT WAS MISSING 'verify'.
  );
}

async function verifyWithECDSA(publicKey, message, signature) {
  return await subtle.verify({ name: 'ECDSA', hash: { name: 'SHA-384' } }, publicKey, signature, enc.encode(message));
}

async function HMACtoAESKey(key, data, exportToArrayBuffer = false) {
  const hmacBuf = await subtle.sign({ name: 'HMAC' }, key, enc.encode(data));
  const out = await subtle.importKey('raw', hmacBuf, 'AES-GCM', true, ['encrypt', 'decrypt']);
  if (exportToArrayBuffer) {
    return await subtle.exportKey('raw', out);
  }
  return out;
}

async function HMACtoHMACKey(key, data) {
  const hmacBuf = await subtle.sign({ name: 'HMAC' }, key, enc.encode(data));
  return await subtle.importKey(
    'raw',
    hmacBuf,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    true,
    ['sign'] 
  );
}

/**
 * This logic now correctly matches the original lib.js
 */
async function HKDF(inputKey, salt, infoStr) {
  // 1. Use the 'sign' key to create a buffer
  const inputKeyBuf = await subtle.sign({ name: 'HMAC' }, inputKey, enc.encode('0'));
  // 2. Import that buffer as a *new* key with 'deriveKey' permission
  const inputKeyHKDF = await subtle.importKey('raw', inputKeyBuf, 'HKDF', false, ['deriveKey']);
  
  // 3. Use the 'salt' key (which also has 'sign') to create salts
  const salt1 = await subtle.sign({ name: 'HMAC' }, salt, enc.encode('salt1'));
  const salt2 = await subtle.sign({ name: 'HMAC' }, salt, enc.encode('salt2'));

  const infoBuf = enc.encode(infoStr);

  // 4. Use the new inputKeyHKDF (with 'deriveKey') to derive the output keys
  const hkdfOut1 = await subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: salt1, info: infoBuf },
    inputKeyHKDF, 
    { name: 'HMAC', hash: 'SHA-256', length: 256 }, 
    true,
    ['sign'] 
  );

  const hkdfOut2 = await subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: salt2, info: infoBuf },
    inputKeyHKDF, 
    { name: 'HMAC', hash: 'SHA-256', length: 256 }, 
    true,
    ['sign'] 
  );

  return [hkdfOut1, hkdfOut2];
}


async function encryptWithGCM(key, plaintext, iv, authenticatedData = '') {
  return await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(authenticatedData) }, key, enc.encode(plaintext));
}

async function decryptWithGCM(key, ciphertext, iv, authenticatedData = '') {
  return await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(authenticatedData) }, key, ciphertext);
}

async function generateECDSA() {
  const keypair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign', 'verify']);
  return { pub: keypair.publicKey, sec: keypair.privateKey };
}

async function signWithECDSA(privateKey, message) {
  return await subtle.sign({ name: 'ECDSA', hash: { name: 'SHA-384' } }, privateKey, enc.encode(message));
}

export {
  govEncryptionDataStr,
  bufferToString,
  genRandomSalt,
  cryptoKeyToJSON,
  generateEG,
  computeDH,
  verifyWithECDSA,
  HMACtoAESKey,
  HMACtoHMACKey,
  HKDF,
  encryptWithGCM,
  decryptWithGCM,
  generateECDSA,
  signWithECDSA
};

const govEncryptionDataStr = 'AES-GENERATION';