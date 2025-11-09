// public/messenger.mjs

'use strict';

import {
  bufferToString,
  genRandomSalt,
  generateEG,
  computeDH,
  verifyWithECDSA,
  HMACtoAESKey,
  HMACtoHMACKey,
  HKDF,
  encryptWithGCM,
  decryptWithGCM,
  cryptoKeyToJSON,
  govEncryptionDataStr
} from './lib.mjs';

const MSG_KEY_KDF_STR = 'message-key';
const CHAIN_KEY_KDF_STR = 'chain-key';
const HKDF_INFO_STR = 'double-ratchet-hkdf';

class MessengerClient {
  constructor(certAuthorityPublicKey, govPublicKey) {
    this.govPublicKey = govPublicKey;
    this.caPublicKey = certAuthorityPublicKey;
    this.EGKeyPair = {};
    this.certs = {};
    this.conns = {};
  }

  async generateCertificate(username) {
    const keyPair = await generateEG(); 
    this.EGKeyPair = keyPair; 
    
    const pubKeyJwk = await cryptoKeyToJSON(keyPair.pub);

    const certificate = {
      username: username,
      pubKey: pubKeyJwk 
    };
    return certificate; 
  }

  async receiveCertificate(certificate, signature) {
    const pubKeyCrypto = await window.crypto.subtle.importKey(
      'jwk',
      certificate.pubKey, 
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      [] 
    );

    const certificateWithCryptoKey = {
      username: certificate.username,
      pubKey: pubKeyCrypto
    };

    const certString = JSON.stringify(certificate); 
    const isValid = await verifyWithECDSA(this.caPublicKey, certString, signature);
    
    if (!isValid) {
      throw new Error('Certificate verification failed! Invalid signature.');
    }

    this.certs[certificate.username] = certificateWithCryptoKey; 
  }

  // Alice's init: Creates a sending chain
  async _initSessionAlice(name) {
    const bob_cert = this.certs[name]; 
    const RK = await computeDH(this.EGKeyPair.sec, bob_cert.pubKey);
    const alice_ratchet_keypair = await generateEG();
    const DH_out = await computeDH(alice_ratchet_keypair.sec, bob_cert.pubKey);
    const [new_RK, CKs] = await HKDF(RK, DH_out, HKDF_INFO_STR);
    this.conns[name] = {
      RK: new_RK, CKs: CKs, CKr: null,
      DHs: alice_ratchet_keypair, DHr: bob_cert.pubKey,
      Ns: 0, Nr: 0, PNs_to_send: 0, skippedMessageKeys: {}
    };
    return this.conns[name];
  }

  // Bob's init: Creates a receiving chain
  async _initSessionBob(name, header) {
    const alice_cert = this.certs[name];
    const RK = await computeDH(this.EGKeyPair.sec, alice_cert.pubKey);
    const DH_out = await computeDH(this.EGKeyPair.sec, header.dh_pub); 
    const [new_RK, CKr] = await HKDF(RK, DH_out, HKDF_INFO_STR);
    
    // Get existing state IF it exists (e.g., if Bob already sent a message)
    const conn = this.conns[name] || {};
    
    this.conns[name] = {
      ...conn, 
      RK: new_RK, 
      CKr: CKr, 
      DHr: header.dh_pub, 
      Nr: 0,
      skippedMessageKeys: conn.skippedMessageKeys || {} 
    };
    return this.conns[name];
  }

  async sendMessage(name, plaintext) {
    let conn = this.conns[name];
    if (!conn) {
      conn = await this._initSessionAlice(name);
    }
    
    // --- THIS IS THE FIX ---
    // If our CKs is null, it means we've *only received*
    // and this is our *first send*. We must perform a DH ratchet
    // to establish a new sending chain.
    if (conn.CKs === null) {
      const ratchet_keypair = await generateEG(); // Our new ratchet key
      const DH_out = await computeDH(ratchet_keypair.sec, conn.DHr); // Use recipient's current key
      const [new_RK, CKs] = await HKDF(conn.RK, DH_out, HKDF_INFO_STR);
      conn.RK = new_RK;
      conn.CKs = CKs;
      conn.DHs = ratchet_keypair;
      conn.PNs_to_send = conn.Ns; // Store old Ns (which is 0, but good practice)
      conn.Ns = 0; // Reset send counter
    }
    // --- END FIX ---

    const Cks = conn.CKs; // This is now guaranteed to be a CryptoKey
    
    if (!(Cks instanceof CryptoKey)) {
        throw new Error("Internal state error: Sending Chain Key is not a CryptoKey.");
    }
    
    const MK_key = await HMACtoAESKey(Cks, MSG_KEY_KDF_STR);
    const next_CKs = await HMACtoHMACKey(Cks, CHAIN_KEY_KDF_STR);
    conn.CKs = next_CKs; // Store the new CryptoKey
    const message_num = conn.Ns;
    conn.Ns += 1;

    const receiverIV_Uint8Array = genRandomSalt();
    const header = {};
    header.receiverIV_array = Array.from(receiverIV_Uint8Array);
    header.dh_pub_jwk = await cryptoKeyToJSON(conn.DHs.pub); 
    header.Ns = message_num;
    if (message_num === 0) {
      if (conn.PNs_to_send !== undefined) {
        header.PNs = conn.PNs_to_send;
        delete conn.PNs_to_send;
      } else {
        header.PNs = 0;
      }
    }
    const headerString = JSON.stringify(header);
    const ciphertext = await encryptWithGCM(MK_key, plaintext, receiverIV_Uint8Array, headerString);
    return [header, ciphertext];
  }

  async _trySkippedMessageKeys(conn, header, ciphertext, headerString, receiverIV_Uint8Array) {
    const dh_pub_json = await cryptoKeyToJSON(header.dh_pub); 
    const key_id = `${JSON.stringify(dh_pub_json)}:${header.Ns}`;
    const MK_key = conn.skippedMessageKeys[key_id];
    
    if (MK_key) {
      try {
        const plaintext_ab = await decryptWithGCM(MK_key, ciphertext, receiverIV_Uint8Array, headerString);
        delete conn.skippedMessageKeys[key_id];
        return bufferToString(plaintext_ab);
      } catch (e) {
        console.warn('Skipped key decryption failed.', e);
        return null;
      }
    }
    return null;
  }

  async _advanceReceivingChain(conn, until_Ns) {
    if (conn.Nr > until_Ns) return null;
    let CKr = conn.CKr;
    const dh_pub_json_str = JSON.stringify(await cryptoKeyToJSON(conn.DHr));
    while (conn.Nr < until_Ns) {
      if (!CKr) throw new Error('Cannot advance chain with null key');
      const MK_key = await HMACtoAESKey(CKr, MSG_KEY_KDF_STR);
      const next_CKr = await HMACtoHMACKey(CKr, CHAIN_KEY_KDF_STR);
      const key_id = `${dh_pub_json_str}:${conn.Nr}`;
      conn.skippedMessageKeys[key_id] = MK_key;
      CKr = next_CKr; // <-- THIS WAS THE BUG IN THE LOOP (fixed in a previous version, but critical)
      conn.Nr += 1;
    }
    if (!CKr) throw new Error('Cannot derive message key with null key');
    const MK_key = await HMACtoAESKey(CKr, MSG_KEY_KDF_STR);
    const next_CKr = await HMACtoHMACKey(CKr, CHAIN_KEY_KDF_STR);
    conn.CKr = next_CKr;
    conn.Nr += 1;
    return MK_key;
  }

  async _storeSkippedKeys(conn, chainKey, dhPubKeyJwkStr, startNr, endNr) {
    let CKr = chainKey;
    for (let i = startNr; i < endNr; i++) {
      if (!CKr) throw new Error('Cannot store skipped keys with null chain key');
      const MK_key = await HMACtoAESKey(CKr, MSG_KEY_KDF_STR);
      const next_CKr = await HMACtoHMACKey(CKr, CHAIN_KEY_KDF_STR);
      const key_id = `${dhPubKeyJwkStr}:${i}`;
      conn.skippedMessageKeys[key_id] = MK_key;
      CKr = next_CKr;
    }
  }

  async receiveMessage(name, [header, ciphertext]) {
    const headerString = JSON.stringify(header); 
    const receiverIV_Uint8Array = new Uint8Array(header.receiverIV_array);

    try {
      header.dh_pub = await window.crypto.subtle.importKey(
        'jwk',
        header.dh_pub_jwk, 
        { name: 'ECDH', namedCurve: 'P-384' },
        true,
        []
      );
      delete header.dh_pub_jwk; 
    } catch (e) {
      throw new Error('Failed to import sender public key from header. ' + e.message);
    }
    
    let conn = this.conns[name];
    const isFirstTimeReceiver = conn && conn.CKr === null;
    
    if (isFirstTimeReceiver) {
      console.log("Receiver initializing session (was sender-only)...");
      conn = await this._initSessionBob(name, header);
    }

    if (conn && !isFirstTimeReceiver) {
      const plaintext = await this._trySkippedMessageKeys(conn, header, ciphertext, headerString, receiverIV_Uint8Array);
      if (plaintext) {
        return plaintext;
      }
    }

    if (!conn) {
      conn = await this._initSessionBob(name, header);
    }
    
    const header_dh_pub_json = await cryptoKeyToJSON(header.dh_pub);
    const stored_dh_pub_json = await cryptoKeyToJSON(conn.DHr);
    const header_dh_pub_json_str = JSON.stringify(header_dh_pub_json);
    const stored_dh_pub_json_str = JSON.stringify(stored_dh_pub_json);

    if (header_dh_pub_json_str !== stored_dh_pub_json_str) {
      // This is a "real" DH ratchet step
      if (header.Ns > 0) {
        throw new Error('Received an out-of-order message from a previous chain, but no skipped key was found.');
      }

      if (header.Ns === 0 && header.PNs !== undefined && conn.CKr) {
        await this._storeSkippedKeys(conn, conn.CKr, stored_dh_pub_json_str, conn.Nr, header.PNs);
      }
      const our_priv_key = conn.DHs ? conn.DHs.sec : this.EGKeyPair.sec;
      const DH_out = await computeDH(our_priv_key, header.dh_pub);
      const [new_RK_recv, CKr] = await HKDF(conn.RK, DH_out, HKDF_INFO_STR);
      conn.RK = new_RK_recv;
      conn.CKr = CKr;
      conn.DHr = header.dh_pub;
      conn.Nr = 0;
      
      // We MUST also create our *next* sending key
      const ratchet_keypair = await generateEG();
      const DH_out_send = await computeDH(ratchet_keypair.sec, conn.DHr);
      const [new_RK_send, CKs] = await HKDF(conn.RK, DH_out_send, HKDF_INFO_STR);
      conn.RK = new_RK_send;
      conn.CKs = CKs;
      conn.DHs = ratchet_keypair;
      conn.PNs_to_send = conn.Ns;
      conn.Ns = 0;
    }
    
    if (header.Ns < conn.Nr) {
      throw new Error(`Replayed or already-seen message detected. Ns=${header.Ns}, current Nr=${conn.Nr}`);
    }
    
    const MK_key = await this._advanceReceivingChain(conn, header.Ns);
    if (!MK_key) {
      throw new Error('Message key derivation failed. Message may be from a discarded chain.');
    }
    
    try {
      const plaintext_ab = await decryptWithGCM(MK_key, ciphertext, receiverIV_Uint8Array, headerString);
      return bufferToString(plaintext_ab);
    } catch (e) {
      console.error("----------- DECRYPTION FAILED -----------");
      console.error("Original crypto error:", e);
      console.error("Message Key Used:", MK_key);
      console.error("Header String (AD):", headerString);
      console.error("-----------------------------------------");
      throw new Error('Decryption failed! Message may be tampered with. See console for details.');
    }
  }
}

// EXPORT the class
export { MessengerClient };