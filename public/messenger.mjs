// public/messenger.mjs - FIXED VERSION (Bob-to-Alice decryption issue resolved)

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
  cryptoKeyToJSON
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
    return { username, pubKey: pubKeyJwk };
  }

  async receiveCertificate(certificate, signature) {
    const pubKeyCrypto = await window.crypto.subtle.importKey(
      'jwk',
      certificate.pubKey,
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      []
    );

    const isValid = await verifyWithECDSA(
      this.caPublicKey,
      JSON.stringify(certificate),
      signature
    );

    if (!isValid) {
      throw new Error('Certificate verification failed! Invalid signature.');
    }

    this.certs[certificate.username] = {
      username: certificate.username,
      pubKey: pubKeyCrypto
    };
  }

  // Alice initiates the conversation
  async _initSessionAlice(name) {
    const bobCert = this.certs[name];
    const RK = await computeDH(this.EGKeyPair.sec, bobCert.pubKey);
    const aliceRatchet = await generateEG();
    const DH_out = await computeDH(aliceRatchet.sec, bobCert.pubKey);
    const [newRK, CKs] = await HKDF(RK, DH_out, HKDF_INFO_STR);

    this.conns[name] = {
      RK: newRK,
      CKs,
      CKr: null,
      DHs: aliceRatchet,
      DHr: bobCert.pubKey,
      Ns: 0,
      Nr: 0,
      PNs_to_send: 0,
      skippedMessageKeys: {}
    };
    return this.conns[name];
  }

  // Bob responds for the first time
  async _initSessionBob(name, header) {
    const aliceCert = this.certs[name];
    const RK = await computeDH(this.EGKeyPair.sec, aliceCert.pubKey);
    const DH_out_recv = await computeDH(this.EGKeyPair.sec, header.dh_pub);
    const [newRK, CKr] = await HKDF(RK, DH_out_recv, HKDF_INFO_STR);

    // Generate Bob’s sending ratchet keypair immediately
    const bobRatchet = await generateEG();
    const DH_out_send = await computeDH(bobRatchet.sec, header.dh_pub);
    const [finalRK, CKs] = await HKDF(newRK, DH_out_send, HKDF_INFO_STR);

    this.conns[name] = {
      RK: finalRK,
      CKr,
      CKs,
      DHs: bobRatchet,
      DHr: header.dh_pub,
      Ns: 0,
      Nr: 0,
      PNs_to_send: 0,
      skippedMessageKeys: {}
    };
    return this.conns[name];
  }

  async sendMessage(name, plaintext) {
    let conn = this.conns[name];
    if (!conn) conn = await this._initSessionAlice(name);

    if (!conn.CKs) {
      const newRatchet = await generateEG();
      const DH_out = await computeDH(newRatchet.sec, conn.DHr);
      const [newRK, CKs] = await HKDF(conn.RK, DH_out, HKDF_INFO_STR);
      conn.RK = newRK;
      conn.CKs = CKs;
      conn.DHs = newRatchet;
      conn.PNs_to_send = conn.Ns;
      conn.Ns = 0;
    }

    const MK = await HMACtoAESKey(conn.CKs, MSG_KEY_KDF_STR);
    conn.CKs = await HMACtoHMACKey(conn.CKs, CHAIN_KEY_KDF_STR);

    const headerForAAD = {
      dh_pub_jwk: await cryptoKeyToJSON(conn.DHs.pub),
      Ns: conn.Ns
    };
    if (conn.Ns === 0 && conn.PNs_to_send !== undefined)
      headerForAAD.PNs = conn.PNs_to_send;

    const receiverIV = genRandomSalt();
    const ciphertext = await encryptWithGCM(
      MK,
      plaintext,
      receiverIV,
      JSON.stringify(headerForAAD)
    );

    conn.Ns += 1;

    return [
      { ...headerForAAD, receiverIV_array: Array.from(receiverIV) },
      ciphertext
    ];
  }

  async receiveMessage(name, [header, ciphertext]) {
    const connExisting = this.conns[name];
    const receiverIV = new Uint8Array(header.receiverIV_array);

    const headerForAAD = {
      dh_pub_jwk: header.dh_pub_jwk,
      Ns: header.Ns
    };
    if (header.PNs !== undefined) headerForAAD.PNs = header.PNs;
    const headerStringForAAD = JSON.stringify(headerForAAD);

    header.dh_pub = await window.crypto.subtle.importKey(
      'jwk',
      header.dh_pub_jwk,
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      []
    );

    let conn = connExisting;

    // If Bob was only a receiver before, initialize his sending chain now
    if (!conn) {
      conn = await this._initSessionBob(name, header);
    }

    // Ratchet step: if sender's DH changed
    const currentDHr = conn.DHr
      ? JSON.stringify(await cryptoKeyToJSON(conn.DHr))
      : null;
    const newDHr = JSON.stringify(await cryptoKeyToJSON(header.dh_pub));

    if (currentDHr !== newDHr) {
      const ourPriv = conn.DHs ? conn.DHs.sec : this.EGKeyPair.sec;
      const DH_out_recv = await computeDH(ourPriv, header.dh_pub);
      const [newRK, CKr] = await HKDF(conn.RK, DH_out_recv, HKDF_INFO_STR);
      conn.RK = newRK;
      conn.CKr = CKr;
      conn.DHr = header.dh_pub;

      // Prepare new sending chain
      const newRatchet = await generateEG();
      const DH_out_send = await computeDH(newRatchet.sec, conn.DHr);
      const [newRK2, CKs] = await HKDF(conn.RK, DH_out_send, HKDF_INFO_STR);
      conn.RK = newRK2;
      conn.CKs = CKs;
      conn.DHs = newRatchet;
      conn.Ns = 0;
    }

    // Derive message key
    let MK = await HMACtoAESKey(conn.CKr, MSG_KEY_KDF_STR);
    conn.CKr = await HMACtoHMACKey(conn.CKr, CHAIN_KEY_KDF_STR);
    conn.Nr += 1;

    try {
      const plaintextBuf = await decryptWithGCM(
        MK,
        ciphertext,
        receiverIV,
        headerStringForAAD
      );
      return bufferToString(plaintextBuf);
    } catch (e) {
      console.error('----------- DECRYPTION FAILED -----------');
      console.error('Original error:', e);
      console.error('Header used for AAD:', headerStringForAAD);
      console.error('-----------------------------------------');
      throw new Error(
        'Decryption failed! Message may be tampered with or keys do not match.'
      );
    }
  }
}

export { MessengerClient };
