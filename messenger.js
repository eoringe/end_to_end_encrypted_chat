'use strict'

/** ******* Imports ********/

const {
  /* The following functions are all of the cryptographic
 primatives that you should need for this assignment.
 See lib.js for details on usage. */
  bufferToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib')

/** ******* Constants ********/

const MSG_KEY_KDF_STR = 'message-key'
const CHAIN_KEY_KDF_STR = 'chain-key'
const HKDF_INFO_STR = 'double-ratchet-hkdf'

/** ******* Implementation ********/

class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    this.govPublicKey = govPublicKey
    this.caPublicKey = certAuthorityPublicKey
    this.EGKeyPair = {}
    this.certs = {}
    this.conns = {}
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   */
  async generateCertificate (username) {
    const keyPair = await generateEG()
    this.EGKeyPair = keyPair

    const certificate = {
      username: username,
      pubKey: keyPair.pub
    }
    return certificate
  }

  /**
   * Receive and store another user's certificate.
   */
  async receiveCertificate (certificate, signature) {
    const certString = JSON.stringify(certificate)
    const isValid = await verifyWithECDSA(this.caPublicKey, certString, signature)

    if (!isValid) {
      throw new Error('Certificate verification failed! Invalid signature.')
    }
    this.certs[certificate.username] = certificate
  }

  /**
   * Helper function to initialize a new session as the initiator (Alice).
   */
  async _initSessionAlice (name) {
    const bob_cert = this.certs[name]
    const RK = await computeDH(this.EGKeyPair.sec, bob_cert.pubKey)
    const alice_ratchet_keypair = await generateEG()
    const DH_out = await computeDH(alice_ratchet_keypair.sec, bob_cert.pubKey)
    const [new_RK, CKs] = await HKDF(RK, DH_out, HKDF_INFO_STR)

    this.conns[name] = {
      RK: new_RK,
      CKs: CKs,
      CKr: null,
      DHs: alice_ratchet_keypair,
      DHr: bob_cert.pubKey,
      Ns: 0,
      Nr: 0,
      PNs_to_send: 0, // Initialize
      skippedMessageKeys: {}
    }
    return this.conns[name]
  }

  /**
   * Helper function to initialize a new session as the responder (Bob).
   */
  async _initSessionBob (name, header) {
    const alice_cert = this.certs[name]
    const RK = await computeDH(this.EGKeyPair.sec, alice_cert.pubKey)
    const DH_out = await computeDH(this.EGKeyPair.sec, header.dh_pub)
    const [new_RK, CKr] = await HKDF(RK, DH_out, HKDF_INFO_STR)

    this.conns[name] = {
      RK: new_RK,
      CKs: null,
      CKr: CKr,
      DHs: null,
      DHr: header.dh_pub,
      Ns: 0,
      Nr: 0,
      PNs_to_send: 0, // Initialize
      skippedMessageKeys: {}
    }
    return this.conns[name]
  }

  /**
   * Generate the message to be sent to another user.
   */
  async sendMessage (name, plaintext) {
    let conn = this.conns[name]
    if (!conn) {
      conn = await this._initSessionAlice(name)
    }

    if (conn.CKs === null) {
      // DH ratchet step (as sender, e.g., Bob's first reply)
      const ratchet_keypair = await generateEG()
      const DH_out = await computeDH(ratchet_keypair.sec, conn.DHr)
      const [new_RK, CKs] = await HKDF(conn.RK, DH_out, HKDF_INFO_STR)

      conn.RK = new_RK
      conn.CKs = CKs
      conn.DHs = ratchet_keypair
      
      // ** FIX #1: Store the old Ns before resetting **
      conn.PNs_to_send = conn.Ns // Store old Ns count
      conn.Ns = 0 // Reset
    }

    // --- Symmetric Ratchet (Chain) ---
    const Cks = conn.CKs
    const MK_key = await HMACtoAESKey(Cks, MSG_KEY_KDF_STR)
    const MK_raw = await HMACtoAESKey(Cks, MSG_KEY_KDF_STR, true)
    const next_CKs = await HMACtoHMACKey(Cks, CHAIN_KEY_KDF_STR)

    conn.CKs = next_CKs
    const message_num = conn.Ns
    conn.Ns += 1

    // --- Government Encryption (Hybrid ElGamal) ---
    const vGov_keypair = await generateEG()
    const dh_gov = await computeDH(vGov_keypair.sec, this.govPublicKey)
    const aes_gov = await HMACtoAESKey(dh_gov, govEncryptionDataStr)
    const ivGov = genRandomSalt()
    const cGov = await encryptWithGCM(aes_gov, MK_raw, ivGov)

    // --- Build Header & Encrypt for Receiver ---
    const header = {}
    header.vGov = vGov_keypair.pub
    header.cGov = cGov
    header.ivGov = ivGov
    header.receiverIV = genRandomSalt()
    header.dh_pub = conn.DHs.pub
    header.Ns = message_num
    
    // ** FIX #2: Send PNs on the first message of a new chain **
    if (message_num === 0) {
      if (conn.PNs_to_send !== undefined) {
        header.PNs = conn.PNs_to_send
        delete conn.PNs_to_send
      } else {
        header.PNs = 0 // Very first message
      }
    }

    const headerString = JSON.stringify(header)
    const ciphertext = await encryptWithGCM(MK_key, plaintext, header.receiverIV, headerString)

    return [header, ciphertext]
  }

  /**
   * Helper function for Extra Credit.
   * Tries to find a skipped message key and decrypt with it.
   */
  async _trySkippedMessageKeys (conn, header, ciphertext) {
    const dh_pub_json = await cryptoKeyToJSON(header.dh_pub)
    const key_id = `${JSON.stringify(dh_pub_json)}:${header.Ns}`
    const MK_key = conn.skippedMessageKeys[key_id]

    if (MK_key) {
      const headerString = JSON.stringify(header)
      try {
        const plaintext_ab = await decryptWithGCM(MK_key, ciphertext, header.receiverIV, headerString)
        delete conn.skippedMessageKeys[key_id]
        return bufferToString(plaintext_ab)
      } catch (e) {
        throw new Error('Skipped key decryption failed! ' + e.message)
      }
    }
    return null
  }

  /**
   * Helper function for Extra Credit.
   * Advances the receiving chain, storing keys for skipped messages.
   */
  async _advanceReceivingChain (conn, until_Ns) {
    if (conn.Nr > until_Ns) {
      return null // Message from the past, key should have been in skippedKeys
    }

    let CKr = conn.CKr
    const dh_pub_json_str = JSON.stringify(await cryptoKeyToJSON(conn.DHr))

    while (conn.Nr < until_Ns) {
      if (!CKr) throw new Error('Cannot advance chain with null key')
      const MK_key = await HMACtoAESKey(CKr, MSG_KEY_KDF_STR)
      const next_CKr = await HMACtoHMACKey(CKr, CHAIN_KEY_KDF_STR)

      const key_id = `${dh_pub_json_str}:${conn.Nr}`
      conn.skippedMessageKeys[key_id] = MK_key // Store skipped key

      CKr = next_CKr
      conn.Nr += 1
    }

    if (!CKr) throw new Error('Cannot derive message key with null key')
    const MK_key = await HMACtoAESKey(CKr, MSG_KEY_KDF_STR)
    const next_CKr = await HMACtoHMACKey(CKr, CHAIN_KEY_KDF_STR)

    conn.CKr = next_CKr
    conn.Nr += 1

    return MK_key
  }

  /**
   * Helper function for Extra Credit.
   * Advances an old chain just to store its skipped keys.
   */
  async _storeSkippedKeys (conn, chainKey, dhPubKeyJwkStr, startNr, endNr) {
    let CKr = chainKey
    for (let i = startNr; i < endNr; i++) {
      if (!CKr) throw new Error('Cannot store skipped keys with null chain key')
      const MK_key = await HMACtoAESKey(CKr, MSG_KEY_KDF_STR)
      const next_CKr = await HMACtoHMACKey(CKr, CHAIN_KEY_KDF_STR)
      const key_id = `${dhPubKeyJwkStr}:${i}`
      conn.skippedMessageKeys[key_id] = MK_key
      CKr = next_CKr
    }
  }

  /**
   * Decrypt a message received from another user.
   */
  async receiveMessage (name, [header, ciphertext]) {
    let conn = this.conns[name]
    if (conn) {
      const plaintext = await this._trySkippedMessageKeys(conn, header, ciphertext)
      if (plaintext) {
        return plaintext // Successfully decrypted out-of-order message
      }
    }

    if (!conn) {
      conn = await this._initSessionBob(name, header)
    }

    const header_dh_pub_json = await cryptoKeyToJSON(header.dh_pub)
    const stored_dh_pub_json = await cryptoKeyToJSON(conn.DHr)
    const header_dh_pub_json_str = JSON.stringify(header_dh_pub_json)
    const stored_dh_pub_json_str = JSON.stringify(stored_dh_pub_json)

    if (header_dh_pub_json_str !== stored_dh_pub_json_str) {
      // --- DH RATCHET STEP (as receiver) ---
      
      // Store skipped keys from the *previous* receiving chain
      if (header.Ns === 0 && header.PNs !== undefined && conn.CKr) {
         await this._storeSkippedKeys(conn, conn.CKr, stored_dh_pub_json_str, conn.Nr, header.PNs)
      }

      // 1. Update Receiving Chain
      const our_priv_key = conn.DHs ? conn.DHs.sec : this.EGKeyPair.sec
      const DH_out = await computeDH(our_priv_key, header.dh_pub)
      const [new_RK_recv, CKr] = await HKDF(conn.RK, DH_out, HKDF_INFO_STR)

      conn.RK = new_RK_recv
      conn.CKr = CKr
      conn.DHr = header.dh_pub // Store Alice's new ratchet key
      conn.Nr = 0 // Reset receiving message counter

      // 2. Update Sending Chain
      const ratchet_keypair = await generateEG()
      const DH_out_send = await computeDH(ratchet_keypair.sec, conn.DHr)
      const [new_RK_send, CKs] = await HKDF(conn.RK, DH_out_send, HKDF_INFO_STR)

      conn.RK = new_RK_send
      conn.CKs = CKs
      conn.DHs = ratchet_keypair
      conn.PNs_to_send = conn.Ns // Store old Ns count
      conn.Ns = 0 // Reset
    }

    // --- 2. Handle Out-of-Order / Advance Chain ---
    if (header.Ns < conn.Nr) {
      throw new Error(`Replayed or already-seen message detected. Ns=${header.Ns}, current Nr=${conn.Nr}`)
    }

    // --- 3. Symmetric Ratchet (Chain) ---
    const MK_key = await this._advanceReceivingChain(conn, header.Ns)

    if (!MK_key) {
      throw new Error('Message key derivation failed. Message may be from a discarded chain.')
    }

    // --- 4. Decrypt Message ---
    const headerString = JSON.stringify(header)
    try {
      const plaintext_ab = await decryptWithGCM(MK_key, ciphertext, header.receiverIV, headerString)
      return bufferToString(plaintext_ab)
    } catch (e) {
      throw new Error('Decryption failed! Message may be tampered with. ' + e.message)
    }
  }
};

module.exports = {
  MessengerClient
}