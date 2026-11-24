/*
 * Safe Share crypto, format v1 (must stay in sync with cli/safeshare_cli.py)
 *
 *  key          = 32 random bytes, transported only in the URL fragment (base64url)
 *  aes_key      = key                                         (no passphrase)
 *               = PBKDF2-HMAC-SHA256(key || utf8(pass), salt16, 600000, 32)  (passphrase)
 *  ciphertext   = AES-256-GCM(aes_key, iv12, plaintext, aad="safeshare-v1")
 *  reveal_token = base64url(SHA-256("safeshare-v1:reveal:" || key))
 *  plaintext    = utf8(JSON) {type:"text", text} | {type:"file", name, mime, data(base64)}
 */
(function (global) {
  "use strict";

  const subtle = global.crypto.subtle;
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const AAD = enc.encode("safeshare-v1");
  const REVEAL_LABEL = enc.encode("safeshare-v1:reveal:");
  const PBKDF2_ITERATIONS = 600000;

  function concat(...parts) {
    const len = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(len);
    let off = 0;
    for (const p of parts) { out.set(p, off); off += p.length; }
    return out;
  }

  function bytesToB64(bytes) {
    let bin = "";
    const CHUNK = 0x8000;
    for (let i = 0; i < bytes.length; i += CHUNK) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
    }
    return btoa(bin);
  }

  function b64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  const b64url = (bytes) => bytesToB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const fromB64url = (s) => b64ToBytes(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));

  const random = (n) => global.crypto.getRandomValues(new Uint8Array(n));

  async function deriveAesKey(key, passphrase, salt) {
    if (!passphrase) {
      return subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
    }
    const material = await subtle.importKey("raw", concat(key, enc.encode(passphrase)), "PBKDF2", false, ["deriveKey"]);
    return subtle.deriveKey(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function revealToken(key) {
    const digest = await subtle.digest("SHA-256", concat(REVEAL_LABEL, key));
    return b64url(new Uint8Array(digest));
  }

  /** Encrypts a payload object. Returns {request, keyB64} – request goes to the API, key into the URL fragment. */
  async function encryptPayload(payload, passphrase) {
    const key = random(32);
    const iv = random(12);
    const salt = passphrase ? random(16) : null;
    const aesKey = await deriveAesKey(key, passphrase, salt);
    const plaintext = enc.encode(JSON.stringify(payload));
    const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv, additionalData: AAD }, aesKey, plaintext));
    return {
      keyB64: b64url(key),
      request: {
        v: 1,
        ciphertext: b64url(ct),
        iv: b64url(iv),
        salt: salt ? b64url(salt) : null,
        reveal_token: await revealToken(key),
      },
    };
  }

  /** Decrypts an API reveal response. Throws on wrong key/passphrase. */
  async function decryptPayload(resp, keyB64, passphrase) {
    const key = fromB64url(keyB64);
    const salt = resp.salt ? fromB64url(resp.salt) : null;
    if (salt && !passphrase) throw new Error("passphrase_required");
    const aesKey = await deriveAesKey(key, salt ? passphrase : null, salt);
    const pt = await subtle.decrypt(
      { name: "AES-GCM", iv: fromB64url(resp.iv), additionalData: AAD },
      aesKey,
      fromB64url(resp.ciphertext)
    );
    return JSON.parse(dec.decode(pt));
  }

  global.SafeShareCrypto = {
    encryptPayload,
    decryptPayload,
    revealToken: (keyB64) => revealToken(fromB64url(keyB64)),
    bytesToB64,
    b64ToBytes,
    isValidKey: (s) => /^[A-Za-z0-9_-]{43}$/.test(s || ""),
  };
})(typeof window !== "undefined" ? window : globalThis);
