/**
 * @module holdfast-crypto
 *
 * Holdfast Cryptographic Boundary
 * ================================
 * This is the only code in the Holdfast application that touches plaintext
 * vault data. All encryption and decryption happen here, entirely inside the
 * user's browser (or Node.js runtime). The passphrase and derived key never
 * leave this module; only the resulting ciphertext is sent to the server.
 *
 * Algorithm summary
 * -----------------
 *   Key derivation : PBKDF2-SHA-256, 250,000 iterations, 128-bit random salt
 *   Encryption     : AES-256-GCM, fresh 96-bit IV per call
 *   Wire format    : base64( IV[12 bytes] || ciphertext+GCM-tag )
 *
 * Compatibility
 * -------------
 *   Browser : any environment with window.crypto.subtle (all modern browsers)
 *   Node.js : 20+ (globalThis.crypto exposed without import)
 *
 * @version 1.0.0
 * @license MIT
 *
 * Exported functions
 * ------------------
 *   generateSalt()              → Uint8Array (16 bytes)
 *   deriveKey(passphrase, salt) → Promise<CryptoKey>
 *   encrypt(plaintext, key)     → Promise<string>    base64 [IV || ct]
 *   decrypt(blob, key)          → Promise<string>    UTF-8 plaintext
 *   encryptBuffer(buffer, key)  → Promise<ArrayBuffer>  [IV || ct]  (binary blobs)
 *   decryptBuffer(buffer, key)  → Promise<ArrayBuffer>  plaintext   (binary blobs)
 */

if (typeof crypto === 'undefined' || !crypto.subtle) {
  throw new Error(
    'holdfast-crypto requires the WebCrypto API. ' +
    'Use Node.js 20+ or a modern browser.'
  );
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/**
 * Encode a Uint8Array to a Base64 string.
 * Uses 8192-byte chunks to avoid call-stack overflow on large payloads.
 * @param {Uint8Array} bytes
 * @returns {string} Base64-encoded string
 */
function _toBase64(bytes) {
  let binary = '';
  const chunk = 8192;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

/**
 * Decode a Base64 string to a Uint8Array.
 * @param {string} str
 * @returns {Uint8Array}
 */
function _fromBase64(str) {
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Generate a cryptographically random salt for use with {@link deriveKey}.
 *
 * @returns {Uint8Array} 16 random bytes (128-bit salt)
 *
 * @example
 * const salt = generateSalt();
 * // Store salt alongside the encrypted vault; it is not secret.
 */
export function generateSalt() {
  return crypto.getRandomValues(new Uint8Array(16));
}

/**
 * Derive an AES-256-GCM {@link CryptoKey} from a passphrase and salt using
 * PBKDF2-SHA-256.
 *
 * Algorithm parameters:
 *   - PBKDF2, hash: SHA-256, iterations: 250,000
 *   - Output: AES-GCM, key length: 256 bits
 *   - extractable: false (key material cannot be exported from the runtime)
 *
 * @param {string}     passphrase - The user's vault passphrase (UTF-8)
 * @param {Uint8Array} salt       - 16-byte random salt from {@link generateSalt}
 * @returns {Promise<CryptoKey>}  Non-extractable AES-256-GCM key
 *
 * @example
 * const key = await deriveKey('correct horse battery staple', salt);
 */
export async function deriveKey(passphrase, salt) {
  const raw = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 250000, hash: 'SHA-256' },
    raw,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt a UTF-8 plaintext string with AES-256-GCM.
 *
 * A fresh 12-byte (96-bit) IV is generated for every call — even for
 * identical plaintext and key — ensuring ciphertext uniqueness.
 *
 * Wire format: base64( IV[12 bytes] || AES-256-GCM-ciphertext+tag )
 *   - IV          : first 12 bytes of decoded output
 *   - Ciphertext  : bytes 12 … n-16 of decoded output
 *   - GCM auth tag: last 16 bytes of decoded output (appended by WebCrypto)
 *
 * @param {string}    plaintext - UTF-8 string to encrypt
 * @param {CryptoKey} key       - AES-256-GCM key from {@link deriveKey}
 * @returns {Promise<string>}   Base64-encoded [IV || ciphertext+tag]
 *
 * @example
 * const blob = await encrypt(JSON.stringify(vault), key);
 * // blob is safe to store or transmit; it contains no plaintext.
 */
export async function encrypt(plaintext, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(plaintext)
  );
  const combined = new Uint8Array(12 + ct.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ct), 12);
  return _toBase64(combined);
}

/**
 * Decrypt a Base64-encoded [IV || ciphertext+tag] string produced by
 * {@link encrypt}.
 *
 * Throws a {@link DOMException} (`OperationError`) if:
 *   - The GCM authentication tag does not match (tampered ciphertext)
 *   - The key was derived from a different passphrase or salt
 *   - The blob is malformed or truncated
 *
 * @param {string}    blob - Base64-encoded [IV || ciphertext+tag]
 * @param {CryptoKey} key  - AES-256-GCM key from {@link deriveKey}
 * @returns {Promise<string>} UTF-8 plaintext
 *
 * @throws {DOMException} On tag verification failure or wrong key
 *
 * @example
 * const plaintext = await decrypt(blob, key);
 * const vault = JSON.parse(plaintext);
 */
export async function decrypt(blob, key) {
  const combined = _fromBase64(blob);
  const iv = combined.slice(0, 12);
  const ct = combined.slice(12);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new TextDecoder().decode(pt);
}

/**
 * Encrypt a binary buffer (ArrayBuffer) with AES-256-GCM.
 * Used for video messages and file attachments — binary data that is not
 * UTF-8 text. Generates a fresh 12-byte IV per call.
 *
 * Wire format: ArrayBuffer( IV[12 bytes] || AES-256-GCM-ciphertext+tag )
 *
 * @param {ArrayBuffer} buffer - Raw binary data to encrypt
 * @param {CryptoKey}   key    - AES-256-GCM key from {@link deriveKey}
 * @returns {Promise<ArrayBuffer>} [IV || ciphertext+tag] as ArrayBuffer
 *
 * @example
 * const encrypted = await encryptBuffer(videoBlob.arrayBuffer(), key);
 */
export async function encryptBuffer(buffer, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, buffer);
  const combined = new Uint8Array(12 + ct.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ct), 12);
  return combined.buffer;
}

/**
 * Decrypt a binary [IV || ciphertext+tag] ArrayBuffer produced by
 * {@link encryptBuffer}.
 *
 * Throws a {@link DOMException} (`OperationError`) on tag verification
 * failure or wrong key — same guarantees as {@link decrypt}.
 *
 * @param {ArrayBuffer} buffer - [IV || ciphertext+tag] from {@link encryptBuffer}
 * @param {CryptoKey}   key    - AES-256-GCM key from {@link deriveKey}
 * @returns {Promise<ArrayBuffer>} Decrypted binary data
 *
 * @throws {DOMException} On tag verification failure or wrong key
 *
 * @example
 * const decrypted = await decryptBuffer(encryptedBuffer, key);
 * const blob = new Blob([decrypted], { type: 'video/webm' });
 */
export async function decryptBuffer(buffer, key) {
  const combined = new Uint8Array(buffer);
  const iv = combined.slice(0, 12);
  const ct = combined.slice(12);
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
}
