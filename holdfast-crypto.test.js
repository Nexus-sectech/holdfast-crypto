/**
 * holdfast-crypto.test.js
 *
 * Test suite for the Holdfast cryptographic boundary module.
 * Runs with Node.js 20+ built-in test runner:
 *
 *   node --test holdfast-crypto.test.js
 *
 * No external dependencies.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateSalt, deriveKey, encrypt, decrypt } from './holdfast-crypto.js';

const PASSPHRASE  = 'correct horse battery staple';
const PLAINTEXT   = JSON.stringify({ title: 'Test vault', entries: [{ body: 'secret' }] });

// ── (e) Salt and IV sizes ─────────────────────────────────────────────────────

test('generateSalt returns exactly 16 bytes', () => {
  const salt = generateSalt();
  assert.ok(salt instanceof Uint8Array, 'should be a Uint8Array');
  assert.strictEqual(salt.byteLength, 16, 'salt must be 16 bytes (128-bit)');
});

test('encrypted blob embeds a 12-byte IV as the first 12 bytes', async () => {
  const salt = generateSalt();
  const key  = await deriveKey(PASSPHRASE, salt);
  const blob = await encrypt(PLAINTEXT, key);

  // Decode and verify first 12 bytes exist and are non-zero (overwhelmingly likely)
  const bytes = Uint8Array.from(atob(blob), c => c.charCodeAt(0));
  assert.ok(bytes.byteLength > 12, 'blob must be longer than 12 bytes');

  // IV is the first 12 bytes — verify the blob is at minimum IV + 16-byte tag
  assert.ok(
    bytes.byteLength >= 12 + 16,
    'blob must contain at least IV (12) + GCM tag (16) bytes'
  );
});

// ── (a) IV uniqueness ─────────────────────────────────────────────────────────

test('encrypting the same plaintext twice produces different ciphertext', async () => {
  const salt  = generateSalt();
  const key   = await deriveKey(PASSPHRASE, salt);
  const blob1 = await encrypt(PLAINTEXT, key);
  const blob2 = await encrypt(PLAINTEXT, key);

  assert.notStrictEqual(blob1, blob2, 'ciphertext must differ due to unique IV per call');

  // Verify the IVs specifically differ
  const iv1 = atob(blob1).slice(0, 12);
  const iv2 = atob(blob2).slice(0, 12);
  assert.notStrictEqual(iv1, iv2, 'IVs must be different across calls');
});

// ── (b) Roundtrip ─────────────────────────────────────────────────────────────

test('decrypt(encrypt(plaintext)) === plaintext', async () => {
  const salt      = generateSalt();
  const key       = await deriveKey(PASSPHRASE, salt);
  const blob      = await encrypt(PLAINTEXT, key);
  const recovered = await decrypt(blob, key);

  assert.strictEqual(recovered, PLAINTEXT, 'decrypted output must match original plaintext exactly');
});

test('roundtrip preserves Unicode characters', async () => {
  const unicode = 'Dear Ìsọ̀lá, Ваша информация 安全 🔒';
  const salt    = generateSalt();
  const key     = await deriveKey(PASSPHRASE, salt);
  const blob    = await encrypt(unicode, key);
  const result  = await decrypt(blob, key);

  assert.strictEqual(result, unicode, 'Unicode roundtrip must be lossless');
});

test('roundtrip works with an empty string', async () => {
  const salt   = generateSalt();
  const key    = await deriveKey(PASSPHRASE, salt);
  const blob   = await encrypt('', key);
  const result = await decrypt(blob, key);

  assert.strictEqual(result, '', 'empty string roundtrip must work');
});

// ── (c) Tampered ciphertext causes GCM tag failure ────────────────────────────

test('modifying one byte of ciphertext causes GCM tag verification failure', async () => {
  const salt  = generateSalt();
  const key   = await deriveKey(PASSPHRASE, salt);
  const blob  = await encrypt(PLAINTEXT, key);

  // Decode, flip one bit in the ciphertext body (byte 12, past the IV)
  const bytes = Uint8Array.from(atob(blob), c => c.charCodeAt(0));
  bytes[12] ^= 0x01;

  // Re-encode
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  const tampered = btoa(binary);

  await assert.rejects(
    () => decrypt(tampered, key),
    'decrypting tampered ciphertext must throw (GCM authentication failure)'
  );
});

test('modifying one byte of the GCM tag causes verification failure', async () => {
  const salt  = generateSalt();
  const key   = await deriveKey(PASSPHRASE, salt);
  const blob  = await encrypt(PLAINTEXT, key);

  // Flip the last byte (within the GCM tag)
  const bytes = Uint8Array.from(atob(blob), c => c.charCodeAt(0));
  bytes[bytes.length - 1] ^= 0xFF;

  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  const tampered = btoa(binary);

  await assert.rejects(
    () => decrypt(tampered, key),
    'decrypting blob with corrupted GCM tag must throw'
  );
});

// ── (d) Wrong passphrase fails to decrypt ─────────────────────────────────────

test('wrong passphrase fails to decrypt', async () => {
  const salt    = generateSalt();
  const keyGood = await deriveKey(PASSPHRASE, salt);
  const keyBad  = await deriveKey('wrong passphrase', salt);
  const blob    = await encrypt(PLAINTEXT, keyGood);

  await assert.rejects(
    () => decrypt(blob, keyBad),
    'decrypting with a key from a different passphrase must throw'
  );
});

test('correct passphrase but different salt fails to decrypt', async () => {
  const salt1 = generateSalt();
  const salt2 = generateSalt();
  const key1  = await deriveKey(PASSPHRASE, salt1);
  const key2  = await deriveKey(PASSPHRASE, salt2);
  const blob  = await encrypt(PLAINTEXT, key1);

  await assert.rejects(
    () => decrypt(blob, key2),
    'decrypting with a key derived from a different salt must throw'
  );
});

// ── Determinism of key derivation ────────────────────────────────────────────

test('same passphrase and salt always produce the same decryption result', async () => {
  const salt  = generateSalt();
  const key1  = await deriveKey(PASSPHRASE, salt);
  const blob  = await encrypt(PLAINTEXT, key1);

  // Re-derive independently
  const key2   = await deriveKey(PASSPHRASE, salt);
  const result = await decrypt(blob, key2);

  assert.strictEqual(result, PLAINTEXT, 'key derivation must be deterministic for same passphrase+salt');
});
