# Changelog

All changes to the Holdfast encryption boundary are recorded here before they ship to production. This is an append-only log.

## [1.0.0] - 2026-05-11

### Initial release

- `deriveKey()` — PBKDF2-SHA256, 250,000 iterations, 128-bit salt → AES-256-GCM key
- `encrypt()` — AES-256-GCM with fresh 96-bit IV per call
- `decrypt()` — AES-256-GCM decryption with GCM tag verification
- `generateSalt()` — 16-byte cryptographically random salt via `crypto.getRandomValues`
- Zero external dependencies; WebCrypto API only
- Test suite covering IV uniqueness, roundtrip integrity, GCM tag verification, wrong-passphrase rejection, and salt/IV length validation
