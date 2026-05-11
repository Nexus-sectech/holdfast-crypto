# holdfast-crypto

The zero-knowledge encryption module used by [Holdfast](https://holdfast-co.uk), the digital estate vault operated by Nexus-Sec Ltd.

This module is published separately so that anyone can audit, verify, and confirm that the code running in their browser matches what is documented here. It is the **only code in Holdfast that touches plaintext**.

## What this module does

When a Holdfast user creates or edits their vault, this module:

1. Derives an AES-256 encryption key from the user's passphrase using PBKDF2
2. Encrypts all vault contents client-side before anything leaves the browser
3. Decrypts vault contents client-side after download, using the same passphrase

The passphrase never leaves the browser. The derived key never leaves the browser. Holdfast's servers only ever receive, store, and return ciphertext.

## Algorithm parameters

| Parameter | Value |
|---|---|
| Encryption | AES-256-GCM |
| Key derivation | PBKDF2-SHA256 |
| Iterations | 250,000 |
| Salt | 128-bit (16 bytes), randomly generated per vault |
| IV | 96-bit (12 bytes), randomly generated per encryption operation |
| Authentication tag | 128-bit (GCM default) |

These parameters are not configurable by the user. They are constants in the module.

## Why these choices

**AES-256-GCM** provides authenticated encryption: both confidentiality and integrity. If a single byte of ciphertext is modified, decryption fails entirely rather than producing corrupted plaintext.

**PBKDF2 with 250,000 iterations** is FIPS-validated and available natively in the WebCrypto API across all browsers without polyfills or third-party libraries. It puts a meaningful computational cost on offline passphrase guessing. Argon2id is the modern preference (memory-hard, more resistant to GPU/ASIC attacks) and is on the migration roadmap; it would require a WASM implementation and a re-derivation path for existing vaults.

**96-bit random IV per encryption** is mandatory for GCM security. Reusing an IV with the same key is catastrophic (leaks the keystream). This module generates a fresh IV on every call to `encrypt()`.

**No third-party dependencies.** The module calls the WebCrypto API (`crypto.subtle`) directly. This eliminates supply-chain risk on the most sensitive code path in the product.

## Files

```
holdfast-crypto.js        # The encryption module (ES module, zero dependencies)
holdfast-crypto.test.js   # Test suite
sha256sum.txt             # SHA-256 hash of holdfast-crypto.js
CHANGELOG.md              # Append-only record of every change
LICENSE                   # MIT
README.md                 # This file
```

## How to verify

You can confirm that your browser is running the same code published in this repository.

### Method 1: Subresource Integrity (automatic)

On Holdfast vault pages, `holdfast-crypto.js` is loaded with an SRI `integrity` attribute. Your browser automatically refuses to execute the file if its hash does not match the expected value. You can inspect this:

1. Open your browser's developer tools (F12)
2. Go to the **Elements** tab
3. Search for `holdfast-crypto`
4. The `<script>` tag will show an `integrity="sha384-..."` attribute
5. Compare that hash to the one listed under the current release in this repository

### Method 2: Manual hash comparison

1. Open developer tools → **Network** tab
2. Reload the vault page
3. Find `holdfast-crypto.js` in the network requests
4. Right-click → Copy → Copy response (or view the source)
5. Hash it locally:
   ```bash
   # On the file you saved from the browser:
   shasum -a 256 holdfast-crypto.js
   ```
6. Compare the output to `sha256sum.txt` in this repository at the matching release tag

### Method 3: Behavioural verification

You do not need to read the code to test that real encryption is happening:

1. Create a vault entry with any content
2. Save the vault
3. Open developer tools → **Network** tab → find the request that uploads the vault blob
4. The request body contains ciphertext, not your plaintext. Confirm you cannot read your own content in the payload
5. Save the vault again without changing anything. The uploaded blob will differ (fresh IV each time)
6. Modify a single character in the stored ciphertext (via the browser console) and attempt to decrypt. It will fail (GCM tag verification)

Base64 encoding fails all three of these tests. Real AES-256-GCM encryption passes all three.

## Releases

Each release is tagged with a semantic version (`v1.0.0`, `v1.1.0`, etc.) and includes an updated `sha256sum.txt`. The SRI hash on the production site corresponds to a specific tagged release.

All changes to this module are recorded in [CHANGELOG.md](CHANGELOG.md) before they ship to production. This is the "no quiet patches" commitment described in the [Holdfast Diligence Q&A](https://holdfast-co.uk).

## Scope and boundaries

This module contains **only** the encryption boundary:

- `deriveKey()` - passphrase + salt → AES-256-GCM key
- `encrypt()` - plaintext + key → ciphertext + IV + salt
- `decrypt()` - ciphertext + IV + salt + passphrase → plaintext
- `generateSalt()` - cryptographically random 16-byte salt

It does **not** contain:

- API calls, network requests, or server communication
- Authentication logic (Supabase Auth)
- UI code, form handling, or DOM manipulation
- Anything that runs server-side

If you are evaluating Holdfast's zero-knowledge claim, this module is the only file you need to review.

## Operator trust and limitations

Publishing this module improves transparency but does not eliminate the structural limitation of browser-delivered cryptography: the operator (Nexus-Sec Ltd) serves the JavaScript, and could in principle serve a different version to a specific user. This is true of every web application that performs client-side encryption.

The mitigations are:

- **SRI hashes** - the browser itself enforces integrity on each page load
- **This public repository** - the source is auditable by anyone, at any time
- **Legal entity exposure** - Nexus-Sec Ltd is a UK-registered company (No. 17126982) with a named director, registered with the ICO
- **Small surface area** - the module is deliberately minimal, making a malicious change difficult to hide

For users whose threat model requires verified binaries rather than browser-delivered code, Holdfast may not be the right product. We will say so directly rather than overstate what browser-based zero-knowledge can guarantee.

## Licence

MIT. See [LICENSE](LICENSE).

## Operator

Nexus-Sec Ltd · Company No. 17126982 · ICO registered · [holdfast-co.uk](https://holdfast-co.uk)
