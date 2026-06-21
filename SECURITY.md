# Security

## Threat model

EncryptMe is a **client-side, serverless** file encryption tool. All
cryptography runs in your browser; no file, password, or key is ever sent over
the network. The deployed artifact is a static site with a strict
Content-Security-Policy and makes **zero runtime network requests** (the
libsodium WASM is inlined into the JS bundle, so there is nothing to fetch).

### What it protects

- **Confidentiality and integrity of files at rest.** Encrypted output uses
  XChaCha20-Poly1305 (AEAD) via libsodium's `crypto_secretstream`. Each chunk is
  authenticated; any modification, reordering, truncation, or extension of the
  ciphertext is detected and the output is rejected.
- **Password-based protection** via Argon2id (`crypto_pwhash`, moderate profile,
  ~256 MiB), salted per file.
- **Recipient-targeted encryption** via X25519 (`crypto_kx`) with a fresh
  ephemeral sender keypair per file.

### What it does NOT protect against

- **A compromised endpoint.** Malware, a malicious browser extension, or a
  keylogger on your machine can read your plaintext, password, or keys. This
  tool cannot defend against a compromised device.
- **A compromised delivery channel for the app itself.** You are trusting the
  static site you loaded. Verify you are on the expected origin; prefer the
  offline/local copy for high-sensitivity use. (Self-host or run the build
  locally if you want to remove the host from your trust base.)
- **Weak passwords.** Argon2id raises the cost of guessing, but a guessable
  password is still guessable. Use the built-in generator.
- **Metadata.** The output reveals approximate file size (ciphertext length) and
  the mode byte (password vs. public-key). The original filename is **not**
  stored in the file; it is only suggested by the browser on decrypt.
- **Lost secrets.** There is no recovery. A lost password or secret key means the
  data is permanently unrecoverable. That is the point.

## Cryptographic choices

- Single crypto dependency: `libsodium-wrappers-sumo` (the sumo build, required
  for Argon2id). No hand-rolled crypto.
- Randomness only from `crypto.getRandomValues` / `sodium.randombytes_buf`.
- Final-chunk `TAG_FINAL` enforced on decrypt (truncation protection).
- The file header is bound as AEAD additional data to the first chunk.
- Key material is zeroed (`sodium.memzero`) after use where the API exposes it.

See [FILE_FORMAT.md](FILE_FORMAT.md) for the exact wire format.

## Reporting a vulnerability

Please report suspected vulnerabilities privately via a GitHub security advisory
("Report a vulnerability" on the repository's Security tab) rather than a public
issue. We aim to acknowledge reports within a few days. There is no bounty
program; credit is given to reporters who wish it.
