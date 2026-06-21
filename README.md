# EncryptMe

Browser-only file encryption. Encrypt and decrypt files with
**XChaCha20-Poly1305** + **Argon2id** / **X25519**, entirely on your device — no
upload, no server, no account. The deployed site makes **zero network requests**
at runtime.

A clean-room reimplementation (Astro + TypeScript) inspired by the now-unmaintained
[**hat.sh**](https://github.com/sh-dv/hat.sh) project (MIT). Not a fork.

## Features

- **Password mode** — symmetric encryption, password → Argon2id → key.
- **Public-key mode** — encrypt to a recipient's X25519 public key; only their
  secret key decrypts it.
- **Keypair generator** — create and export X25519 keypairs.
- **Password generator** — CSPRNG-based, with a strength meter.
- **Streaming, large-file capable** — on Chromium/Edge, files stream straight to
  disk via the File System Access API (multi-GB files, no tab OOM). Firefox/Safari
  fall back to an in-memory download capped at 1 GB.
- Authenticated chunks with truncation protection; tampering is rejected.

## Crypto design (short version)

| Concern        | Primitive                                            |
| -------------- | ---------------------------------------------------- |
| Bulk encryption| XChaCha20-Poly1305 (`crypto_secretstream`), 64 KiB chunks |
| Password → key | Argon2id (`crypto_pwhash`, moderate profile)         |
| Key exchange   | X25519 (`crypto_kx`), ephemeral sender keypair       |
| Randomness     | `crypto.getRandomValues` / `randombytes_buf`         |

The only crypto dependency is `libsodium-wrappers-sumo`. The crypto core lives in
[`src/lib/crypto/`](src/lib/crypto/) and is framework-agnostic and unit-tested in
isolation. Full wire format: [FILE_FORMAT.md](FILE_FORMAT.md).

## Threat model

Keys and passwords never leave your device; nothing is uploaded; **a lost
password or secret key means the data is unrecoverable.** Full model and
responsible-disclosure note: [SECURITY.md](SECURITY.md).

## Develop

```bash
npm install
npm run dev          # local dev server
npm test             # vitest: crypto roundtrip / tamper / truncation
npm run test:e2e     # playwright: in-browser encrypt→decrypt happy path
npm run build        # static build into dist/
npm run preview      # serve the built site
```

## Deploy (GitHub Pages)

`astro.config.mjs` sets `site` and `base` for a project page. By default:

```
site: https://sshlainatwired.github.io
base: /encryptme/
```

Override per environment with `SITE_URL` / `BASE_PATH` env vars (e.g. if your
repo or username differs). Pushing to `main` builds and deploys via
[`.github/workflows/deploy.yml`](.github/workflows/deploy.yml) — enable
**Settings → Pages → Source: GitHub Actions** once.

No COOP/COEP headers are needed: the standard libsodium API does not require
`SharedArrayBuffer` / cross-origin isolation.

## Credits

Inspired by [hat.sh](https://github.com/sh-dv/hat.sh) by sh-dv (MIT). Built with
[Astro](https://astro.build), [Tailwind CSS](https://tailwindcss.com), and
[libsodium](https://doc.libsodium.org/). Licensed under [MIT](LICENSE).
