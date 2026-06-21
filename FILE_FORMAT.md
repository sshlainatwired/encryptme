# EncryptMe file format (v1)

Binary, no base64 wrapping. All multi-byte crypto values are raw bytes.

## Layout

```
offset  size      field
------  --------  ---------------------------------------------------------
0       4         magic            ASCII "EZME" (0x45 0x5A 0x4D 0x45)
4       1         version          0x01
5       1         mode             0x01 = password, 0x02 = public-key
6       N         mode payload     password: 16-byte Argon2id salt
                                   public-key: 32-byte sender ephemeral X25519 pubkey
6+N     24        ss header        crypto_secretstream header (HEADERBYTES)
30+N    ...       chunks           sequence of AEAD frames (see below)
```

`N` is 16 (password) or 32 (public-key). The header length is fully determined
by the mode byte, so a decryptor reads 6 bytes, learns the mode, then reads the
rest of the header.

## Chunks

The payload is encrypted with **XChaCha20-Poly1305** via libsodium's
`crypto_secretstream` API. Plaintext is split into fixed `CHUNK_SIZE` = **65536
bytes (64 KiB)** pieces. Each frame is:

```
ciphertext = CHUNK_SIZE (or less, final frame) + ABYTES (17-byte tag)
```

- Every frame except the last carries `TAG_MESSAGE`.
- The last frame carries `TAG_FINAL`. There is **always** a final frame, even
  for empty input (an empty final frame). A stream that ends without a
  `TAG_FINAL` frame, or contains data after it, is rejected as corrupt — this is
  the truncation/extension protection.
- The full file header (magic..ss header) is passed as secretstream **additional
  data** on the first frame, binding it to the stream. Tampering with the magic,
  version, mode, salt or ephemeral key fails authentication.

### Framing rule (encrypt and decrypt agree)

A `CHUNK_SIZE`-aligned frame is only emitted as non-final once more bytes are
known to follow. Whatever remains at end-of-stream is the final frame. This
makes the boundary unambiguous for inputs whose length is an exact multiple of
`CHUNK_SIZE`.

## Key derivation

### Password mode (0x01)

```
salt = randombytes_buf(16)                       # crypto_pwhash_SALTBYTES
key  = crypto_pwhash(32, password, salt,
                     OPSLIMIT_MODERATE,
                     MEMLIMIT_MODERATE,           # ~256 MiB
                     ALG_ARGON2ID13)
```

The KDF profile is tied to the **version byte**; a future profile change bumps
the version so old files keep decrypting.

### Public-key mode (0x02)

X25519 via `crypto_kx`. The sender generates an ephemeral keypair and derives a
shared key against the recipient's static public key:

```
encrypt: (eph_pk, eph_sk) = crypto_kx_keypair()
         key = crypto_kx_client_session_keys(eph_pk, eph_sk, recipient_pk).sharedTx
         # eph_pk is stored in the header

decrypt: key = crypto_kx_server_session_keys(recipient_pk, recipient_sk, eph_pk).sharedRx
```

`client.sharedTx == server.sharedRx` by construction, so both sides obtain the
same secretstream key.

## Constants

| name        | value                                        |
| ----------- | -------------------------------------------- |
| magic       | `EZME`                                        |
| version     | 1                                            |
| CHUNK_SIZE  | 65536 (64 KiB)                               |
| SALTBYTES   | 16                                           |
| KEYBYTES    | 32                                           |
| ABYTES      | 17                                           |
| HEADERBYTES | 24                                           |
| pubkey      | 32                                           |

These are pinned in `src/lib/crypto/fileformat.ts` and asserted against the
running libsodium on init.
