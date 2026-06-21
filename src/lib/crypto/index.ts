// EncryptMe crypto core. Framework-agnostic, dependency-light (libsodium only).
//
// Public API: encrypt() / decrypt() are async generators over byte streams, so
// they work for both in-memory tests and disk streaming without buffering whole
// files. generateKeypair() makes X25519 keypairs for public-key mode.
import { getSodium } from "./sodium";
import { ByteQueue } from "./bytes";
import {
  ABYTES,
  CHUNK_SIZE,
  EPK_BYTES,
  MODE_BYTE_OFFSET,
  MIN_BYTES_TO_READ_MODE,
  MODE_KEY,
  MODE_PASSWORD,
  headerLengthForMode,
  parseHeader,
  writeHeader,
  type Mode,
} from "./fileformat";
import { deriveKey, newSalt } from "./kdf";
import {
  generateKeypair,
  recipientSharedKey,
  senderSharedKey,
} from "./keyexchange";
import { initPull, initPush, pullChunk, pushChunk } from "./secretstream";

export { CHUNK_SIZE, ABYTES, generateKeypair };

const FRAME = CHUNK_SIZE + ABYTES;

export type EncryptOptions =
  | { mode: "password"; password: string }
  | { mode: "key"; recipientPublicKey: Uint8Array };

export type DecryptOptions =
  | { mode: "password"; password: string }
  | { mode: "key"; secretKey: Uint8Array; publicKey: Uint8Array };

type ByteSource = AsyncIterable<Uint8Array>;

// --- encrypt ---------------------------------------------------------------

export async function* encrypt(
  source: ByteSource,
  opts: EncryptOptions
): AsyncGenerator<Uint8Array> {
  const s = await getSodium();

  let key: Uint8Array;
  let mode: Mode;
  let payload: Uint8Array;
  if (opts.mode === "password") {
    const salt = await newSalt();
    key = await deriveKey(opts.password, salt);
    mode = MODE_PASSWORD;
    payload = salt;
  } else {
    const r = await senderSharedKey(opts.recipientPublicKey);
    key = r.key;
    mode = MODE_KEY;
    payload = r.ephemeralPublicKey;
  }

  try {
    const { state, ssHeader } = initPush(s, key);
    const fileHeader = writeHeader(mode, payload, ssHeader);
    yield fileHeader;

    const TAG_MESSAGE = s.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
    const TAG_FINAL = s.crypto_secretstream_xchacha20poly1305_TAG_FINAL;
    const empty = new Uint8Array(0);

    // Re-chunk plaintext to CHUNK_SIZE. A chunk is only emitted as non-final
    // once we know more bytes follow; whatever remains at end-of-stream is the
    // FINAL chunk (even if empty), giving truncation protection on decrypt.
    const q = new ByteQueue();
    let first = true;
    for await (const part of source) {
      q.push(part);
      while (q.length > CHUNK_SIZE) {
        const plain = q.shift(CHUNK_SIZE);
        yield pushChunk(s, state, plain, TAG_MESSAGE, first ? fileHeader : empty);
        first = false;
      }
    }
    const lastPlain = q.drain();
    yield pushChunk(s, state, lastPlain, TAG_FINAL, first ? fileHeader : empty);
  } finally {
    s.memzero(key);
  }
}

// --- decrypt ---------------------------------------------------------------

export async function* decrypt(
  source: ByteSource,
  opts: DecryptOptions
): AsyncGenerator<Uint8Array> {
  const s = await getSodium();
  const q = new ByteQueue();

  // 1) Read the file header (variable length depending on mode byte).
  const iter = source[Symbol.asyncIterator]();
  async function fill(min: number): Promise<boolean> {
    while (q.length < min) {
      const { value, done } = await iter.next();
      if (done) return false;
      q.push(value);
    }
    return true;
  }

  if (!(await fill(MIN_BYTES_TO_READ_MODE))) throw new Error("file too short");
  const mode = q.byteAt(MODE_BYTE_OFFSET);
  const headerLen = headerLengthForMode(mode);
  if (!(await fill(headerLen))) throw new Error("truncated header");
  const fileHeader = q.shift(headerLen);
  const parsed = parseHeader(fileHeader);

  // 2) Derive the key.
  let key: Uint8Array;
  if (parsed.mode === MODE_PASSWORD) {
    if (opts.mode !== "password") throw new Error("file needs a password");
    key = await deriveKey(opts.password, parsed.payload);
  } else if (parsed.mode === MODE_KEY) {
    if (opts.mode !== "key") throw new Error("file needs a secret key");
    if (parsed.payload.length !== EPK_BYTES) throw new Error("bad ephemeral key");
    key = await recipientSharedKey(
      { publicKey: opts.publicKey, secretKey: opts.secretKey },
      parsed.payload
    );
  } else {
    throw new Error("unknown mode");
  }

  try {
    const state = initPull(s, key, parsed.ssHeader);
    const TAG_FINAL = s.crypto_secretstream_xchacha20poly1305_TAG_FINAL;
    const empty = new Uint8Array(0);

    // 3) Frame the body. A frame is emitted as non-final only once we know more
    // bytes follow; the remainder at end-of-stream must be a FINAL frame.
    let first = true;
    let sawFinal = false;
    const open = (cipher: Uint8Array, mustBeFinal: boolean): Uint8Array => {
      const { message, tag } = pullChunk(s, state, cipher, first ? fileHeader : empty);
      first = false;
      const isFinal = tag === TAG_FINAL;
      if (isFinal && !mustBeFinal) throw new Error("corrupt: data after final chunk");
      if (!isFinal && mustBeFinal)
        throw new Error("corrupt: stream ended without final tag");
      if (isFinal) sawFinal = true;
      return message;
    };

    // Continue from the same iterator the header was read from.
    while (true) {
      while (q.length > FRAME) yield open(q.shift(FRAME), false);
      const { value, done } = await iter.next();
      if (done) break;
      q.push(value);
    }
    if (q.length < ABYTES) throw new Error("corrupt: truncated final chunk");
    yield open(q.drain(), true);
    if (!sawFinal) throw new Error("corrupt: missing final tag");
  } finally {
    s.memzero(key);
  }
}
