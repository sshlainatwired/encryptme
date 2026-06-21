// EncryptMe binary file format. See FILE_FORMAT.md for the full spec.
//
// [ magic   ] 4 bytes  ASCII "EZME"
// [ version ] 1 byte   format/KDF-profile version (currently 1)
// [ mode    ] 1 byte   0x01 password, 0x02 public-key
// [ payload ]          password: 16-byte Argon2id salt
//                      key:      32-byte sender ephemeral X25519 public key
// [ sshdr   ] 24 bytes secretstream header
// [ chunks  ]          frames of (CHUNK_SIZE + ABYTES), last may be shorter

const MAGIC = new Uint8Array([0x45, 0x5a, 0x4d, 0x45]); // "EZME"
const VERSION = 1;

export const MODE_PASSWORD = 0x01;
export const MODE_KEY = 0x02;
export type Mode = typeof MODE_PASSWORD | typeof MODE_KEY;

// Pinned libsodium constants (also asserted against the runtime in sodium.ts).
export const SALTBYTES = 16;
export const KEYBYTES = 32;
export const ABYTES = 17;
export const SS_HEADERBYTES = 24;
export const EPK_BYTES = 32;

// Plaintext bytes per secretstream chunk. Part of the format: encrypt and
// decrypt must agree. 64 KiB keeps memory low while amortizing the 17-byte tag.
export const CHUNK_SIZE = 64 * 1024;

const PREFIX_LEN = MAGIC.length + 2; // magic + version + mode

function payloadLengthForMode(mode: number): number {
  if (mode === MODE_PASSWORD) return SALTBYTES;
  if (mode === MODE_KEY) return EPK_BYTES;
  throw new Error(`unknown mode byte 0x${mode.toString(16)}`);
}

export function headerLengthForMode(mode: number): number {
  return PREFIX_LEN + payloadLengthForMode(mode) + SS_HEADERBYTES;
}

export function writeHeader(
  mode: Mode,
  payload: Uint8Array,
  ssHeader: Uint8Array
): Uint8Array {
  if (payload.length !== payloadLengthForMode(mode)) {
    throw new Error("payload length mismatch for mode");
  }
  if (ssHeader.length !== SS_HEADERBYTES) {
    throw new Error("bad secretstream header length");
  }
  const out = new Uint8Array(headerLengthForMode(mode));
  out.set(MAGIC, 0);
  out[MAGIC.length] = VERSION;
  out[MAGIC.length + 1] = mode;
  out.set(payload, PREFIX_LEN);
  out.set(ssHeader, PREFIX_LEN + payload.length);
  return out;
}

export interface ParsedHeader {
  version: number;
  mode: number;
  payload: Uint8Array;
  ssHeader: Uint8Array;
}

// `header` must be exactly headerLengthForMode(mode) bytes.
export function parseHeader(header: Uint8Array): ParsedHeader {
  for (let i = 0; i < MAGIC.length; i++) {
    if (header[i] !== MAGIC[i]) throw new Error("not an EncryptMe file (bad magic)");
  }
  const version = header[MAGIC.length]!;
  if (version !== VERSION) throw new Error(`unsupported format version ${version}`);
  const mode = header[MAGIC.length + 1]!;
  const payloadLen = payloadLengthForMode(mode);
  const payload = header.slice(PREFIX_LEN, PREFIX_LEN + payloadLen);
  const ssHeader = header.slice(PREFIX_LEN + payloadLen, PREFIX_LEN + payloadLen + SS_HEADERBYTES);
  return { version, mode, payload, ssHeader };
}

// Mode byte lives right after magic+version, so we only need this many bytes to
// know the full header length.
export const MIN_BYTES_TO_READ_MODE = PREFIX_LEN;
export const MODE_BYTE_OFFSET = MAGIC.length + 1;
