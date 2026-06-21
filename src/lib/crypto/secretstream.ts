// Thin wrappers over libsodium's XChaCha20-Poly1305 secretstream. The framing,
// header assembly and tag enforcement live in index.ts (the orchestrator).
import type { Sodium } from "./sodium";

export interface PushState {
  state: ReturnType<Sodium["crypto_secretstream_xchacha20poly1305_init_push"]>["state"];
}

export function initPush(
  s: Sodium,
  key: Uint8Array
): { state: PushState["state"]; ssHeader: Uint8Array } {
  const r = s.crypto_secretstream_xchacha20poly1305_init_push(key);
  return { state: r.state, ssHeader: r.header };
}

export function pushChunk(
  s: Sodium,
  state: PushState["state"],
  plain: Uint8Array,
  tag: number,
  ad: Uint8Array
): Uint8Array {
  return s.crypto_secretstream_xchacha20poly1305_push(state, plain, ad, tag);
}

export function initPull(
  s: Sodium,
  key: Uint8Array,
  ssHeader: Uint8Array
): ReturnType<Sodium["crypto_secretstream_xchacha20poly1305_init_pull"]> {
  return s.crypto_secretstream_xchacha20poly1305_init_pull(ssHeader, key);
}

// Returns { message, tag } or throws if the frame fails authentication.
export function pullChunk(
  s: Sodium,
  state: ReturnType<Sodium["crypto_secretstream_xchacha20poly1305_init_pull"]>,
  cipher: Uint8Array,
  ad: Uint8Array
): { message: Uint8Array; tag: number } {
  // The JS wrapper returns `false` on auth failure, which the types don't model.
  const r = s.crypto_secretstream_xchacha20poly1305_pull(state, cipher, ad) as
    | { message: Uint8Array; tag: number }
    | false;
  if (r === false) throw new Error("decryption failed: chunk authentication error");
  return r;
}
