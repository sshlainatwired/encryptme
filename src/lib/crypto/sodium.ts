// libsodium init/ready singleton. Everything crypto-related awaits getSodium().
import _sodium from "libsodium-wrappers-sumo";
import {
  ABYTES,
  EPK_BYTES,
  KEYBYTES,
  SALTBYTES,
  SS_HEADERBYTES,
} from "./fileformat";

export type Sodium = typeof _sodium;

let initialized = false;

// Pinned constants are part of the on-disk format. If a future libsodium ever
// changed them, the format would silently break — so verify on first init.
function assertConstants(s: Sodium): void {
  const checks: Array<[string, number, number]> = [
    ["SALTBYTES", s.crypto_pwhash_SALTBYTES, SALTBYTES],
    ["KEYBYTES", s.crypto_secretstream_xchacha20poly1305_KEYBYTES, KEYBYTES],
    ["ABYTES", s.crypto_secretstream_xchacha20poly1305_ABYTES, ABYTES],
    [
      "HEADERBYTES",
      s.crypto_secretstream_xchacha20poly1305_HEADERBYTES,
      SS_HEADERBYTES,
    ],
    ["KX_PUBLICKEYBYTES", s.crypto_kx_PUBLICKEYBYTES, EPK_BYTES],
  ];
  for (const [name, actual, expected] of checks) {
    if (actual !== expected) {
      throw new Error(
        `libsodium constant ${name}=${actual} but format expects ${expected}`
      );
    }
  }
}

export async function getSodium(): Promise<Sodium> {
  if (!initialized) {
    await _sodium.ready;
    assertConstants(_sodium);
    initialized = true;
  }
  return _sodium;
}
