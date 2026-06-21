// Password -> key via Argon2id. The KDF profile is tied to the format version
// byte so it can evolve later. Version 1 = "moderate" (opslimit 3, ~256 MiB).
import { getSodium } from "./sodium";
import { KEYBYTES, SALTBYTES } from "./fileformat";

export async function newSalt(): Promise<Uint8Array> {
  const s = await getSodium();
  return s.randombytes_buf(SALTBYTES);
}

export async function deriveKey(
  password: string,
  salt: Uint8Array
): Promise<Uint8Array> {
  const s = await getSodium();
  if (salt.length !== SALTBYTES) throw new Error("bad salt length");
  return s.crypto_pwhash(
    KEYBYTES,
    password,
    salt,
    s.crypto_pwhash_OPSLIMIT_MODERATE,
    s.crypto_pwhash_MEMLIMIT_MODERATE,
    s.crypto_pwhash_ALG_ARGON2ID13
  );
}
