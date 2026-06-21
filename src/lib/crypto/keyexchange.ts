// Asymmetric mode: X25519 via crypto_kx. The sender uses an ephemeral keypair
// against the recipient's static public key; the shared key is one direction of
// the kx session pair so both sides derive the same secretstream key.
//
//   encrypt: client_session_keys(eph_pk, eph_sk, recipient_pk).sharedTx
//   decrypt: server_session_keys(recipient_pk, recipient_sk, eph_pk).sharedRx
//
// (client.sharedTx === server.sharedRx by construction.)
import { getSodium } from "./sodium";

export interface Keypair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export async function generateKeypair(): Promise<Keypair> {
  const s = await getSodium();
  const kp = s.crypto_kx_keypair();
  return { publicKey: kp.publicKey, secretKey: kp.privateKey };
}

// Sender side. Returns the shared key plus the ephemeral public key to embed in
// the file header. Zeroes the ephemeral secret and the unused rx key.
export async function senderSharedKey(recipientPublicKey: Uint8Array): Promise<{
  key: Uint8Array;
  ephemeralPublicKey: Uint8Array;
}> {
  const s = await getSodium();
  const eph = s.crypto_kx_keypair();
  const sk = s.crypto_kx_client_session_keys(
    eph.publicKey,
    eph.privateKey,
    recipientPublicKey
  );
  s.memzero(sk.sharedRx);
  s.memzero(eph.privateKey);
  return { key: sk.sharedTx, ephemeralPublicKey: eph.publicKey };
}

// Recipient side. Derives the same shared key from the embedded ephemeral pk.
export async function recipientSharedKey(
  recipientKeypair: Keypair,
  ephemeralPublicKey: Uint8Array
): Promise<Uint8Array> {
  const s = await getSodium();
  const sk = s.crypto_kx_server_session_keys(
    recipientKeypair.publicKey,
    recipientKeypair.secretKey,
    ephemeralPublicKey
  );
  s.memzero(sk.sharedTx);
  return sk.sharedRx;
}
