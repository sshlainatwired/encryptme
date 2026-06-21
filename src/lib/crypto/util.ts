// Small UI-facing helpers: CSPRNG password generation, key encoding, and a
// cheap password-strength estimate (no zxcvbn dependency).
import { getSodium } from "./sodium";

const LOWER = "abcdefghijkmnpqrstuvwxyz"; // no l/o
const UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"; // no I/O
const DIGIT = "23456789"; // no 0/1
const SYMBOL = "!@#$%^&*()-_=+[]{}";

// Rejection sampling over getRandomValues -> no modulo bias.
function randomIndex(max: number): number {
  const limit = Math.floor(0x100000000 / max) * max;
  const buf = new Uint32Array(1);
  let v: number;
  do {
    crypto.getRandomValues(buf);
    v = buf[0]!;
  } while (v >= limit);
  return v % max;
}

export function generatePassword(length = 20, symbols = true): string {
  const charset = LOWER + UPPER + DIGIT + (symbols ? SYMBOL : "");
  let out = "";
  for (let i = 0; i < length; i++) out += charset[randomIndex(charset.length)];
  return out;
}

export interface Strength {
  score: 0 | 1 | 2 | 3 | 4;
  label: string;
}

// Rough log2(charset^length) entropy estimate. Not a substitute for zxcvbn, but
// honest for randomly-generated passwords and good enough as a meter.
export function estimateStrength(pw: string): Strength {
  if (!pw) return { score: 0, label: "empty" };
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 32;
  const bits = pw.length * Math.log2(pool || 1);
  const score = bits < 40 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
  const labels = ["very weak", "weak", "fair", "strong", "very strong"];
  return { score: score as Strength["score"], label: labels[score]! };
}

// X25519 keys are shared as base64 (url-safe, no padding).
export async function encodeKey(key: Uint8Array): Promise<string> {
  const s = await getSodium();
  return s.to_base64(key, s.base64_variants.URLSAFE_NO_PADDING);
}

export async function decodeKey(text: string): Promise<Uint8Array> {
  const s = await getSodium();
  return s.from_base64(text.trim(), s.base64_variants.URLSAFE_NO_PADDING);
}
