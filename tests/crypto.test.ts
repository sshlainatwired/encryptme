import { describe, it, expect, beforeAll } from "vitest";
import sodium from "libsodium-wrappers-sumo";
import {
  encrypt,
  decrypt,
  generateKeypair,
  CHUNK_SIZE,
  ABYTES,
} from "../src/lib/crypto";

// Drive the async-iterable API from an in-memory buffer, splitting into
// arbitrary-sized reads to prove the framing is robust to read boundaries.
function source(data: Uint8Array, readSize: number): AsyncIterable<Uint8Array> {
  return {
    async *[Symbol.asyncIterator]() {
      for (let i = 0; i < data.length; i += readSize) {
        yield data.subarray(i, Math.min(i + readSize, data.length));
      }
    },
  };
}

async function collect(gen: AsyncIterable<Uint8Array>): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  let total = 0;
  for await (const p of gen) {
    parts.push(p);
    total += p.length;
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

beforeAll(async () => {
  await sodium.ready;
});

const rand = (n: number) => sodium.randombytes_buf(n);

describe("password mode roundtrip", () => {
  // sizes that don't align to CHUNK_SIZE, plus boundaries
  const sizes = [
    0,
    1,
    100,
    CHUNK_SIZE - 1,
    CHUNK_SIZE,
    CHUNK_SIZE + 1,
    2 * CHUNK_SIZE,
    2 * CHUNK_SIZE + 12345,
  ];

  for (const size of sizes) {
    it(`roundtrips ${size} bytes byte-for-byte`, async () => {
      const data = rand(size);
      const password = "correct horse battery staple";
      const ct = await collect(
        encrypt(source(data, 7777), { mode: "password", password })
      );
      const pt = await collect(
        decrypt(source(ct, 3333), { mode: "password", password })
      );
      expect(pt).toEqual(data);
    });
  }

  it("wrong password fails cleanly without yielding plaintext", async () => {
    const data = rand(50000);
    const ct = await collect(
      encrypt(source(data, 9999), { mode: "password", password: "right" })
    );
    await expect(
      collect(decrypt(source(ct, 9999), { mode: "password", password: "wrong" }))
    ).rejects.toThrow();
  });
});

describe("public-key mode roundtrip", () => {
  it("roundtrips with recipient keypair", async () => {
    const recipient = await generateKeypair();
    const data = rand(CHUNK_SIZE + 999);
    const ct = await collect(
      encrypt(source(data, 4096), {
        mode: "key",
        recipientPublicKey: recipient.publicKey,
      })
    );
    const pt = await collect(
      decrypt(source(ct, 4096), {
        mode: "key",
        secretKey: recipient.secretKey,
        publicKey: recipient.publicKey,
      })
    );
    expect(pt).toEqual(data);
  });

  it("wrong recipient key fails", async () => {
    const recipient = await generateKeypair();
    const attacker = await generateKeypair();
    const data = rand(20000);
    const ct = await collect(
      encrypt(source(data, 4096), {
        mode: "key",
        recipientPublicKey: recipient.publicKey,
      })
    );
    await expect(
      collect(
        decrypt(source(ct, 4096), {
          mode: "key",
          secretKey: attacker.secretKey,
          publicKey: attacker.publicKey,
        })
      )
    ).rejects.toThrow();
  });
});

describe("tamper & truncation detection", () => {
  it("rejects a flipped ciphertext byte", async () => {
    const data = rand(30000);
    const password = "pw";
    const ct = await collect(
      encrypt(source(data, 8192), { mode: "password", password })
    );
    ct[ct.length - 5] ^= 0xff; // flip a byte in the final frame
    await expect(
      collect(decrypt(source(ct, 8192), { mode: "password", password }))
    ).rejects.toThrow();
  });

  it("rejects a tampered header (magic/salt)", async () => {
    const data = rand(5000);
    const password = "pw";
    const ct = await collect(
      encrypt(source(data, 8192), { mode: "password", password })
    );
    ct[8] ^= 0xff; // flip a salt byte -> wrong key AND header AD mismatch
    await expect(
      collect(decrypt(source(ct, 8192), { mode: "password", password }))
    ).rejects.toThrow();
  });

  it("rejects a stream missing the final tag (truncation)", async () => {
    const data = rand(3 * CHUNK_SIZE);
    const password = "pw";
    const ct = await collect(
      encrypt(source(data, 8192), { mode: "password", password })
    );
    // Drop the entire final frame so the stream ends without TAG_FINAL.
    const truncated = ct.subarray(0, ct.length - (CHUNK_SIZE + ABYTES));
    await expect(
      collect(decrypt(source(truncated, 8192), { mode: "password", password }))
    ).rejects.toThrow(/final|truncat|corrupt/i);
  });

  it("rejects extra data after the final tag", async () => {
    const data = rand(1000);
    const password = "pw";
    const ct = await collect(
      encrypt(source(data, 8192), { mode: "password", password })
    );
    const extended = new Uint8Array(ct.length + (CHUNK_SIZE + ABYTES));
    extended.set(ct, 0);
    await expect(
      collect(decrypt(source(extended, 8192), { mode: "password", password }))
    ).rejects.toThrow();
  });
});
