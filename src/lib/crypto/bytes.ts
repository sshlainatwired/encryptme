// A FIFO byte buffer for re-framing arbitrarily-chunked streams into the fixed
// frame sizes the format requires, without copying the whole stream at once.
export class ByteQueue {
  private chunks: Uint8Array[] = [];
  length = 0;

  push(c: Uint8Array): void {
    if (c.length === 0) return;
    this.chunks.push(c);
    this.length += c.length;
  }

  byteAt(i: number): number {
    let idx = i;
    for (const c of this.chunks) {
      if (idx < c.length) return c[idx]!;
      idx -= c.length;
    }
    throw new RangeError("byteAt out of range");
  }

  // Remove and return exactly n bytes from the front. Caller must ensure n <= length.
  shift(n: number): Uint8Array {
    if (n > this.length) throw new RangeError("shift past end");
    const out = new Uint8Array(n);
    let off = 0;
    while (off < n) {
      const head = this.chunks[0]!;
      const need = n - off;
      if (head.length <= need) {
        out.set(head, off);
        off += head.length;
        this.chunks.shift();
      } else {
        out.set(head.subarray(0, need), off);
        this.chunks[0] = head.subarray(need);
        off += need;
      }
    }
    this.length -= n;
    return out;
  }

  drain(): Uint8Array {
    return this.shift(this.length);
  }
}
