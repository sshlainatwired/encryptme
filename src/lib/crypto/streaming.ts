// Browser I/O adapter for the crypto core. Streams a File through a transform
// (encrypt/decrypt) to disk via the File System Access API where available,
// falling back to an in-memory Blob download (capped) on Firefox/Safari.
//
// This is the only crypto module that touches the DOM; the core stays portable.

// Minimal FSA typings (not in all TS dom libs yet).
interface FileSystemWritableFileStreamLike {
  write(data: Uint8Array): Promise<void>;
  close(): Promise<void>;
  abort(reason?: unknown): Promise<void>;
}
interface FileSystemFileHandleLike {
  createWritable(): Promise<FileSystemWritableFileStreamLike>;
}
interface SaveFilePickerOptions {
  suggestedName?: string;
  types?: Array<{ description?: string; accept: Record<string, string[]> }>;
}
type ShowSaveFilePicker = (
  opts?: SaveFilePickerOptions
) => Promise<FileSystemFileHandleLike>;

const FALLBACK_MAX_BYTES = 1024 * 1024 * 1024; // 1 GiB

export function hasFileSystemAccess(): boolean {
  return typeof (globalThis as { showSaveFilePicker?: unknown }).showSaveFilePicker === "function";
}

export interface ProcessOptions {
  onProgress?: (bytesRead: number, total: number) => void;
  signal?: AbortSignal;
}

export type Transform = (source: AsyncIterable<Uint8Array>) => AsyncGenerator<Uint8Array>;

// Wrap a File as an async byte stream that reports progress and honours cancel.
function readFile(
  file: File,
  opts: ProcessOptions
): AsyncIterable<Uint8Array> {
  return {
    async *[Symbol.asyncIterator]() {
      const reader = file.stream().getReader();
      let read = 0;
      try {
        for (;;) {
          if (opts.signal?.aborted) throw new DOMException("cancelled", "AbortError");
          const { value, done } = await reader.read();
          if (done) break;
          read += value.length;
          opts.onProgress?.(read, file.size);
          yield value;
        }
      } finally {
        reader.releaseLock();
      }
    },
  };
}

export type ProcessResult = { method: "fsa" } | { method: "download"; blob: Blob };

/**
 * Run `transform` over `file`, writing the result to `suggestedName`.
 * On FSA browsers, streams straight to disk (handles multi-GB files).
 * Otherwise buffers to a Blob (rejects inputs over FALLBACK_MAX_BYTES) and
 * triggers a download. Throws on cancel or any auth failure; partial output is
 * discarded (FSA writable is aborted; Blob is never created).
 */
export async function processFile(
  file: File,
  transform: Transform,
  suggestedName: string,
  opts: ProcessOptions = {}
): Promise<ProcessResult> {
  const source = readFile(file, opts);

  if (hasFileSystemAccess()) {
    const picker = (globalThis as unknown as { showSaveFilePicker: ShowSaveFilePicker })
      .showSaveFilePicker;
    const handle = await picker({ suggestedName });
    const writable = await handle.createWritable();
    try {
      for await (const chunk of transform(source)) {
        if (opts.signal?.aborted) throw new DOMException("cancelled", "AbortError");
        await writable.write(chunk);
      }
      await writable.close();
      return { method: "fsa" };
    } catch (e) {
      await writable.abort().catch(() => {});
      throw e;
    }
  }

  // Fallback: buffer in memory.
  if (file.size > FALLBACK_MAX_BYTES) {
    throw new Error(
      `File too large for this browser (${(file.size / 1e9).toFixed(1)} GB). ` +
        `Files over 1 GB need a Chromium-based browser (Chrome/Edge).`
    );
  }
  const parts: Uint8Array[] = [];
  for await (const chunk of transform(source)) {
    if (opts.signal?.aborted) throw new DOMException("cancelled", "AbortError");
    parts.push(chunk);
  }
  const blob = new Blob(parts as BlobPart[]);
  triggerDownload(blob, suggestedName);
  return { method: "download", blob };
}

function triggerDownload(blob: Blob, name: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Revoke after the click has a chance to start the download.
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}
