// UI wiring for the EncryptMe page. All crypto runs through ../lib/crypto.
import { encrypt, decrypt, generateKeypair } from "../lib/crypto";
import { processFile, hasFileSystemAccess } from "../lib/crypto/streaming";
import {
  generatePassword,
  estimateStrength,
  encodeKey,
  decodeKey,
} from "../lib/crypto/util";
import { MODE_BYTE_OFFSET, MODE_KEY, MODE_PASSWORD } from "../lib/crypto/fileformat";

const $ = <T extends Element = HTMLElement>(sel: string, root: ParentNode = document) =>
  root.querySelector(sel) as T | null;
const $$ = <T extends Element = HTMLElement>(sel: string, root: ParentNode = document) =>
  Array.from(root.querySelectorAll(sel)) as T[];

const fmtBytes = (n: number): string => {
  if (n < 1024) return `${n} B`;
  const u = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(1)} ${u[i]}`;
};

interface State {
  encryptFiles: File[];
  decryptFile: File | null;
  encryptMode: "password" | "key";
  decryptMode: "password" | "key";
  keypair: { publicKey: string; secretKey: string } | null;
  secretRevealed: boolean;
  abort: AbortController | null;
}

export function initApp(): void {
  const state: State = {
    encryptFiles: [],
    decryptFile: null,
    encryptMode: "password",
    decryptMode: "password",
    keypair: null,
    secretRevealed: false,
    abort: null,
  };

  // --- tabs ---
  const selectTab = (name: string) => {
    $$<HTMLButtonElement>(".tab").forEach((b) =>
      b.setAttribute("aria-selected", String(b.dataset.tab === name))
    );
    $$(".panel").forEach((p) => {
      const match = (p as HTMLElement).dataset.panel === name;
      p.classList.toggle("hidden", !match);
      p.classList.toggle("flex", match);
    });
  };
  $$<HTMLButtonElement>(".tab").forEach((b) =>
    b.addEventListener("click", () => selectTab(b.dataset.tab!))
  );
  selectTab("encrypt");

  // --- mode toggles ---
  const selectMode = (group: "encrypt" | "decrypt", value: "password" | "key") => {
    if (group === "encrypt") state.encryptMode = value;
    else state.decryptMode = value;
    $$<HTMLButtonElement>(`.modebtn[data-mode="${group}"]`).forEach((b) =>
      b.setAttribute("aria-selected", String(b.dataset.value === value))
    );
    $(`[data-sub="${group}-password"]`)?.classList.toggle("hidden", value !== "password");
    $(`[data-sub="${group}-password"]`)?.classList.toggle("flex", value === "password");
    $(`[data-sub="${group}-key"]`)?.classList.toggle("hidden", value !== "key");
    $(`[data-sub="${group}-key"]`)?.classList.toggle("flex", value === "key");
  };
  $$<HTMLButtonElement>('.modebtn[data-mode="encrypt"]').forEach((b) =>
    b.addEventListener("click", () => selectMode("encrypt", b.dataset.value as "password" | "key"))
  );
  selectMode("encrypt", "password");

  // --- file inputs ---
  const setEncryptFiles = (files: File[]) => {
    state.encryptFiles = files;
    const label = $('[data-files="encrypt"]')!;
    label.textContent = files.length
      ? files.map((f) => `${f.name} · ${fmtBytes(f.size)}`).join(", ")
      : "No files selected";
  };
  const setDecryptFile = async (file: File | null) => {
    state.decryptFile = file;
    $('[data-files="decrypt"]')!.textContent = file
      ? `${file.name} · ${fmtBytes(file.size)}`
      : "No file selected";
    if (file) await detectDecryptMode(file);
  };

  const encInput = $<HTMLInputElement>('[data-input="encrypt"]')!;
  encInput.addEventListener("change", () => setEncryptFiles(Array.from(encInput.files ?? [])));
  const decInput = $<HTMLInputElement>('[data-input="decrypt"]')!;
  decInput.addEventListener("change", () => setDecryptFile(decInput.files?.[0] ?? null));

  // Drag-and-drop on the slot labels (native file inputs don't accept drops).
  const wireDrop = (sel: string, onFiles: (f: File[]) => void) => {
    const zone = $(sel);
    if (!zone) return;
    const stop = (e: Event) => {
      e.preventDefault();
      e.stopPropagation();
    };
    ["dragenter", "dragover"].forEach((ev) =>
      zone.addEventListener(ev, (e) => {
        stop(e);
        zone.classList.add("is-drag");
      })
    );
    ["dragleave", "dragend"].forEach((ev) =>
      zone.addEventListener(ev, (e) => {
        stop(e);
        zone.classList.remove("is-drag");
      })
    );
    zone.addEventListener("drop", (e) => {
      stop(e);
      zone.classList.remove("is-drag");
      const files = Array.from((e as DragEvent).dataTransfer?.files ?? []);
      if (files.length) onFiles(files);
    });
  };
  wireDrop('[data-zone="encrypt"]', setEncryptFiles);
  wireDrop('[data-zone="decrypt"]', (f) => setDecryptFile(f[0] ?? null));

  const detectDecryptMode = async (file: File) => {
    const note = $('[data-el="dec-detected"]')!;
    try {
      const head = new Uint8Array(await file.slice(0, MODE_BYTE_OFFSET + 1).arrayBuffer());
      const mode = head[MODE_BYTE_OFFSET];
      if (mode === MODE_KEY) {
        selectMode("decrypt", "key");
        note.textContent = "detected: public-key file";
      } else if (mode === MODE_PASSWORD) {
        selectMode("decrypt", "password");
        note.textContent = "detected: password file";
      } else {
        note.textContent = "unrecognized file format";
      }
      note.classList.remove("hidden");
    } catch {
      note.classList.add("hidden");
    }
  };

  // --- password helpers ---
  const encPw = $<HTMLInputElement>('[data-el="enc-pw"]')!;
  const encPw2 = $<HTMLInputElement>('[data-el="enc-pw2"]')!;
  const meter = $('[data-el="pw-meter"]')!;
  const meterLabel = $('[data-el="pw-label"]')!;
  const colors = ["bg-slate-400", "bg-red-500", "bg-amber-500", "bg-lime-500", "bg-emerald-500"];
  const updateMeter = () => {
    const { score, label } = estimateStrength(encPw.value);
    meter.style.width = `${(score / 4) * 100}%`;
    meter.className = `h-full rounded-full transition-all ${colors[score]}`;
    meterLabel.textContent = label;
  };
  encPw.addEventListener("input", updateMeter);

  const encToggle = $('[data-act="toggle-enc-pw"]')!;
  encToggle.addEventListener("click", () => {
    const show = encPw.type === "password";
    encPw.type = encPw2.type = show ? "text" : "password";
    encToggle.textContent = show ? "hide" : "show";
  });
  const decToggle = $('[data-act="toggle-dec-pw"]')!;
  decToggle.addEventListener("click", () => {
    const f = $<HTMLInputElement>('[data-el="dec-pw"]')!;
    f.type = f.type === "password" ? "text" : "password";
    decToggle.textContent = f.type === "password" ? "show" : "hide";
  });

  const pwLen = $<HTMLInputElement>('[data-el="pw-len"]')!;
  const pwLenVal = $('[data-el="pw-len-val"]')!;
  pwLen.addEventListener("input", () => (pwLenVal.textContent = pwLen.value));
  $('[data-act="gen-pw"]')!.addEventListener("click", () => {
    const pw = generatePassword(Number(pwLen.value));
    encPw.value = encPw2.value = pw;
    encPw.type = encPw2.type = "text";
    updateMeter();
  });

  // --- status / progress ---
  const statusEl = $('[data-el="status"]')!;
  const statusText = $('[data-el="status-text"]')!;
  const bar = $('[data-el="bar"]')!;
  const result = $('[data-el="result"]')!;

  const showStatus = (text: string) => {
    statusEl.classList.remove("hidden");
    statusEl.classList.add("flex");
    statusText.textContent = text;
    result.classList.add("hidden");
  };
  const hideStatus = () => {
    statusEl.classList.add("hidden");
    statusEl.classList.remove("flex");
    bar.style.width = "0%";
  };
  const showResult = (text: string, ok: boolean) => {
    result.textContent = text;
    result.className = `rounded-lg px-4 py-3 text-sm ${
      ok
        ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 ring-1 ring-emerald-500/30"
        : "bg-red-500/10 text-red-700 dark:text-red-400 ring-1 ring-red-500/30"
    }`;
    result.classList.remove("hidden");
  };
  const progress = (read: number, total: number) => {
    bar.style.width = `${total ? (read / total) * 100 : 100}%`;
    statusText.textContent = `${fmtBytes(read)} / ${fmtBytes(total)}`;
  };

  $('[data-act="cancel"]')!.addEventListener("click", () => state.abort?.abort());

  // --- run a single processFile, handling cancel/errors uniformly ---
  const run = async (
    file: File,
    transform: Parameters<typeof processFile>[1],
    outName: string,
    prefix: string
  ): Promise<boolean> => {
    state.abort = new AbortController();
    showStatus(`${prefix}: ${file.name}`);
    try {
      const res = await processFile(file, transform, outName, {
        onProgress: progress,
        signal: state.abort.signal,
      });
      bar.style.width = "100%";
      if (res.method === "download") {
        showResult(`Done. Saved ${outName} to your downloads.`, true);
      } else {
        showResult(`Done. Wrote ${outName}.`, true);
      }
      return true;
    } catch (e) {
      const err = e as { name?: string; message?: string };
      if (err.name === "AbortError") showResult("Cancelled. No output was kept.", false);
      else showResult(err.message ?? "Operation failed.", false);
      return false;
    } finally {
      hideStatus();
      state.abort = null;
    }
  };

  // --- encrypt ---
  $('[data-act="encrypt"]')!.addEventListener("click", async () => {
    if (!state.encryptFiles.length) return showResult("Choose at least one file first.", false);

    let opts: Parameters<typeof encrypt>[1];
    if (state.encryptMode === "password") {
      if (!encPw.value) return showResult("Enter a password.", false);
      if (encPw.value !== encPw2.value) return showResult("Passwords do not match.", false);
      opts = { mode: "password", password: encPw.value };
    } else {
      const text = $<HTMLTextAreaElement>('[data-el="enc-recipient"]')!.value.trim();
      if (!text) return showResult("Paste the recipient's public key.", false);
      try {
        opts = { mode: "key", recipientPublicKey: await decodeKey(text) };
      } catch {
        return showResult("That doesn't look like a valid public key.", false);
      }
    }

    if (!hasFileSystemAccess() && state.encryptFiles.length > 1) {
      showResult("Tip: this browser downloads each file separately.", true);
    }
    for (const file of state.encryptFiles) {
      const ok = await run(file, (src) => encrypt(src, opts), `${file.name}.enc`, "Encrypting");
      if (!ok) break;
    }
  });

  // --- decrypt ---
  $('[data-act="decrypt"]')!.addEventListener("click", async () => {
    const file = state.decryptFile;
    if (!file) return showResult("Choose a .enc file first.", false);

    let opts: Parameters<typeof decrypt>[1];
    if (state.decryptMode === "password") {
      const pw = $<HTMLInputElement>('[data-el="dec-pw"]')!.value;
      if (!pw) return showResult("Enter the password.", false);
      opts = { mode: "password", password: pw };
    } else {
      try {
        const publicKey = await decodeKey($<HTMLTextAreaElement>('[data-el="dec-pub"]')!.value);
        const secretKey = await decodeKey($<HTMLTextAreaElement>('[data-el="dec-sec"]')!.value);
        opts = { mode: "key", publicKey, secretKey };
      } catch {
        return showResult("Public/secret key is not valid base64.", false);
      }
    }

    const outName = file.name.endsWith(".enc") ? file.name.slice(0, -4) : `${file.name}.dec`;
    await run(file, (src) => decrypt(src, opts), outName, "Decrypting");
  });

  // --- keys ---
  const keysOut = $('[data-el="keys-out"]')!;
  const outPub = $<HTMLTextAreaElement>('[data-el="out-pub"]')!;
  const outSec = $<HTMLTextAreaElement>('[data-el="out-sec"]')!;
  const maskSec = () => "•".repeat(40);

  $('[data-act="genkeys"]')!.addEventListener("click", async () => {
    const kp = await generateKeypair();
    state.keypair = { publicKey: await encodeKey(kp.publicKey), secretKey: await encodeKey(kp.secretKey) };
    state.secretRevealed = false;
    outPub.value = state.keypair.publicKey;
    outSec.value = maskSec();
    keysOut.classList.remove("hidden");
    keysOut.classList.add("flex");
  });
  $('[data-act="reveal-sec"]')!.addEventListener("click", () => {
    if (!state.keypair) return;
    state.secretRevealed = !state.secretRevealed;
    outSec.value = state.secretRevealed ? state.keypair.secretKey : maskSec();
  });

  const copy = async (text: string, btn: HTMLElement) => {
    try {
      await navigator.clipboard.writeText(text);
      const old = btn.textContent;
      btn.textContent = "copied";
      setTimeout(() => (btn.textContent = old), 1200);
    } catch {
      /* clipboard blocked; user can select manually */
    }
  };
  $('[data-act="copy-pub"]')!.addEventListener("click", (e) =>
    state.keypair && copy(state.keypair.publicKey, e.currentTarget as HTMLElement)
  );
  $('[data-act="copy-sec"]')!.addEventListener("click", (e) =>
    state.keypair && copy(state.keypair.secretKey, e.currentTarget as HTMLElement)
  );

  const downloadText = (text: string, name: string) => {
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  };
  $('[data-act="dl-pub"]')!.addEventListener("click", () =>
    state.keypair && downloadText(state.keypair.publicKey, "encryptme-public.key")
  );
  $('[data-act="dl-sec"]')!.addEventListener("click", () =>
    state.keypair && downloadText(state.keypair.secretKey, "encryptme-secret.key")
  );
}
