/** Saving API downloads in the browser and hashing them locally. */
export function saveBlob(blob: Blob, filename: string, doc: Document = document): void {
  const url = URL.createObjectURL(blob);
  const a = doc.createElement("a");
  a.href = url;
  a.download = filename;
  a.rel = "noopener";
  a.style.display = "none";
  doc.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

export function toHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

export async function sha256Hex(
  data: Blob | ArrayBuffer,
  subtle: SubtleCrypto = crypto.subtle,
): Promise<string> {
  const buf = data instanceof ArrayBuffer ? data : await data.arrayBuffer();
  return toHex(await subtle.digest("SHA-256", buf));
}

export async function copyText(
  text: string,
  clipboard: Pick<Clipboard, "writeText"> | undefined = navigator.clipboard,
): Promise<boolean> {
  try {
    if (!clipboard) return false;
    await clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/** Shell-quote a filename for the copy-paste verification command. */
export function verifyCommand(filename: string): string {
  const quoted = /^[A-Za-z0-9._\-/]+$/.test(filename)
    ? filename
    : `"${filename.replace(/(["\\$`])/g, "\\$1")}"`;
  return `veritas-verify export ${quoted}`;
}
