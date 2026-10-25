// Byte helpers shared by every module. Nothing here is AITP-specific.

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** UTF-8 encode. The input must be well-formed (no lone surrogates). */
export function utf8(text: string): Uint8Array {
  if (!isWellFormed(text)) throw new TypeError("string contains a lone surrogate");
  return encoder.encode(text);
}

/** Strict UTF-8 decode: malformed input throws instead of turning into U+FFFD. */
export function fromUtf8(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

/** True when `text` has no unpaired UTF-16 surrogate. */
export function isWellFormed(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return false;
    }
  }
  return true;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) throw new TypeError("invalid hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** Big-endian bytes to an unsigned BigInt. */
export function bytesToBigBE(bytes: Uint8Array): bigint {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

/** Little-endian bytes to an unsigned BigInt. */
export function bytesToBigLE(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i] as number);
  return n;
}

/** An unsigned BigInt as exactly `length` big-endian bytes. */
export function bigToBytesBE(n: bigint, length: number): Uint8Array {
  if (n < 0n) throw new RangeError("negative");
  const out = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  if (n !== 0n) throw new RangeError("value does not fit");
  return out;
}

/**
 * A copy backed by a fresh ArrayBuffer, the shape WebCrypto's BufferSource
 * typing wants. Also stops a caller's later writes reaching a pending call.
 */
export function buf(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(bytes.length));
  out.set(bytes);
  return out;
}
