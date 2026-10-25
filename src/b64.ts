// Unpadded base64url (RFC 4648 §5), strictly.
//
// RFC-AITP-0001 §5.4 makes unpadded base64url the only encoding for
// signatures, proofs, nonces, `cnf` and AID identifiers, and §5.4.5 forbids
// any normalization of JWS segments. So this decoder accepts exactly the
// strings `encode` can produce: alphabet [A-Za-z0-9_-], no `=`, no
// whitespace, no length that is 1 mod 4, and zero unused trailing bits. A
// string with non-zero trailing bits decodes to the same bytes as a
// different string, which would make one value spellable two ways.

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const LOOKUP = new Map<string, number>([...ALPHABET].map((c, i) => [c, i]));

export class Base64UrlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "Base64UrlError";
  }
}

export function encode(bytes: Uint8Array): string {
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = ((bytes[i] as number) << 16) | ((bytes[i + 1] as number) << 8) | (bytes[i + 2] as number);
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]! + ALPHABET[(n >> 6) & 63]! + ALPHABET[n & 63]!;
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = (bytes[i] as number) << 16;
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]!;
  } else if (rest === 2) {
    const n = ((bytes[i] as number) << 16) | ((bytes[i + 1] as number) << 8);
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]! + ALPHABET[(n >> 6) & 63]!;
  }
  return out;
}

export function decode(text: string): Uint8Array {
  if (text.length % 4 === 1) throw new Base64UrlError("impossible base64url length");
  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (const c of text) {
    const v = LOOKUP.get(c);
    if (v === undefined) throw new Base64UrlError(`character ${JSON.stringify(c)} is outside the unpadded base64url alphabet`);
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  if (bits > 0 && (acc & ((1 << bits) - 1)) !== 0) throw new Base64UrlError("non-zero trailing bits");
  return out;
}

/** Decode, or `undefined` when `text` is not strict unpadded base64url. */
export function tryDecode(text: string): Uint8Array | undefined {
  try {
    return decode(text);
  } catch {
    return undefined;
  }
}

/** Decode and require exactly `length` bytes. */
export function decodeExact(text: string, length: number): Uint8Array | undefined {
  const bytes = tryDecode(text);
  return bytes !== undefined && bytes.length === length ? bytes : undefined;
}
