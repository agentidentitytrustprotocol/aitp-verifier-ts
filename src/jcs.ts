// RFC 8785 JSON Canonicalization Scheme.
//
// - Objects: members sorted by their names as arrays of UTF-16 code units
//   (§3.2.3). JavaScript's default string comparison is exactly that order.
// - Strings: the ECMAScript JSON.stringify escaping (§3.2.2.2): `"` and `\`
//   escaped, U+0000–U+001F as \b \t \n \f \r or lowercase \u00xx, every
//   other code point literal. A lone surrogate is rejected, not escaped.
// - Numbers: the ECMAScript Number-to-String algorithm (§3.2.2.3, ES2015+
//   §7.1.12.1). In JavaScript that algorithm is `String(n)`; -0 serializes as
//   "0", and NaN and ±Infinity are not representable and are rejected.
// - No whitespace anywhere.

import { isWellFormed, utf8 } from "./bytes.js";

export class JcsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JcsError";
  }
}

export function canonicalize(value: unknown): string {
  const parts: string[] = [];
  write(value, parts, 0);
  return parts.join("");
}

/** The UTF-8 bytes of the canonical form. */
export function canonicalBytes(value: unknown): Uint8Array {
  return utf8(canonicalize(value));
}

export function serializeNumber(n: number): string {
  if (!Number.isFinite(n)) throw new JcsError(`${n} has no JSON representation`);
  return Object.is(n, -0) ? "0" : String(n);
}

export function serializeString(s: string): string {
  if (!isWellFormed(s)) throw new JcsError("string contains a lone surrogate");
  return JSON.stringify(s);
}

function write(value: unknown, out: string[], depth: number): void {
  if (depth > 256) throw new JcsError("nesting too deep");
  if (value === null) {
    out.push("null");
  } else if (value === true || value === false) {
    out.push(value ? "true" : "false");
  } else if (typeof value === "number") {
    out.push(serializeNumber(value));
  } else if (typeof value === "string") {
    out.push(serializeString(value));
  } else if (Array.isArray(value)) {
    out.push("[");
    value.forEach((item, i) => {
      if (i > 0) out.push(",");
      write(item, out, depth + 1);
    });
    out.push("]");
  } else if (typeof value === "object") {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) throw new JcsError("only plain objects are JSON objects");
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    out.push("{");
    keys.forEach((k, i) => {
      if (i > 0) out.push(",");
      const v = obj[k];
      if (v === undefined) throw new JcsError(`member ${JSON.stringify(k)} is undefined`);
      out.push(serializeString(k), ":");
      write(v, out, depth + 1);
    });
    out.push("}");
  } else {
    throw new JcsError(`${typeof value} has no JSON representation`);
  }
}
