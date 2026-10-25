// A strict JSON parser (RFC 8259 grammar, I-JSON constraints of RFC 7493).
//
// `JSON.parse` keeps the last of two duplicate keys, so `{"aud":"A","aud":"B"}`
// reads differently to it and to a parser that keeps the first. RFC-AITP-0001
// §5.4.5 requires a JWS payload with duplicate keys to be rejected, and every
// JCS-profile artifact is only well defined if each member has one value. This
// parser rejects a duplicate at any depth, a lone surrogate (in an escape or
// raw), a number that does not fit an IEEE double, and anything outside the
// RFC 8259 grammar. Objects are built with defineProperty, so a `__proto__`
// key is an ordinary member, never a prototype change.

import { fromUtf8, isWellFormed } from "./bytes.js";

export type JsonValue = null | boolean | number | string | JsonValue[] | JsonObject;
export interface JsonObject {
  [key: string]: JsonValue;
}

export class JsonParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JsonParseError";
  }
}

const MAX_DEPTH = 256;

export function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Parse UTF-8 bytes. Malformed UTF-8 is a parse error. */
export function parseJsonBytes(bytes: Uint8Array): JsonValue {
  let text: string;
  try {
    text = fromUtf8(bytes);
  } catch {
    throw new JsonParseError("input is not valid UTF-8");
  }
  return parseJson(text);
}

export function parseJson(text: string): JsonValue {
  if (!isWellFormed(text)) throw new JsonParseError("input contains a lone surrogate");
  const p = new Parser(text);
  p.ws();
  const value = p.value(0);
  p.ws();
  if (p.i !== text.length) p.fail("trailing characters after the JSON value");
  return value;
}

/** Parse and require the top-level value to be an object. */
export function parseJsonObjectBytes(bytes: Uint8Array): JsonObject {
  const value = parseJsonBytes(bytes);
  if (!isJsonObject(value)) throw new JsonParseError("top-level value is not an object");
  return value;
}

class Parser {
  i = 0;
  constructor(readonly s: string) {}

  fail(message: string): never {
    throw new JsonParseError(`${message} at offset ${this.i}`);
  }

  ws(): void {
    while (this.i < this.s.length) {
      const c = this.s.charCodeAt(this.i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.i++;
      else break;
    }
  }

  value(depth: number): JsonValue {
    if (depth > MAX_DEPTH) this.fail("nesting too deep");
    const c = this.s[this.i];
    switch (c) {
      case "{":
        return this.object(depth);
      case "[":
        return this.array(depth);
      case '"':
        return this.string();
      case "t":
        return this.literal("true", true);
      case "f":
        return this.literal("false", false);
      case "n":
        return this.literal("null", null);
      default:
        if (c === "-" || (c !== undefined && c >= "0" && c <= "9")) return this.number();
        return this.fail(c === undefined ? "unexpected end of input" : `unexpected character ${JSON.stringify(c)}`);
    }
  }

  literal<T extends JsonValue>(word: string, value: T): T {
    if (this.s.startsWith(word, this.i)) {
      this.i += word.length;
      return value;
    }
    return this.fail("invalid literal");
  }

  object(depth: number): JsonObject {
    this.i++; // {
    const out: JsonObject = {};
    const seen = new Set<string>();
    this.ws();
    if (this.s[this.i] === "}") {
      this.i++;
      return out;
    }
    for (;;) {
      this.ws();
      if (this.s[this.i] !== '"') this.fail("expected a member name");
      const key = this.string();
      if (seen.has(key)) this.fail(`duplicate member ${JSON.stringify(key)}`);
      seen.add(key);
      this.ws();
      if (this.s[this.i] !== ":") this.fail("expected ':'");
      this.i++;
      this.ws();
      const v = this.value(depth + 1);
      Object.defineProperty(out, key, { value: v, enumerable: true, writable: true, configurable: true });
      this.ws();
      const c = this.s[this.i];
      if (c === ",") {
        this.i++;
        continue;
      }
      if (c === "}") {
        this.i++;
        return out;
      }
      this.fail("expected ',' or '}'");
    }
  }

  array(depth: number): JsonValue[] {
    this.i++; // [
    const out: JsonValue[] = [];
    this.ws();
    if (this.s[this.i] === "]") {
      this.i++;
      return out;
    }
    for (;;) {
      this.ws();
      out.push(this.value(depth + 1));
      this.ws();
      const c = this.s[this.i];
      if (c === ",") {
        this.i++;
        continue;
      }
      if (c === "]") {
        this.i++;
        return out;
      }
      this.fail("expected ',' or ']'");
    }
  }

  string(): string {
    this.i++; // opening quote
    let out = "";
    let start = this.i;
    for (;;) {
      if (this.i >= this.s.length) this.fail("unterminated string");
      const c = this.s.charCodeAt(this.i);
      if (c === 0x22) {
        out += this.s.slice(start, this.i);
        this.i++;
        break;
      }
      if (c < 0x20) this.fail("unescaped control character in string");
      if (c !== 0x5c) {
        this.i++;
        continue;
      }
      out += this.s.slice(start, this.i);
      this.i++;
      const e = this.s[this.i];
      this.i++;
      switch (e) {
        case '"':
          out += '"';
          break;
        case "\\":
          out += "\\";
          break;
        case "/":
          out += "/";
          break;
        case "b":
          out += "\b";
          break;
        case "f":
          out += "\f";
          break;
        case "n":
          out += "\n";
          break;
        case "r":
          out += "\r";
          break;
        case "t":
          out += "\t";
          break;
        case "u": {
          const hex = this.s.slice(this.i, this.i + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) this.fail("invalid \\u escape");
          out += String.fromCharCode(parseInt(hex, 16));
          this.i += 4;
          break;
        }
        default:
          this.fail("invalid escape");
      }
      start = this.i;
    }
    if (!isWellFormed(out)) this.fail("string contains a lone surrogate");
    return out;
  }

  number(): number {
    const m = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(this.s.slice(this.i, this.i + 400));
    if (!m) return this.fail("invalid number");
    const text = m[0];
    // A longer run of digits than the regex window saw is not a number we
    // can represent anyway; let the next character fail the grammar.
    this.i += text.length;
    const n = Number(text);
    if (!Number.isFinite(n)) this.fail("number out of range");
    return n;
  }
}
