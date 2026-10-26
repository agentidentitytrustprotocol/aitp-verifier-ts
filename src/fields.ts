// Small structural checks shared by every artifact.

import * as b64 from "./b64.js";
import { concat, toHex, utf8 } from "./bytes.js";
import { type JsonObject, type JsonValue, isJsonObject } from "./json.js";
import { sha256 } from "./keys.js";

export interface MemberCheck {
  readonly missing: string[];
  readonly unknown: string[];
}

/** Which required members are absent and which members are not allowed. */
export function checkMembers(obj: JsonObject, required: readonly string[], optional: readonly string[] = []): MemberCheck {
  const allowed = new Set([...required, ...optional]);
  return {
    missing: required.filter((k) => !Object.hasOwn(obj, k)),
    unknown: Object.keys(obj).filter((k) => !allowed.has(k)),
  };
}

export function has(obj: JsonObject, key: string): boolean {
  return Object.hasOwn(obj, key);
}

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/**
 * The v4 UUID layout in canonical lowercase (RFC-AITP-0005 §2.2): version
 * nibble 4 and variant 10xx. Random and SHA-256-derived identifiers both
 * have this layout.
 */
export function isUuidV4(value: unknown): value is string {
  return typeof value === "string" && UUID_V4.test(value);
}

/** A JSON integer in the safe range, ≥ 0: the type of every AITP timestamp. */
export function isUnsignedInt(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

export function isString(value: unknown): value is string {
  return typeof value === "string";
}

export function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

export function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((v) => typeof v === "string");
}

/** An `extensions` / `ext` slot: any object, whose contents are ignored. */
export function isExtensionSlot(value: JsonValue | undefined): boolean {
  return isJsonObject(value);
}

/** A nonce or challenge: strict base64url of exactly `bytes` bytes. */
export function decodeNonce(value: unknown, bytes = 16): Uint8Array | undefined {
  return typeof value === "string" ? b64.decodeExact(value, bytes) : undefined;
}

/**
 * A SHA-256-derived identifier in the v4 layout (RFC-AITP-0005 §2.2):
 * the first 16 bytes of SHA-256(tag || 0x00 || input), with the version
 * nibble set to 4 and the variant bits to 10.
 */
export async function derivedUuid(tag: string, input: Uint8Array): Promise<string> {
  const d = (await sha256(concat(utf8(tag), new Uint8Array([0]), input))).slice(0, 16);
  d[6] = ((d[6] as number) & 0x0f) | 0x40;
  d[8] = ((d[8] as number) & 0x3f) | 0x80;
  const h = toHex(d);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
