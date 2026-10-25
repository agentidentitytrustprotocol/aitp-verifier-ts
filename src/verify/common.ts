// Shared pieces of the verification functions: the error helper, the
// grammars several artifacts reuse, and key lookup from an AID.

import { type Aid, parseAid } from "../aid.js";
import { AitpError, type ErrorCode } from "../errors.js";
import type { JsonObject } from "../json.js";

/** Reject with exactly one registry code. */
export function fail(code: ErrorCode, message: string = code): never {
  throw new AitpError(code, message);
}

/** The protocol revision this verifier implements (RFC-AITP-0001 §5.1). */
export const PROTOCOL_VERSION = "aitp/0.3";

/** RFC-AITP-0001 §5.3 AID grammar, as every schema spells it. */
export const AID_PATTERN = /^aid:pubkey:([A-Za-z0-9_-]{43}|ed25519:[A-Za-z0-9_-]{43}|p256:[A-Za-z0-9_-]{44})$/;

/** RFC-AITP-0001 §5.4.3 JCS-profile signature field grammar. */
export const SIGNATURE_PATTERN = /^((ed25519|p256)\.)?[A-Za-z0-9_-]{86}$/;

/** A 128-bit nonce or challenge: 22 unpadded base64url characters. */
export const NONCE_PATTERN = /^[A-Za-z0-9_-]{22}$/;

/**
 * An AID that matches the grammar and decodes to a valid key, or
 * `undefined`. Grammar first, so a string the schema rejects is never
 * handed to the decoder.
 */
export function aidOf(value: unknown): Aid | undefined {
  return typeof value === "string" && AID_PATTERN.test(value) ? parseAid(value) : undefined;
}

/** A capability string: non-empty, no whitespace (RFC-AITP-0005 §4.2). */
export function isCapability(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && !/\s/u.test(value);
}

export function isUniqueStrings(value: unknown, item: (v: unknown) => boolean = (v) => typeof v === "string"): value is string[] {
  return Array.isArray(value) && value.every(item) && new Set(value).size === value.length;
}

/** The members of `obj` outside `allowed`. */
export function unknownMembers(obj: JsonObject, allowed: readonly string[]): string[] {
  const set = new Set(allowed);
  return Object.keys(obj).filter((k) => !set.has(k));
}
