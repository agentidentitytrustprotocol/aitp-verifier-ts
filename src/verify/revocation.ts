// Signed revocation snapshots and the revocation policy (RFC-AITP-0008).
//
// `verifySnapshot` reports what is wrong with a snapshot itself, with the
// snapshot's own codes (§1.5). A token decision never sees those codes: a
// snapshot that fails any check is discarded, a discarded snapshot is
// absent, and absence is resolved by the configured mode (§3.1), whose
// default is fail_closed.

import { type Aid, sameKeyAid } from "../aid.js";
import { canonicalBytes } from "../jcs.js";
import { isJsonObject } from "../json.js";
import type { PublicKey } from "../keys.js";
import { verifyJcsSignature } from "../sigfield.js";
import { isUnsignedInt, isUuidV4 } from "../fields.js";
import { isExpired } from "../timeutil.js";
import { AitpError } from "../errors.js";
import { PROTOCOL_VERSION, SIGNATURE_PATTERN, aidOf, fail, unknownMembers } from "./common.js";

export type RevocationMode = "fail_closed" | "fail_open" | "soft_fail";

export const DEFAULT_REVOCATION_MODE: RevocationMode = "fail_closed";

export interface RevocationPolicy {
  /** Default fail_closed (§3.1). */
  readonly mode?: RevocationMode;
  /** Maximum age of a snapshot, from its `published_at`; unbounded when absent (§3.2). */
  readonly maxStalenessSecs?: number;
}

export interface RevocationEntry {
  readonly jti: string;
  readonly revokedAt: number;
}

export interface VerifiedSnapshot {
  readonly issuer: Aid;
  readonly publishedAt: number;
  readonly expiresAt: number;
  readonly entries: readonly RevocationEntry[];
}

const BODY_REQUIRED = ["version", "issuer", "published_at", "expires_at", "entries"];

function invalid(message: string): never {
  return fail("REVOCATION_SNAPSHOT_INVALID", message);
}

/**
 * §1.5 verification of a `{revocation_list, signature}` snapshot: schema,
 * member set, then the signature over JCS(revocation_list) under `key`, the
 * issuing peer's key.
 */
export async function verifySnapshot(snapshot: unknown, key: PublicKey): Promise<VerifiedSnapshot> {
  if (!isJsonObject(snapshot)) invalid("snapshot is not an object");
  const { revocation_list: body, signature } = snapshot;
  if (!isJsonObject(body)) invalid("revocation_list is not an object");
  if (typeof signature !== "string" || !SIGNATURE_PATTERN.test(signature)) invalid("signature");
  for (const k of BODY_REQUIRED) if (!(k in body)) invalid(`missing revocation_list.${k}`);
  if (body.version !== PROTOCOL_VERSION) invalid("revocation_list.version");
  const issuer = aidOf(body.issuer);
  if (issuer === undefined) invalid("revocation_list.issuer");
  if (!isUnsignedInt(body.published_at)) invalid("revocation_list.published_at");
  if (!isUnsignedInt(body.expires_at) || body.expires_at < 1) invalid("revocation_list.expires_at");
  if (body.extensions !== undefined && !isJsonObject(body.extensions)) invalid("revocation_list.extensions");
  if (!Array.isArray(body.entries)) invalid("revocation_list.entries");
  const entries: RevocationEntry[] = [];
  const unknown = [
    ...unknownMembers(snapshot, ["revocation_list", "signature"]),
    ...unknownMembers(body, [...BODY_REQUIRED, "extensions"]).map((k) => `revocation_list.${k}`),
  ];
  for (const e of body.entries) {
    if (!isJsonObject(e) || !isUuidV4(e.jti) || !isUnsignedInt(e.revoked_at)) invalid("revocation_list.entries[]");
    if (e.reason !== undefined && typeof e.reason !== "string") invalid("revocation_list.entries[].reason");
    unknown.push(...unknownMembers(e, ["jti", "revoked_at", "reason"]).map((k) => `entries[].${k}`));
    entries.push({ jti: e.jti, revokedAt: e.revoked_at });
  }
  if (unknown.length > 0) fail("UNKNOWN_FIELD", `unknown member ${unknown[0]}`);
  const r = await verifyJcsSignature(key, canonicalBytes(body), signature);
  if (r !== "ok") fail("REVOCATION_SNAPSHOT_SIGNATURE_INVALID", `snapshot signature: ${r}`);
  return { issuer, publishedAt: body.published_at, expiresAt: body.expires_at, entries };
}

/** What a revocation lookup established about one token. */
export type RevocationStatus = "revoked" | "not_revoked" | "unknown";

/**
 * Look up `jti` in a snapshot obtained for `issuer`. Any reason to discard
 * the snapshot (§1.5: invalid, unknown member, bad signature, expired,
 * stale, or signed by another issuer) makes the status unknown.
 */
export async function snapshotStatus(
  snapshot: unknown,
  issuer: Aid,
  jti: string,
  now: number,
  policy: RevocationPolicy = {},
): Promise<RevocationStatus> {
  let v: VerifiedSnapshot;
  try {
    v = await verifySnapshot(snapshot, issuer.key);
  } catch (e) {
    if (e instanceof AitpError) return "unknown";
    throw e;
  }
  if (!sameKeyAid(v.issuer, issuer)) return "unknown";
  if (isExpired(v.expiresAt, now)) return "unknown";
  if (policy.maxStalenessSecs !== undefined && now - v.publishedAt > policy.maxStalenessSecs) return "unknown";
  return v.entries.some((e) => e.jti === jti) ? "revoked" : "not_revoked";
}

/** The outcome of applying the mode to a status. */
export interface RevocationDecision {
  /** True when the token may be used. */
  readonly allowed: boolean;
  /** True when allowed only under soft_fail, with restricted grants. */
  readonly degraded: boolean;
}

/** §3.1: revoked always rejects; unknown follows the mode. */
export function decideRevocation(status: RevocationStatus, mode: RevocationMode = DEFAULT_REVOCATION_MODE): RevocationDecision {
  if (status === "revoked") return { allowed: false, degraded: false };
  if (status === "not_revoked") return { allowed: true, degraded: false };
  if (mode === "fail_closed") return { allowed: false, degraded: false };
  return { allowed: true, degraded: mode === "soft_fail" };
}
