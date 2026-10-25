// Grant vouchers (RFC-AITP-0005 §8) and single-hop delegation tokens
// (RFC-AITP-0006 §4). Both are verified by A, the original TCT issuer: the
// voucher under A's own key, the delegation token under the delegator B's
// Manifest key.

import { type Aid, sameKeyAid } from "../aid.js";
import type { CompactJws } from "../jws.js";
import { type JsonObject, isJsonObject } from "../json.js";
import type { PublicKey } from "../keys.js";
import { jwkThumbprint } from "../jwk.js";
import { isUnsignedInt, isUuidV4 } from "../fields.js";
import { isExpired } from "../timeutil.js";
import { PROTOCOL_VERSION, aidOf, fail, isCapability, unknownMembers } from "./common.js";
import { type TokenCodes, checkTokenSignature, parseToken, signerAid } from "./token.js";

export const VOUCHER_TYP = "aitp-grant+jwt";
export const DELEGATION_TYP = "aitp-delegation+jwt";

const VOUCHER_CLAIMS = ["ver", "iss", "sub", "grants", "iat", "exp", "src_jti"];
const DELEGATION_CLAIMS = ["ver", "iss", "sub", "aud", "scope", "exp", "cnf", "voucher"];
const VOUCHER_CODES: TokenCodes = { structural: "DELEGATION_INVALID_VOUCHER", signature: "DELEGATION_INVALID_VOUCHER" };
const DELEGATION_CODES: TokenCodes = { structural: "DELEGATION_INVALID_SIGNATURE", signature: "DELEGATION_INVALID_SIGNATURE" };

function isGrantList(value: unknown): value is string[] {
  return Array.isArray(value) && value.length > 0 && value.every(isCapability);
}

export interface VerifiedVoucher {
  readonly iss: Aid;
  readonly sub: Aid;
  readonly grants: readonly string[];
  readonly iat: number;
  readonly exp: number;
  readonly srcJti: string;
}

function parseVoucherClaims(jws: CompactJws): VerifiedVoucher & { claims: JsonObject } {
  const c = jws.claims;
  const unknown = unknownMembers(c, [...VOUCHER_CLAIMS, "ext"]);
  if (unknown.length > 0) fail("UNKNOWN_FIELD", `unknown voucher claim ${unknown[0]}`);
  for (const k of VOUCHER_CLAIMS) if (!(k in c)) fail("DELEGATION_INVALID_VOUCHER", `voucher claim ${k} missing`);
  const iss = signerAid(c, "iss", VOUCHER_CODES);
  const sub = aidOf(c.sub);
  if (sub === undefined) fail("DELEGATION_INVALID_VOUCHER", "voucher sub is not an AID");
  if (typeof c.ver !== "string" || !isGrantList(c.grants) || !isUnsignedInt(c.iat) || !isUnsignedInt(c.exp)) {
    fail("DELEGATION_INVALID_VOUCHER", "malformed voucher claims");
  }
  if (!isUuidV4(c.src_jti)) fail("DELEGATION_INVALID_VOUCHER", "voucher src_jti is not in the UUID v4 layout");
  if (c.ext !== undefined && !isJsonObject(c.ext)) fail("DELEGATION_INVALID_VOUCHER", "voucher ext");
  return { iss, sub, grants: c.grants, iat: c.iat, exp: c.exp, srcJti: c.src_jti, claims: c };
}

export interface VoucherOptions {
  /** The verifier's own AID: a voucher is only ever checked by its issuer. */
  readonly selfAid: Aid;
  readonly now: number;
}

/**
 * The voucher checks of RFC-AITP-0006 §4 steps 3 and 5 (voucher half):
 * `typ`, own issuer, own-key signature, expiry. Expiry is
 * DELEGATION_EXPIRED: a voucher is only verified in delegation context.
 */
export async function verifyVoucher(token: unknown, options: VoucherOptions): Promise<VerifiedVoucher> {
  const jws = parseToken(token, VOUCHER_TYP, VOUCHER_CODES);
  const v = parseVoucherClaims(jws);
  if (!sameKeyAid(v.iss, options.selfAid)) fail("DELEGATION_INVALID_VOUCHER", "voucher was not issued by this verifier");
  await checkTokenSignature(jws, v.iss, options.selfAid.key, VOUCHER_CODES);
  if (v.claims.ver !== PROTOCOL_VERSION) fail("UNKNOWN_VERSION", "unsupported voucher ver");
  if (isExpired(v.exp, options.now)) fail("DELEGATION_EXPIRED", "voucher exp has passed");
  return { iss: v.iss, sub: v.sub, grants: v.grants, iat: v.iat, exp: v.exp, srcJti: v.srcJti };
}

export interface VerifiedDelegation {
  readonly iss: Aid;
  readonly sub: Aid;
  readonly scope: readonly string[];
  readonly exp: number;
  readonly voucher: VerifiedVoucher;
}

export interface DelegationOptions {
  /** A: the verifier, the voucher's issuer and the token's audience. */
  readonly selfAid: Aid;
  readonly now: number;
  /** B's key from B's Manifest (§4 step 1); `undefined` when no Manifest designates one. */
  readonly resolveDelegatorKey: (iss: Aid) => PublicKey | undefined | Promise<PublicKey | undefined>;
  /**
   * §4 step 7, A's own deny list. Returns whether `srcJti` is revoked;
   * throws an AitpError with the snapshot's own code when A's list is a
   * signed snapshot that fails verification.
   */
  readonly isSourceRevoked: (srcJti: string) => boolean | Promise<boolean>;
  /**
   * §4 step 9. A function runs the downstream PoP exchange against `sub`
   * and throws on failure; "channel-bound" declares that an equivalent
   * channel binding to the `sub` key is already in place.
   */
  readonly confirmPossession: "channel-bound" | ((sub: Aid, jkt: string) => Promise<void>);
}

/** RFC-AITP-0006 §4, steps 1–9 in order, with the multi-hop guard first. */
export async function verifyDelegation(token: unknown, options: DelegationOptions): Promise<VerifiedDelegation> {
  // 1. Outer token.
  const jws = parseToken(token, DELEGATION_TYP, DELEGATION_CODES);
  const c = jws.claims;
  if ("chain" in c) fail("DELEGATION_MULTIHOP_NOT_SUPPORTED", "multi-hop delegation (RFC-AITP-0011) is not supported");
  const unknown = unknownMembers(c, [...DELEGATION_CLAIMS, "ext"]);
  if (unknown.length > 0) fail("UNKNOWN_FIELD", `unknown delegation claim ${unknown[0]}`);
  for (const k of DELEGATION_CLAIMS) if (!(k in c)) fail("DELEGATION_INVALID_SIGNATURE", `delegation claim ${k} missing`);
  const iss = signerAid(c, "iss", DELEGATION_CODES);
  const sub = aidOf(c.sub);
  const cnf = c.cnf;
  if (
    sub === undefined ||
    typeof c.ver !== "string" ||
    typeof c.aud !== "string" ||
    !isGrantList(c.scope) ||
    !isUnsignedInt(c.exp) ||
    typeof c.voucher !== "string" ||
    !isJsonObject(cnf) ||
    Object.keys(cnf).length !== 1 ||
    typeof cnf.jkt !== "string" ||
    (c.ext !== undefined && !isJsonObject(c.ext))
  ) {
    fail("DELEGATION_INVALID_SIGNATURE", "malformed delegation claims");
  }
  const key = await options.resolveDelegatorKey(iss);
  if (key === undefined) fail("KEY_RESOLUTION_FAILED", "no Manifest designates the delegator's key");
  await checkTokenSignature(jws, iss, key, DELEGATION_CODES);
  if (c.ver !== PROTOCOL_VERSION) fail("UNKNOWN_VERSION", "unsupported delegation ver");
  if (cnf.jkt !== (await jwkThumbprint(sub.key))) fail("DELEGATION_INVALID_SIGNATURE", "cnf.jkt does not bind the sub key");

  // 2. Addressing and freshness.
  if (c.aud !== options.selfAid.text) fail("DELEGATION_AUDIENCE_MISMATCH", "aud is not this verifier");
  if (isExpired(c.exp, options.now)) fail("DELEGATION_EXPIRED", "delegation exp has passed");

  // 3. Embedded voucher, under A's own key.
  const vjws = parseToken(c.voucher, VOUCHER_TYP, VOUCHER_CODES);
  const v = parseVoucherClaims(vjws);
  if (!sameKeyAid(v.iss, options.selfAid)) fail("DELEGATION_INVALID_VOUCHER", "voucher was not issued by this verifier");
  await checkTokenSignature(vjws, v.iss, options.selfAid.key, VOUCHER_CODES);
  if (v.claims.ver !== PROTOCOL_VERSION) fail("UNKNOWN_VERSION", "unsupported voucher ver");

  // 4. The delegator held the grant.
  if (v.sub.text !== iss.text) fail("DELEGATION_INVALID_VOUCHER", "voucher sub is not the delegator");

  // 5. Expiry monotonicity.
  if (isExpired(v.exp, options.now) || c.exp > v.exp) fail("DELEGATION_EXPIRED", "delegation outlives its voucher");

  // 6. Scope.
  const scope = c.scope as string[];
  if (!scope.every((s) => v.grants.includes(s))) fail("DELEGATION_SCOPE_EXCEEDED", "scope exceeds the voucher grants");

  // 7. Source TCT revocation, after every signature check.
  if (await options.isSourceRevoked(v.srcJti)) fail("DELEGATION_SOURCE_TCT_REVOKED", "source TCT is revoked");

  // 8. No self-delegation.
  if (sameKeyAid(iss, sub)) fail("DELEGATION_INVALID_SIGNATURE", "self-delegation");

  // 9. Proof of possession.
  if (options.confirmPossession !== "channel-bound") {
    try {
      await options.confirmPossession(sub, cnf.jkt);
    } catch {
      fail("DELEGATION_POP_FAILED", "delegatee did not prove possession of the sub key");
    }
  }

  const voucher = { iss: v.iss, sub: v.sub, grants: v.grants, iat: v.iat, exp: v.exp, srcJti: v.srcJti };
  return { iss, sub, scope, exp: c.exp, voucher };
}
