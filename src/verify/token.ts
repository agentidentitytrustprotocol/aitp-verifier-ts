// The compact-JWS steps every portable trust artifact shares
// (RFC-AITP-0001 §5.4.5): strict parse, explicit `typ`, the protected
// header pinned to exactly {alg, typ}, and `alg` derived from the signer's
// AID. Each artifact supplies its own codes, because the registry gives
// each one its own structural-rejection code.

import type { Aid } from "../aid.js";
import type { ErrorCode } from "../errors.js";
import { type CompactJws, JwsFormatError, expectedAlg, parseCompactJws, verifyJwsSignature } from "../jws.js";
import type { JsonObject } from "../json.js";
import type { PublicKey } from "../keys.js";
import { aidOf, fail } from "./common.js";

export interface TokenCodes {
  /** Malformed serialization, header or claims. */
  readonly structural: ErrorCode;
  /** A signature that does not verify. */
  readonly signature: ErrorCode;
}

/** Parse a compact JWS and enforce `typ` (§5.4.5 rules 1–2). */
export function parseToken(token: unknown, typ: string, codes: TokenCodes): CompactJws {
  if (typeof token !== "string") fail(codes.structural, "token is not a string");
  let jws: CompactJws;
  try {
    jws = parseCompactJws(token);
  } catch (e) {
    if (e instanceof JwsFormatError) fail(codes.structural, e.message);
    throw e;
  }
  if (jws.header.typ !== typ) fail("TOKEN_TYP_MISMATCH", `typ is not ${typ}`);
  const keys = Object.keys(jws.header);
  if (keys.length !== 2 || typeof jws.header.alg !== "string") fail(codes.structural, "protected header is not exactly {alg, typ}");
  return jws;
}

/** The signer AID named by a claim, or a structural rejection. */
export function signerAid(claims: JsonObject, claim: string, codes: TokenCodes): Aid {
  const aid = aidOf(claims[claim]);
  if (aid === undefined) fail(codes.structural, `${claim} is not a valid AID`);
  return aid;
}

/** Pin `alg` to the signer's AID (rule 3), then verify under `key`. */
export async function checkTokenSignature(jws: CompactJws, signer: Aid, key: PublicKey, codes: TokenCodes): Promise<void> {
  if (jws.header.alg !== expectedAlg(signer.key.alg)) fail("TOKEN_ALG_MISMATCH", `alg must be ${expectedAlg(signer.key.alg)}`);
  if (key.alg !== signer.key.alg || !(await verifyJwsSignature(jws, key))) fail(codes.signature, "signature does not verify");
}
