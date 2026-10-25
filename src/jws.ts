// The compact JWS profile of the portable trust artifacts (RFC-AITP-0001
// §5.4.5), written from RFC 7515 and that section. No JOSE library: the
// profile is small and stricter than general JOSE in every direction.
//
// `parseCompactJws` does only the structural part (three non-empty strict
// base64url segments, header and payload JSON objects without duplicate
// keys). Each artifact decides the order of the remaining checks and the
// code each failure carries (the TCT order is RFC-AITP-0005 §7.2), so the
// pieces are separate: `headerProblem`, `expectedAlg` and `verifyJwsSignature`.

import * as b64 from "./b64.js";
import { utf8 } from "./bytes.js";
import { type JsonObject, parseJsonObjectBytes } from "./json.js";
import { type Alg, type PublicKey, type PrivateKey, signRaw, verifyRaw } from "./keys.js";
import { canonicalBytes } from "./jcs.js";

export type JwsAlg = "EdDSA" | "ES256";

export interface CompactJws {
  readonly header: JsonObject;
  readonly claims: JsonObject;
  /** ASCII(header "." payload): the exact bytes the signature covers. */
  readonly signingInput: Uint8Array;
  readonly signature: Uint8Array;
}

export class JwsFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JwsFormatError";
  }
}

export function parseCompactJws(token: string): CompactJws {
  const parts = token.split(".");
  if (parts.length !== 3) throw new JwsFormatError("a compact JWS has exactly three segments");
  const [h, p, s] = parts as [string, string, string];
  if (h === "" || p === "" || s === "") throw new JwsFormatError("empty JWS segment");
  const hb = b64.tryDecode(h);
  const pb = b64.tryDecode(p);
  const sb = b64.tryDecode(s);
  if (hb === undefined || pb === undefined || sb === undefined) {
    throw new JwsFormatError("JWS segment is not unpadded base64url");
  }
  let header: JsonObject;
  let claims: JsonObject;
  try {
    header = parseJsonObjectBytes(hb);
  } catch (e) {
    throw new JwsFormatError(`protected header: ${(e as Error).message}`);
  }
  try {
    claims = parseJsonObjectBytes(pb);
  } catch (e) {
    throw new JwsFormatError(`payload: ${(e as Error).message}`);
  }
  return { header, claims, signingInput: utf8(`${h}.${p}`), signature: sb };
}

/** The sole `alg` a signer's key admits (§5.4.5 algorithm pinning). */
export function expectedAlg(alg: Alg): JwsAlg {
  return alg === "ed25519" ? "EdDSA" : "ES256";
}

export type HeaderProblem = "members" | "typ" | "alg";

/**
 * The first §5.4.5 header defect, in the order members → typ → alg, or
 * `undefined`. `members` is any header that is not exactly {alg, typ} with
 * string values.
 */
export function headerProblem(header: JsonObject, typ: string, alg: JwsAlg): HeaderProblem | undefined {
  const keys = Object.keys(header);
  if (keys.length !== 2 || typeof header.alg !== "string" || typeof header.typ !== "string") return "members";
  if (header.typ !== typ) return "typ";
  if (header.alg !== alg) return "alg";
  return undefined;
}

/**
 * Verify the JWS signature under `key`. EdDSA signs the ASCII signing input
 * directly (RFC 8037); ES256 is ECDSA-SHA256 over it with a raw 64-byte
 * R || S (RFC 7518 §3.4), held to the §5.4.7 low-S rule.
 */
export function verifyJwsSignature(jws: CompactJws, key: PublicKey): Promise<boolean> {
  return verifyRaw(key, jws.signingInput, jws.signature);
}

/**
 * Mint a compact JWS with the signed-examples conventions: header exactly
 * {"alg","typ"} in that order, payload the JCS form of the claims.
 */
export async function signCompactJws(key: PrivateKey, typ: string, claims: JsonObject): Promise<string> {
  const header = b64.encode(utf8(JSON.stringify({ alg: expectedAlg(key.alg), typ })));
  const payload = b64.encode(canonicalBytes(claims));
  const sig = await signRaw(key, utf8(`${header}.${payload}`));
  return `${header}.${payload}.${b64.encode(sig)}`;
}
