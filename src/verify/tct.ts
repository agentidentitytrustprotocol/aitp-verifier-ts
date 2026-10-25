// Trust Context Token verification (RFC-AITP-0005 §7.2), holder side
// (§5.2) and issuer side (§10.5).
//
// Execution order, as §7.2 step 1's note fixes it: segment parse, `typ`,
// claims membership and structure (jti layout included), `alg` pin,
// signature, claims, then revocation. Revocation runs through a callback
// that is never reached unless every earlier check passed (RFC-AITP-0008
// §3.3), so a caller can put a network fetch behind it.

import { type Aid, sameKeyAid } from "../aid.js";
import type { CompactJws } from "../jws.js";
import { type JsonObject, isJsonObject } from "../json.js";
import type { PublicKey } from "../keys.js";
import { jwkThumbprint } from "../jwk.js";
import { isUnsignedInt, isUuidV4 } from "../fields.js";
import { isExpired } from "../timeutil.js";
import { PROTOCOL_VERSION, aidOf, fail, isCapability, unknownMembers } from "./common.js";
import { type RevocationMode, type RevocationStatus, DEFAULT_REVOCATION_MODE, decideRevocation } from "./revocation.js";
import { type TokenCodes, checkTokenSignature, parseToken } from "./token.js";

export const TCT_TYP = "aitp-tct+jwt";
export const ATTESTATION_GRANT = "aitp.attestation";

const CLAIMS = ["ver", "jti", "iss", "sub", "aud", "iat", "exp", "grants", "cnf"];
const CODES: TokenCodes = { structural: "TCT_SIGNATURE_INVALID", signature: "TCT_SIGNATURE_INVALID" };

export interface TctClaims {
  readonly jti: string;
  readonly iss: Aid;
  readonly sub: Aid;
  readonly aud: string;
  readonly iat: number;
  readonly exp: number;
  readonly grants: readonly string[];
  readonly jkt: string;
  readonly claims: JsonObject;
}

/** A revocation lookup for a verified (`iss`, `jti`). */
export type RevocationLookup = (issuer: Aid, jti: string) => Promise<RevocationStatus> | RevocationStatus;

export interface TctOptions {
  /** Reference time, Unix seconds. */
  readonly now: number;
  /**
   * Holder side: the verifier's own AID, which `aud` and `sub` must equal.
   * Omit only where the caller checks the audience itself.
   */
  readonly expectedAudience?: string;
  /**
   * The issuer key from its Manifest (§7.3). Defaults to the key encoded in
   * `iss`; when given it must be that same key.
   */
  readonly issuerKey?: PublicKey;
  /** The issuer Manifest's `expires_at`, when it is available (§10.4). */
  readonly issuerManifestExpiresAt?: number;
  /** Revocation lookup; absent means revocation is not checked here. */
  readonly revocation?: RevocationLookup;
  /** Mode applied to an unknown revocation status; default fail_closed. */
  readonly revocationMode?: RevocationMode;
}

export interface VerifiedTct extends TctClaims {
  /** True when admitted under soft_fail with revocation status unknown. */
  readonly degraded: boolean;
}

/** Steps 1 and 2: parse, `typ`, then claims membership and structure. */
export function parseTct(token: unknown): { jws: CompactJws; tct: TctClaims } {
  const jws = parseToken(token, TCT_TYP, CODES);
  const c = jws.claims;
  const unknown = unknownMembers(c, [...CLAIMS, "ext"]);
  if (unknown.length > 0) fail("UNKNOWN_FIELD", `unknown claim ${unknown[0]}`);
  for (const k of CLAIMS) if (!(k in c)) fail("TCT_SIGNATURE_INVALID", `missing claim ${k}`);
  if (!isUuidV4(c.jti)) fail("TCT_SIGNATURE_INVALID", "jti is not in the UUID v4 layout");
  if (typeof c.ver !== "string") fail("TCT_SIGNATURE_INVALID", "ver");
  const iss = aidOf(c.iss);
  const sub = aidOf(c.sub);
  if (iss === undefined || sub === undefined) fail("TCT_SIGNATURE_INVALID", "iss and sub must be AIDs");
  if (typeof c.aud !== "string") fail("TCT_SIGNATURE_INVALID", "aud must be a single AID string");
  if (!isUnsignedInt(c.iat) || !isUnsignedInt(c.exp)) fail("TCT_SIGNATURE_INVALID", "iat and exp must be Unix seconds");
  if (!Array.isArray(c.grants) || c.grants.length === 0 || !c.grants.every(isCapability)) {
    fail("TCT_SIGNATURE_INVALID", "grants must be a non-empty array of capabilities");
  }
  const cnf = c.cnf;
  if (!isJsonObject(cnf) || Object.keys(cnf).length !== 1 || typeof cnf.jkt !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(cnf.jkt)) {
    fail("TCT_SIGNATURE_INVALID", "cnf must be exactly {jkt}");
  }
  if (c.ext !== undefined && !isJsonObject(c.ext)) fail("TCT_SIGNATURE_INVALID", "ext must be an object");
  return {
    jws,
    tct: { jti: c.jti, iss, sub, aud: c.aud, iat: c.iat, exp: c.exp, grants: c.grants as string[], jkt: cnf.jkt, claims: c },
  };
}

/** Steps 3 and 4 under the issuer key. */
async function checkSignature(jws: CompactJws, tct: TctClaims, issuerKey: PublicKey | undefined): Promise<void> {
  const key = issuerKey ?? tct.iss.key;
  await checkTokenSignature(jws, tct.iss, key, CODES);
}

/** Step 5's checks shared by both sides, grant-context rules included. */
async function checkClaims(tct: TctClaims, options: TctOptions): Promise<void> {
  if (tct.claims.ver !== PROTOCOL_VERSION) fail("UNKNOWN_VERSION", "unsupported TCT ver");
  if (options.expectedAudience !== undefined) {
    if (tct.aud !== options.expectedAudience) fail("AUDIENCE_MISMATCH", "aud is not this verifier");
    if (tct.sub.text !== options.expectedAudience) fail("AUDIENCE_MISMATCH", "sub is not this verifier");
  }
  if (tct.aud !== tct.sub.text) fail("TCT_SIGNATURE_INVALID", "aud must equal sub");
  if (isExpired(tct.exp, options.now)) fail("TCT_EXPIRED", "TCT exp has passed");
  if (tct.jkt !== (await jwkThumbprint(tct.sub.key))) fail("TCT_SIGNATURE_INVALID", "cnf.jkt does not bind the sub key");
  if (sameKeyAid(tct.iss, tct.sub)) fail("TCT_SIGNATURE_INVALID", "self-issued TCT in a grant context");
  if (tct.grants.includes(ATTESTATION_GRANT)) fail("TCT_SIGNATURE_INVALID", "attestation marker in a grant context");
  if (options.issuerManifestExpiresAt !== undefined && tct.exp > options.issuerManifestExpiresAt) {
    fail("TCT_EXPIRES_AFTER_MANIFEST", "TCT outlives its issuer's Manifest");
  }
}

/** Step 6. */
async function checkRevocation(tct: TctClaims, options: TctOptions): Promise<boolean> {
  if (options.revocation === undefined) return false;
  const status = await options.revocation(tct.iss, tct.jti);
  const d = decideRevocation(status, options.revocationMode ?? DEFAULT_REVOCATION_MODE);
  if (!d.allowed) fail("TCT_REVOKED", status === "revoked" ? "TCT is revoked" : "revocation status unknown (fail_closed)");
  return d.degraded;
}

/** Holder-side verification (§7.2 with the §5.2 audience rule). */
export async function verifyTct(token: unknown, options: TctOptions): Promise<VerifiedTct> {
  const { jws, tct } = parseTct(token);
  if (options.issuerKey !== undefined && options.issuerKey.alg !== tct.iss.key.alg) {
    fail("TOKEN_ALG_MISMATCH", "issuer key algorithm differs from the iss AID");
  }
  await checkSignature(jws, tct, options.issuerKey);
  await checkClaims(tct, options);
  const degraded = await checkRevocation(tct, options);
  return { ...tct, degraded };
}

export interface IssuerSideOptions extends Omit<TctOptions, "expectedAudience" | "issuerKey"> {
  /** The verifier's own AID: the TCT's issuer. */
  readonly selfAid: Aid;
  /**
   * Establishes the presenter's AID from an authenticated source (§10.5
   * item 3), throwing POP_RESPONSE_INVALID or POP_CHALLENGE_INVALID when it
   * cannot. Called after §7.2 steps 1–5.
   */
  readonly establishPresenter: (tct: TctClaims) => Promise<Aid>;
}

/** Issuer-side verification of a TCT presented back to its issuer (§10.5). */
export async function verifyTctAsIssuer(token: unknown, options: IssuerSideOptions): Promise<VerifiedTct> {
  const { jws, tct } = parseTct(token);
  if (!sameKeyAid(tct.iss, options.selfAid)) fail("TCT_SIGNATURE_INVALID", "TCT was not issued by this verifier");
  await checkSignature(jws, tct, options.selfAid.key);
  await checkClaims(tct, options);
  const presenter = await options.establishPresenter(tct);
  if (presenter.text !== tct.sub.text || presenter.text !== tct.aud) fail("POP_RESPONSE_INVALID", "presenter is not sub and aud");
  const degraded = await checkRevocation(tct, options);
  return { ...tct, degraded };
}
