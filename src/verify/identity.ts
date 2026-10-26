// Identity binding (RFC-AITP-0002), in the order RFC-AITP-0004 §5.1 step 6
// fixes: descriptor shape and Manifest-hint consistency, then the OIDC
// trust-anchor check before any key is resolved, then key resolution and
// proof verification. Every failure is IDENTITY_FAILED except an untrusted
// OIDC issuer, which is INCOMPATIBLE_TRUST_ANCHORS.
//
// The descriptor's `type` alone selects the verification path. A
// descriptor is never verified as pinned_key because it carries
// `public_key`, nor as OIDC because its proof looks like a JWT.

import { type Aid, aidIdentifier, sameKeyAid } from "../aid.js";
import * as b64 from "../b64.js";
import { AitpError } from "../errors.js";
import { type CompactJws, JwsFormatError, parseCompactJws, verifyJwsSignature, expectedAlg } from "../jws.js";
import { type JsonObject, isJsonObject } from "../json.js";
import { type PublicKey, publicKeyFromRaw } from "../keys.js";
import { jwkThumbprint } from "../jwk.js";
import { type HandshakeContext, pinnedKeyProofInput } from "../proofs.js";
import { parseSignatureField, verifyJcsPrimitive } from "../sigfield.js";
import { isUnsignedInt } from "../fields.js";
import { DEFAULT_TOLERANCE_SECS, isExpired, withinWindow } from "../timeutil.js";
import { SIGNATURE_PATTERN, fail, unknownMembers } from "./common.js";
import type { IdentityHint, IdentityType } from "./manifest.js";

const MEMBERS = ["type", "issuer", "subject", "proof", "public_key", "svid_type", "x5c", "extensions"];

export interface IdentityOptions {
  /** Reference time, Unix seconds. */
  readonly now: number;
  /** The verifying peer's own AID: the JWT `aud` and the pinned-key proof's receiver. */
  readonly selfAid: string;
  /** OIDC issuers this verifier trusts (`trust_anchors`). */
  readonly trustAnchors: readonly string[];
  /** The signing keys of a trusted OIDC issuer (RFC-AITP-0007). */
  readonly resolveIssuerKeys: (issuer: string) => readonly PublicKey[] | Promise<readonly PublicKey[]>;
  /** The local `pinned_keys` store; an empty store trusts no pinned key. */
  readonly pinnedKeys: readonly Aid[];
  /** JWT `iat` tolerance; default 300 s. */
  readonly toleranceSecs?: number;
}

/** What an identity binding establishes about the sender. */
export interface VerifiedIdentity {
  readonly type: IdentityType;
  readonly subject: string;
  readonly issuer?: string;
}

function identityFailed(message: string): never {
  return fail("IDENTITY_FAILED", message);
}

/** Check 1: the descriptor's members, by `type`, and the hint equalities. */
function checkDescriptor(identity: unknown, hint: IdentityHint, sender: Aid): JsonObject {
  if (!isJsonObject(identity)) identityFailed("identity is not an object");
  const unknown = unknownMembers(identity, MEMBERS);
  if (unknown.length > 0) fail("UNKNOWN_FIELD", `unknown identity member ${unknown[0]}`);
  const { type, issuer, subject, proof, public_key: publicKey, extensions } = identity;
  if (typeof subject !== "string" || subject.length === 0) identityFailed("identity.subject");
  if (typeof proof !== "string" || proof.length === 0) identityFailed("identity.proof");
  if (extensions !== undefined && !isJsonObject(extensions)) identityFailed("identity.extensions");
  if (publicKey !== undefined && (typeof publicKey !== "string" || !/^[A-Za-z0-9_-]{43,44}$/.test(publicKey))) {
    identityFailed("identity.public_key");
  }
  if ("svid_type" in identity || "x5c" in identity) {
    if (type !== "spiffe") identityFailed("svid_type and x5c belong to spiffe only");
  }
  if (type === "oidc") {
    if (typeof issuer !== "string" || issuer.length === 0) identityFailed("oidc identity needs issuer");
    if (publicKey !== undefined) identityFailed("public_key is forbidden on an oidc identity");
  } else if (type === "pinned_key") {
    if (publicKey === undefined) identityFailed("pinned_key identity needs public_key");
    if (issuer !== undefined) identityFailed("issuer is forbidden on a pinned_key identity");
    if (!SIGNATURE_PATTERN.test(proof)) identityFailed("pinned_key proof is not a signature field");
  } else if (type === "spiffe") {
    identityFailed("spiffe identities are not supported by this verifier");
  } else {
    identityFailed("unknown identity.type");
  }

  if (type !== hint.type) identityFailed("identity.type differs from the Manifest identity_hint");
  if (subject !== hint.subject) identityFailed("identity.subject differs from the Manifest identity_hint");
  if (type === "oidc" && issuer !== hint.issuer) identityFailed("identity.issuer differs from the Manifest identity_hint");
  if (type === "pinned_key") {
    if (publicKey !== hint.publicKey) identityFailed("identity.public_key differs from the Manifest identity_hint");
    if (publicKey !== aidIdentifier(sender)) identityFailed("identity.public_key is not the sender AID key");
  }
  return identity;
}

async function verifyOidc(identity: JsonObject, sender: Aid, popNonce: string, options: IdentityOptions): Promise<void> {
  const issuer = identity.issuer as string;
  // Check 2: never resolve keys for an issuer this verifier does not trust.
  if (!options.trustAnchors.includes(issuer)) fail("INCOMPATIBLE_TRUST_ANCHORS", "OIDC issuer is not a trust anchor");
  // Check 3, RFC-AITP-0002 §2.3.
  let jwt: CompactJws;
  try {
    jwt = parseCompactJws(identity.proof as string);
  } catch (e) {
    if (e instanceof JwsFormatError) identityFailed(`identity proof is not a JWT: ${e.message}`);
    throw e;
  }
  const keys = await options.resolveIssuerKeys(issuer);
  const alg = jwt.header.alg;
  let verified = false;
  for (const key of keys) {
    if (alg === expectedAlg(key.alg) && (await verifyJwsSignature(jwt, key))) {
      verified = true;
      break;
    }
  }
  if (!verified) identityFailed("JWT signature does not verify under the issuer's keys");
  const c = jwt.claims;
  if (c.iss !== issuer) identityFailed("JWT iss differs from identity.issuer");
  if (c.sub !== identity.subject) identityFailed("JWT sub differs from identity.subject");
  if (!isUnsignedInt(c.exp) || isExpired(c.exp, options.now)) identityFailed("JWT exp");
  if (!isUnsignedInt(c.iat) || !withinWindow(c.iat, options.now, options.toleranceSecs ?? DEFAULT_TOLERANCE_SECS)) {
    identityFailed("JWT iat outside the tolerance window");
  }
  if (typeof c.aud !== "string") identityFailed("JWT aud missing");
  if (c.aud !== options.selfAid) identityFailed("JWT aud is not this verifier");
  if (typeof c.nonce !== "string" || c.nonce !== popNonce) identityFailed("JWT nonce is not the handshake pop_nonce");
  const cnf = c.cnf;
  if (!isJsonObject(cnf) || typeof cnf.jkt !== "string") identityFailed("JWT cnf.jkt missing");
  if (cnf.jkt !== (await jwkThumbprint(sender.key))) identityFailed("JWT cnf.jkt does not bind the sender AID key");
}

async function verifyPinned(identity: JsonObject, context: HandshakeContext, sender: Aid, options: IdentityOptions): Promise<void> {
  // §3.2 steps 2 and 3 run before any signature work.
  const raw = b64.decodeExact(identity.public_key as string, sender.key.raw.length);
  const key = raw === undefined ? undefined : publicKeyFromRaw(sender.key.alg, raw);
  if (key === undefined || b64.encode(key.raw) !== b64.encode(sender.key.raw)) identityFailed("public_key is not the sender key");
  if (!options.pinnedKeys.some((p) => sameKeyAid(p, sender))) identityFailed("key is not in the pinned_keys store");
  // Steps 4 and 5. The tag must match the sender's algorithm (§3.1).
  const sig = parseSignatureField(identity.proof as string);
  if (sig === undefined || sig.alg !== sender.key.alg) identityFailed("proof algorithm differs from the sender's");
  if (!(await verifyJcsPrimitive(sender.key, pinnedKeyProofInput(context), sig.bytes))) identityFailed("pinned-key proof does not verify");
}

/**
 * RFC-AITP-0004 §5.1 step 6 for a sender whose Manifest has been
 * authenticated: `hint` is that Manifest's `identity_hint`, and `context`
 * gives the envelope fields the pinned-key proof binds.
 */
export async function verifyIdentity(
  identity: unknown,
  hint: IdentityHint,
  context: Omit<HandshakeContext, "receiverAid">,
  sender: Aid,
  options: IdentityOptions,
): Promise<VerifiedIdentity> {
  const d = checkDescriptor(identity, hint, sender);
  try {
    if (d.type === "oidc") await verifyOidc(d, sender, context.popNonce, options);
    else await verifyPinned(d, { ...context, receiverAid: options.selfAid }, sender, options);
  } catch (e) {
    if (e instanceof AitpError) throw e;
    identityFailed(`identity proof: ${(e as Error).message}`);
  }
  return {
    type: d.type as IdentityType,
    subject: d.subject as string,
    ...(d.type === "oidc" ? { issuer: d.issuer as string } : {}),
  };
}
