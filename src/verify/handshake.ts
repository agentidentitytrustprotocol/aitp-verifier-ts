// Mutual Handshake receive-side verification (RFC-AITP-0004 §5).
//
// Round 1 (MUTUAL_HELLO, MUTUAL_HELLO_ACK) bootstraps the sender's key from
// its inline Manifest, so no cryptographic step uses the key before the
// Manifest's proof of possession has verified (§5.1 steps 1–8). Round 2
// (MUTUAL_COMMIT, MUTUAL_COMMIT_ACK) relies on that Manifest: envelope
// signature, member set, nonce echo, PoP signature, then the TCT
// (§5.3, §5.4).

import type { Aid } from "../aid.js";
import * as b64 from "../b64.js";
import { type JsonObject, isJsonObject } from "../json.js";
import { verifyJcsSignature } from "../sigfield.js";
import { NONCE_PATTERN, fail, isCapability, unknownMembers } from "./common.js";
import { type EnvelopeOptions, type VerifiedEnvelope, checkEnvelope, checkEnvelopeSignature, recordEnvelope } from "./envelope.js";
import { type IdentityOptions, type VerifiedIdentity, verifyIdentity } from "./identity.js";
import { type IdentityType, type ParsedManifest, checkManifestPop, checkManifestSignature, parseManifest } from "./manifest.js";
import { type VerifiedTct, verifyTct } from "./tct.js";
import { isExpired } from "../timeutil.js";

const HELLO_MEMBERS = ["identity", "manifest", "requested_grants", "pop_nonce"];
const COMMIT_MEMBERS = ["tct", "pop_signature", "pop_nonce_echo"];

function isNonceString(value: unknown): value is string {
  return typeof value === "string" && NONCE_PATTERN.test(value) && b64.decodeExact(value, 16) !== undefined;
}

function checkPayloadMembers(payload: JsonObject, required: readonly string[], optional: readonly string[]): void {
  const unknown = unknownMembers(payload, [...required, ...optional, "extensions"]);
  if (unknown.length > 0) fail("UNKNOWN_FIELD", `unknown payload member ${unknown[0]}`);
  for (const k of required) if (!(k in payload)) fail("INVALID_ENVELOPE", `payload.${k} missing`);
  if (payload.extensions !== undefined && !isJsonObject(payload.extensions)) fail("INVALID_ENVELOPE", "payload.extensions");
}

export interface HelloOptions extends EnvelopeOptions, Omit<IdentityOptions, "now" | "toleranceSecs"> {
  /**
   * Step 8: this receiver's own `accepted_identity_types`. Absent means
   * step 8 is not run here, for a caller that checks only the identity
   * binding; pass `["oidc"]` for the protocol default.
   */
  readonly acceptedIdentityTypes?: readonly IdentityType[];
}

export interface HelloAckOptions extends HelloOptions {
  /** The `pop_nonce` this peer sent in its MUTUAL_HELLO (§5.2 step 9). */
  readonly sentPopNonce: string;
  /**
   * The AID this peer addressed in its MUTUAL_HELLO: the intended peer
   * (RFC-AITP-0004 §2). The ACK's sender must be this AID (§5.2 step 3,
   * `PEER_MISMATCH`). Take it from the Manifest you fetched, never from
   * the ACK.
   */
  readonly peerAid: string;
}

export interface VerifiedHello {
  readonly envelope: VerifiedEnvelope;
  readonly manifest: ParsedManifest;
  readonly identity: VerifiedIdentity;
  readonly requestedGrants: readonly string[];
  readonly popNonce: string;
}

async function verifyRoundOne(
  envelope: unknown,
  type: "mutual_hello" | "mutual_hello_ack",
  options: HelloOptions,
  ack?: { readonly sentPopNonce: string; readonly peerAid: string },
): Promise<VerifiedHello> {
  // 1. Envelope, unauthenticated.
  const v = checkEnvelope(envelope, options);
  if (v.messageType !== type) fail("INVALID_ENVELOPE", `expected ${type}`);
  // 2. Payload member set.
  const p = v.payload;
  checkPayloadMembers(p, type === "mutual_hello" ? HELLO_MEMBERS : [...HELLO_MEMBERS, "pop_nonce_echo"], []);
  if (!isJsonObject(p.manifest)) fail("INVALID_ENVELOPE", "payload.manifest is not an object");
  const grants = p.requested_grants;
  if (!Array.isArray(grants) || !grants.every(isCapability)) fail("INVALID_ENVELOPE", "payload.requested_grants");
  if (!isNonceString(p.pop_nonce)) fail("INVALID_ENVELOPE", "payload.pop_nonce");
  if (type === "mutual_hello_ack" && !isNonceString(p.pop_nonce_echo)) fail("INVALID_ENVELOPE", "payload.pop_nonce_echo");
  // §5.2 step 3: the ACK comes from the peer the initiator addressed.
  if (ack !== undefined && v.sender.text !== ack.peerAid) fail("PEER_MISMATCH", "MUTUAL_HELLO_ACK sender is not the peer we addressed");
  // 3 (§5.2 step 4). One AID anchors everything that follows.
  if (p.manifest.aid !== v.sender.text) fail("INVALID_ENVELOPE", "manifest.aid is not the envelope sender");
  const manifest = parseManifest(p.manifest);
  if (isExpired(manifest.expiresAt, options.now)) fail("MANIFEST_EXPIRED", "inline Manifest has expired");
  // 4, 5. The trust bootstrap.
  await checkManifestPop(manifest);
  await checkManifestSignature(manifest);
  // 6. Identity binding.
  const identity = await verifyIdentity(
    p.identity,
    manifest.identityHint,
    { senderAid: v.sender.text, messageId: v.messageId, timestamp: v.timestamp, popNonce: p.pop_nonce },
    manifest.aid,
    options,
  );
  // 7. Envelope signature under the authenticated key.
  await checkEnvelopeSignature(v, manifest.aid.key);
  // §5.2 step 9.
  if (ack !== undefined && p.pop_nonce_echo !== ack.sentPopNonce) fail("NONCE_MISMATCH", "pop_nonce_echo is not our pop_nonce");
  // 8. Policy.
  if (options.acceptedIdentityTypes !== undefined) {
    if (!options.acceptedIdentityTypes.includes(identity.type)) fail("INCOMPATIBLE_IDENTITY_TYPE", `${identity.type} is not accepted`);
    if (identity.type === "oidc" && !options.trustAnchors.includes(identity.issuer as string)) {
      fail("INCOMPATIBLE_TRUST_ANCHORS", "OIDC issuer is not a trust anchor");
    }
  }
  recordEnvelope(v, options);
  return { envelope: v, manifest, identity, requestedGrants: grants as string[], popNonce: p.pop_nonce };
}

/** §5.1: B verifies A's MUTUAL_HELLO. */
export function verifyMutualHello(envelope: unknown, options: HelloOptions): Promise<VerifiedHello> {
  return verifyRoundOne(envelope, "mutual_hello", options);
}

/** §5.2: A verifies B's MUTUAL_HELLO_ACK. */
export function verifyMutualHelloAck(envelope: unknown, options: HelloAckOptions): Promise<VerifiedHello> {
  return verifyRoundOne(envelope, "mutual_hello_ack", options, { sentPopNonce: options.sentPopNonce, peerAid: options.peerAid });
}

export interface CommitOptions {
  readonly now: number;
  /** This peer's AID: the TCT's `sub` and `aud`. */
  readonly selfAid: string;
  /**
   * The `pop_nonce` this peer sent in round 1, which the commit must echo
   * and sign (§5.3 steps 3–4). Absent only when the caller has already
   * checked the echo and PoP signature.
   */
  readonly ownPopNonce?: string;
  /**
   * The capabilities the TCT's grants must fall within: the issuer's
   * `offered_capabilities` (RFC-AITP-0005 §4.3). Unchecked when absent.
   */
  readonly grantBound?: readonly string[];
  /** This peer's own `required_peer_capabilities`; default none. */
  readonly requiredPeerCapabilities?: readonly string[];
  /** The issuer's cached Manifest `expires_at` (RFC-AITP-0005 §10.4). */
  readonly issuerManifestExpiresAt?: number;
}

export interface VerifiedCommit {
  readonly tct: VerifiedTct;
  /** The companion voucher, stored verbatim (§5.3 step 5). */
  readonly grantVoucher?: string;
}

/**
 * §5.3 steps 2–5 / §5.4 steps 2–6 over a commit payload whose envelope the
 * caller has verified, from `sender`, the peer whose Manifest round 1
 * authenticated.
 */
export async function verifyCommitPayload(payload: unknown, sender: Aid, options: CommitOptions): Promise<VerifiedCommit> {
  if (!isJsonObject(payload)) fail("INVALID_ENVELOPE", "payload is not an object");
  checkPayloadMembers(payload, COMMIT_MEMBERS, ["grant_voucher"]);
  const { tct: token, pop_signature: popSig, pop_nonce_echo: echo, grant_voucher: voucher } = payload;
  if (typeof popSig !== "string" || !isNonceString(echo)) fail("INVALID_ENVELOPE", "malformed commit payload");
  if (voucher !== undefined && typeof voucher !== "string") fail("INVALID_ENVELOPE", "payload.grant_voucher");
  if (options.ownPopNonce !== undefined) {
    if (echo !== options.ownPopNonce) fail("NONCE_MISMATCH", "pop_nonce_echo is not our pop_nonce");
    const r = await verifyJcsSignature(sender.key, b64.decode(options.ownPopNonce), popSig);
    if (r !== "ok") fail("POP_VERIFICATION_FAILED", `pop_signature: ${r}`);
  }
  if (isJsonObject(token) || typeof token !== "string") fail("TCT_SIGNATURE_INVALID", "tct is not a compact JWS");
  const tct = await verifyTct(token, {
    now: options.now,
    expectedAudience: options.selfAid,
    issuerKey: sender.key,
    ...(options.issuerManifestExpiresAt !== undefined ? { issuerManifestExpiresAt: options.issuerManifestExpiresAt } : {}),
  });
  if (tct.iss.text !== sender.text) fail("TCT_SIGNATURE_INVALID", "TCT was not issued by the commit's sender");
  if (options.grantBound !== undefined && !tct.grants.every((g) => options.grantBound?.includes(g))) {
    fail("GRANT_OVERFLOW", "TCT grants exceed the issuer's offered capabilities");
  }
  if (!(options.requiredPeerCapabilities ?? []).every((c) => tct.grants.includes(c))) {
    fail("INSUFFICIENT_GRANTS", "TCT lacks a required peer capability");
  }
  return { tct, ...(voucher !== undefined ? { grantVoucher: voucher } : {}) };
}

/** §5.3 / §5.4 from the envelope: signature and replay first. */
export async function verifyMutualCommit(
  envelope: unknown,
  type: "mutual_commit" | "mutual_commit_ack",
  options: CommitOptions & EnvelopeOptions,
): Promise<VerifiedCommit> {
  const v = checkEnvelope(envelope, options);
  if (v.messageType !== type) fail("INVALID_ENVELOPE", `expected ${type}`);
  await checkEnvelopeSignature(v, options.senderKey);
  const result = await verifyCommitPayload(v.payload, v.sender, options);
  recordEnvelope(v, options);
  return result;
}
