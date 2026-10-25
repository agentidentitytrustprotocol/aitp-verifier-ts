// Agent Manifest verification (RFC-AITP-0003 §5 steps 1–5): version,
// structure, member set, expiry, proof of possession, signature. Step 6,
// the compatibility screen, needs the fetching peer's own identity and is
// the caller's.

import type { Aid } from "../aid.js";
import * as b64 from "../b64.js";
import { canonicalBytes } from "../jcs.js";
import { type JsonObject, isJsonObject } from "../json.js";
import { verifyJcsSignature } from "../sigfield.js";
import { isUnsignedInt } from "../fields.js";
import { isExpired } from "../timeutil.js";
import {
  NONCE_PATTERN,
  PROTOCOL_VERSION,
  SIGNATURE_PATTERN,
  aidOf,
  fail,
  isCapability,
  isUniqueStrings,
  unknownMembers,
} from "./common.js";

const REQUIRED = [
  "version",
  "aid",
  "identity_hint",
  "handshake_endpoint",
  "accepted_trust_anchors",
  "offered_capabilities",
  "proof_of_possession",
  "published_at",
  "expires_at",
  "signature",
];
const OPTIONAL = [
  "display_name",
  "required_peer_capabilities",
  "accepted_identity_types",
  "accepted_signature_algorithms",
  "extensions",
];
const HINT_MEMBERS = ["type", "issuer", "subject", "public_key"];
const IDENTITY_TYPES = ["oidc", "pinned_key", "spiffe"];
const SPIFFE_ID = /^spiffe:\/\/[a-z0-9._-]{1,255}(\/([A-Za-z0-9._-]*[A-Za-z0-9_-][A-Za-z0-9._-]*|\.{3,}))+$/;
const URI = /^[A-Za-z][A-Za-z0-9+.-]*:\S*$/;

export type IdentityType = "oidc" | "pinned_key" | "spiffe";

export interface IdentityHint {
  readonly type: IdentityType;
  readonly subject: string;
  readonly issuer?: string;
  readonly publicKey?: string;
}

export interface ParsedManifest {
  readonly manifest: JsonObject;
  readonly aid: Aid;
  readonly identityHint: IdentityHint;
  readonly acceptedTrustAnchors: readonly string[];
  readonly offeredCapabilities: readonly string[];
  readonly requiredPeerCapabilities: readonly string[];
  /** Absent means `["oidc"]` (§3.2); kept distinct from an empty list. */
  readonly acceptedIdentityTypes?: readonly IdentityType[];
  readonly publishedAt: number;
  readonly expiresAt: number;
}

export interface ManifestOptions {
  /** Reference time, Unix seconds. */
  readonly now: number;
  /** Versions the caller accepts; this verifier implements only aitp/0.3. */
  readonly supportedVersions?: readonly string[];
}

function invalid(message: string): never {
  return fail("MANIFEST_INVALID", message);
}

function checkHint(hint: unknown): IdentityHint {
  if (!isJsonObject(hint)) invalid("identity_hint is not an object");
  const { type, issuer, subject, public_key: publicKey } = hint;
  if (typeof type !== "string" || !IDENTITY_TYPES.includes(type)) invalid("identity_hint.type");
  if (typeof subject !== "string" || subject.length === 0) invalid("identity_hint.subject");
  if (issuer !== undefined && (typeof issuer !== "string" || !URI.test(issuer))) invalid("identity_hint.issuer");
  if (publicKey !== undefined && (typeof publicKey !== "string" || !/^[A-Za-z0-9_-]{43,44}$/.test(publicKey))) {
    invalid("identity_hint.public_key");
  }
  if (type === "oidc" && (issuer === undefined || publicKey !== undefined)) invalid("oidc identity_hint needs issuer, forbids public_key");
  if (type === "pinned_key" && publicKey === undefined) invalid("pinned_key identity_hint needs public_key");
  if (type === "spiffe" && (issuer !== undefined || publicKey !== undefined || subject.length > 2048 || !SPIFFE_ID.test(subject))) {
    invalid("spiffe identity_hint");
  }
  return {
    type: type as IdentityType,
    subject,
    ...(issuer !== undefined ? { issuer: issuer as string } : {}),
    ...(publicKey !== undefined ? { publicKey: publicKey as string } : {}),
  };
}

/**
 * Steps 1 and 2: version, then structure (MANIFEST_INVALID), then the
 * member set (UNKNOWN_FIELD), all before any cryptography.
 */
export function parseManifest(manifest: unknown, options: Pick<ManifestOptions, "supportedVersions"> = {}): ParsedManifest {
  if (!isJsonObject(manifest)) invalid("manifest is not an object");
  const supported = options.supportedVersions ?? [PROTOCOL_VERSION];
  if (manifest.version !== PROTOCOL_VERSION || !supported.includes(PROTOCOL_VERSION)) {
    fail("MANIFEST_VERSION_UNKNOWN", "unsupported manifest version");
  }
  for (const k of REQUIRED) if (!(k in manifest)) invalid(`missing ${k}`);
  const m = manifest;
  const aid = aidOf(m.aid);
  if (aid === undefined) invalid("aid");
  const identityHint = checkHint(m.identity_hint);
  if (typeof m.handshake_endpoint !== "string" || !/^https:\/\/\S+$/.test(m.handshake_endpoint)) invalid("handshake_endpoint");
  if (!isUniqueStrings(m.accepted_trust_anchors, (v) => typeof v === "string" && URI.test(v))) invalid("accepted_trust_anchors");
  if (!isUniqueStrings(m.offered_capabilities, isCapability)) invalid("offered_capabilities");
  if (m.required_peer_capabilities !== undefined && !isUniqueStrings(m.required_peer_capabilities, isCapability)) {
    invalid("required_peer_capabilities");
  }
  if (
    m.accepted_identity_types !== undefined &&
    !isUniqueStrings(m.accepted_identity_types, (v) => typeof v === "string" && IDENTITY_TYPES.includes(v))
  ) {
    invalid("accepted_identity_types");
  }
  if (
    m.accepted_signature_algorithms !== undefined &&
    !isUniqueStrings(m.accepted_signature_algorithms, (v) => v === "ed25519" || v === "p256")
  ) {
    invalid("accepted_signature_algorithms");
  }
  if (m.display_name !== undefined && (typeof m.display_name !== "string" || [...m.display_name].length > 128)) {
    invalid("display_name");
  }
  const pop = m.proof_of_possession;
  if (!isJsonObject(pop)) invalid("proof_of_possession");
  if (typeof pop.challenge !== "string" || !NONCE_PATTERN.test(pop.challenge) || b64.tryDecode(pop.challenge) === undefined) {
    invalid("proof_of_possession.challenge");
  }
  if (typeof pop.signature !== "string" || !SIGNATURE_PATTERN.test(pop.signature)) invalid("proof_of_possession.signature");
  if (!isUnsignedInt(m.published_at)) invalid("published_at");
  if (!isUnsignedInt(m.expires_at) || m.expires_at < 1) invalid("expires_at");
  if (typeof m.signature !== "string" || !SIGNATURE_PATTERN.test(m.signature)) invalid("signature");
  if (m.extensions !== undefined && !isJsonObject(m.extensions)) invalid("extensions");

  const unknown = [
    ...unknownMembers(m, [...REQUIRED, ...OPTIONAL]),
    ...unknownMembers(m.identity_hint as JsonObject, HINT_MEMBERS).map((k) => `identity_hint.${k}`),
    ...unknownMembers(pop, ["challenge", "signature"]).map((k) => `proof_of_possession.${k}`),
  ];
  if (unknown.length > 0) fail("UNKNOWN_FIELD", `unknown member ${unknown[0]}`);

  return {
    manifest: m,
    aid,
    identityHint,
    acceptedTrustAnchors: m.accepted_trust_anchors,
    offeredCapabilities: m.offered_capabilities,
    requiredPeerCapabilities: (m.required_peer_capabilities as string[] | undefined) ?? [],
    ...(m.accepted_identity_types !== undefined ? { acceptedIdentityTypes: m.accepted_identity_types as IdentityType[] } : {}),
    publishedAt: m.published_at,
    expiresAt: m.expires_at,
  };
}

/** Step 4: the PoP signature over sha256(decoded challenge), by the aid key. */
export async function checkManifestPop(p: ParsedManifest): Promise<void> {
  const pop = p.manifest.proof_of_possession as JsonObject;
  const r = await verifyJcsSignature(p.aid.key, b64.decode(pop.challenge as string), pop.signature as string);
  if (r !== "ok") fail("MANIFEST_POP_FAILED", `manifest proof of possession: ${r}`);
}

/** Step 5: the signature over JCS(manifest minus signature), by the aid key (§6). */
export async function checkManifestSignature(p: ParsedManifest): Promise<void> {
  const { signature, ...body } = p.manifest;
  const r = await verifyJcsSignature(p.aid.key, canonicalBytes(body), signature as string);
  if (r !== "ok") fail("MANIFEST_SIGNATURE_INVALID", `manifest signature: ${r}`);
}

/** RFC-AITP-0003 §5 steps 1–5. */
export async function verifyManifest(manifest: unknown, options: ManifestOptions): Promise<ParsedManifest> {
  const p = parseManifest(manifest, options);
  if (isExpired(p.expiresAt, options.now)) fail("MANIFEST_EXPIRED", "manifest expires_at has passed");
  await checkManifestPop(p);
  await checkManifestSignature(p);
  return p;
}
