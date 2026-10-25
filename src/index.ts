// @agentidentitytrustprotocol/verifier: a native TypeScript AITP v0.3
// verifier on WebCrypto, with no runtime dependencies.

export * as b64 from "./b64.js";
export { AitpError, ERROR_REGISTRY, type ErrorCode, isErrorCode } from "./errors.js";
export { type JsonObject, type JsonValue, JsonParseError, parseJson, parseJsonBytes } from "./json.js";
export { canonicalBytes, canonicalize, JcsError } from "./jcs.js";
export {
  type Alg,
  AlgorithmUnavailableError,
  ed25519Available,
  ed25519FromSeed,
  p256FromScalar,
  type PrivateKey,
  type PublicKey,
  sha256,
} from "./keys.js";
export { type Aid, aidFor, parseAid, sameKeyAid } from "./aid.js";
export { jwkThumbprint, publicKeyFromJwk } from "./jwk.js";
export { parseSignatureField, signJcs, verifyJcsSignature, type SignatureField } from "./sigfield.js";
export { type CompactJws, JwsFormatError, parseCompactJws, signCompactJws, verifyJwsSignature } from "./jws.js";
export { derivedUuid, isUuidV4 } from "./fields.js";
export { DEFAULT_TOLERANCE_SECS, isExpired, systemNow, withinWindow } from "./timeutil.js";
export { envelopeSigningInput, type HandshakeContext, pinnedKeyProofInput, popInput } from "./proofs.js";

export { ReplayCache } from "./verify/replay.js";
export { type EnvelopeOptions, MESSAGE_TYPES, type MessageType, type VerifiedEnvelope, verifyEnvelope } from "./verify/envelope.js";
export {
  type IdentityHint,
  type IdentityType,
  type ManifestOptions,
  type ParsedManifest,
  parseManifest,
  verifyManifest,
} from "./verify/manifest.js";
export { type IdentityOptions, type VerifiedIdentity, verifyIdentity } from "./verify/identity.js";
export {
  type CommitOptions,
  type HelloAckOptions,
  type HelloOptions,
  type VerifiedCommit,
  type VerifiedHello,
  verifyCommitPayload,
  verifyMutualCommit,
  verifyMutualHello,
  verifyMutualHelloAck,
} from "./verify/handshake.js";
export {
  type IssuerSideOptions,
  type RevocationLookup,
  type TctClaims,
  type TctOptions,
  type VerifiedTct,
  verifyTct,
  verifyTctAsIssuer,
} from "./verify/tct.js";
export { type PopChallenge, verifyPopChallenge, verifyPopResponse } from "./verify/pop.js";
export {
  DEFAULT_REVOCATION_MODE,
  decideRevocation,
  type RevocationDecision,
  type RevocationMode,
  type RevocationPolicy,
  type RevocationStatus,
  snapshotStatus,
  type VerifiedSnapshot,
  verifySnapshot,
} from "./verify/revocation.js";
export {
  type DelegationOptions,
  type VerifiedDelegation,
  type VerifiedVoucher,
  type VoucherOptions,
  verifyDelegation,
  verifyVoucher,
} from "./verify/delegation.js";
