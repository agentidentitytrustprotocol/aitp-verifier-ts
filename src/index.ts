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
