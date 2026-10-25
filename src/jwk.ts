// JWKs: the RFC 7638 thumbprint behind `cnf.jkt` (RFC-AITP-0001 §5.4.4,
// RFC-AITP-0002 §2.2.1), and public-key JWK parsing for OIDC issuer keys.

import * as b64 from "./b64.js";
import { utf8 } from "./bytes.js";
import { canonicalize } from "./jcs.js";
import { isJsonObject } from "./json.js";
import { type PublicKey, p256FromCoordinates, publicJwk, publicKeyFromRaw, sha256 } from "./keys.js";

/**
 * The RFC 7638 thumbprint of a key in its own algorithm's canonical JWK:
 * `{"crv","kty","x"}` for Ed25519 and `{"crv","kty","x","y"}` for P-256,
 * members in lexicographic order, no whitespace, SHA-256, base64url.
 */
export async function jwkThumbprint(key: PublicKey): Promise<string> {
  return b64.encode(await sha256(utf8(jwkThumbprintInput(key))));
}

export function jwkThumbprintInput(key: PublicKey): string {
  // The required members hold only base64url and fixed ASCII, so JCS
  // output is exactly the RFC 7638 serialization.
  return canonicalize(publicJwk(key));
}

/**
 * A public key from an OKP/Ed25519 or EC/P-256 JWK. Members other than the
 * key material (kid, alg, use, …) are allowed and ignored; a JWK carrying a
 * private `d` is refused, so a private key is never mistaken for trust data.
 */
export function publicKeyFromJwk(jwk: unknown): PublicKey | undefined {
  if (!isJsonObject(jwk) || "d" in jwk) return undefined;
  const { kty, crv, x, y } = jwk;
  if (typeof x !== "string") return undefined;
  if (kty === "OKP" && crv === "Ed25519" && y === undefined) {
    const raw = b64.decodeExact(x, 32);
    return raw === undefined ? undefined : publicKeyFromRaw("ed25519", raw);
  }
  if (kty === "EC" && crv === "P-256" && typeof y === "string") {
    const xb = b64.decodeExact(x, 32);
    const yb = b64.decodeExact(y, 32);
    return xb === undefined || yb === undefined ? undefined : p256FromCoordinates(xb, yb);
  }
  return undefined;
}
