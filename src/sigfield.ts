// JCS-profile signature fields (RFC-AITP-0001 §5.4.3) and the signing
// primitive behind them (§5.4.6).
//
//   <86 chars>            Ed25519 (legacy, untagged)
//   ed25519.<86 chars>    Ed25519
//   p256.<86 chars>       P-256, raw R || S
//
// §5.4.6: the signing input is hashed exactly once, d = SHA-256(input).
// Ed25519 signs d as its message; P-256 uses d as the ECDSA hash (e = d),
// which is ECDSA-with-SHA-256 over the input itself. So `verifyJcsSignature`
// takes the input, never a digest, and P-256 never hashes twice.

import * as b64 from "./b64.js";
import { type Alg, type PublicKey, type PrivateKey, sha256, signRaw, verifyRaw } from "./keys.js";

export interface SignatureField {
  readonly alg: Alg;
  readonly tagged: boolean;
  readonly bytes: Uint8Array;
}

/** Parse a signature field, or `undefined` if it is not one of the three forms. */
export function parseSignatureField(text: string): SignatureField | undefined {
  const dot = text.indexOf(".");
  let alg: Alg;
  let encoded: string;
  if (dot === -1) {
    alg = "ed25519";
    encoded = text;
  } else {
    const tag = text.slice(0, dot);
    if (tag !== "ed25519" && tag !== "p256") return undefined;
    alg = tag;
    encoded = text.slice(dot + 1);
  }
  if (encoded.length !== 86) return undefined;
  const bytes = b64.decodeExact(encoded, 64);
  return bytes === undefined ? undefined : { alg, tagged: dot !== -1, bytes };
}

export type JcsSignatureResult = "ok" | "malformed" | "alg_mismatch" | "bad_signature";

/**
 * Check a signature field over `input` under `key`. The result says why it
 * failed so each artifact can map that to its own registry code; callers
 * that need only pass/fail compare with "ok".
 */
export async function verifyJcsSignature(key: PublicKey, input: Uint8Array, field: string): Promise<JcsSignatureResult> {
  const sig = parseSignatureField(field);
  if (sig === undefined) return "malformed";
  if (sig.alg !== key.alg) return "alg_mismatch";
  return (await verifyJcsPrimitive(key, input, sig.bytes)) ? "ok" : "bad_signature";
}

/** The §5.4.6 primitive over raw signature bytes. */
export async function verifyJcsPrimitive(key: PublicKey, input: Uint8Array, sig: Uint8Array): Promise<boolean> {
  return key.alg === "ed25519" ? verifyRaw(key, await sha256(input), sig) : verifyRaw(key, input, sig);
}

/**
 * Sign `input` under §5.4.6 and encode it as a signature field. P-256 is
 * always tagged (RFC-AITP-0002 §3.1); Ed25519 is tagged when asked.
 */
export async function signJcs(key: PrivateKey, input: Uint8Array, options: { tagged?: boolean } = {}): Promise<string> {
  const sig = key.alg === "ed25519" ? await signRaw(key, await sha256(input)) : await signRaw(key, input);
  const encoded = b64.encode(sig);
  if (key.alg === "p256") return `p256.${encoded}`;
  return options.tagged ? `ed25519.${encoded}` : encoded;
}
