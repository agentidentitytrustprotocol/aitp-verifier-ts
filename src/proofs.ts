// Signing inputs that are not a JCS object: proof of possession
// (RFC-AITP-0001 §5.4.2), the envelope (§5.4) and the pinned-key identity
// proof (RFC-AITP-0002 §3.1).

import * as b64 from "./b64.js";
import { concat, utf8 } from "./bytes.js";
import { canonicalBytes } from "./jcs.js";
import type { JsonObject } from "./json.js";

/**
 * The PoP preimage: the base64url-decoded nonce or challenge, never its
 * ASCII form. The §5.4.6 primitive hashes it once (d = SHA-256(preimage)).
 * Throws on a nonce that is not strict base64url.
 */
export function popInput(nonce: string): Uint8Array {
  return b64.decode(nonce);
}

const ENVELOPE_TAG = utf8("aitp-envelope-v2");

/**
 * `"aitp-envelope-v2" || 0x00 || JCS(envelope minus signature)`. Every
 * other member is kept as received, `extensions` included.
 */
export function envelopeSigningInput(envelope: JsonObject): Uint8Array {
  const { signature: _signature, ...rest } = envelope;
  return concat(ENVELOPE_TAG, new Uint8Array([0]), canonicalBytes(rest));
}

export interface HandshakeContext {
  readonly senderAid: string;
  readonly receiverAid: string;
  readonly messageId: string;
  readonly timestamp: number;
  /** The base64url `pop_nonce`; its decoded bytes enter the input. */
  readonly popNonce: string;
}

function contextInput(prefix: string, c: HandshakeContext): Uint8Array {
  const nul = new Uint8Array([0]);
  return concat(
    utf8(prefix),
    nul,
    utf8(c.senderAid),
    nul,
    utf8(c.receiverAid),
    nul,
    utf8(c.messageId),
    nul,
    utf8(String(c.timestamp)),
    nul,
    b64.decode(c.popNonce),
  );
}

/** RFC-AITP-0002 §3.1 `proof_input` for a pinned-key identity. */
export function pinnedKeyProofInput(c: HandshakeContext): Uint8Array {
  return contextInput("aitp-pinned-key-v1", c);
}

/** RFC-AITP-0002 §6.4.1 `proof_input` for an X509-SVID identity. */
export function spiffeX509ProofInput(c: HandshakeContext): Uint8Array {
  return contextInput("aitp-spiffe-x509-v1", c);
}
