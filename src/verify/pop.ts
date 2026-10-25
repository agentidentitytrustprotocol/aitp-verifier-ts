// Downstream proof of possession (RFC-AITP-0005 §6.1, §6.2): a
// `pop_challenge` names a TCT and a fresh nonce; the holder's
// `pop_response` echoes the nonce and signs sha256(decoded nonce) with the
// key in the TCT's `sub`. A malformed or stale challenge is
// POP_CHALLENGE_INVALID; any failure of the response is POP_RESPONSE_INVALID.

import type { Aid } from "../aid.js";
import * as b64 from "../b64.js";
import { AitpError } from "../errors.js";
import { type JsonObject, isJsonObject } from "../json.js";
import { jwkThumbprint } from "../jwk.js";
import { verifyJcsSignature } from "../sigfield.js";
import { isExpired } from "../timeutil.js";
import { fail, unknownMembers } from "./common.js";
import { type EnvelopeOptions, type VerifiedEnvelope, verifyEnvelope } from "./envelope.js";
import type { TctClaims } from "./tct.js";

export interface PopChallenge {
  readonly tctJti: string;
  /** The challenge nonce, 128 bits of unpadded base64url. */
  readonly nonce: string;
  /** When the challenge stops being answerable, Unix seconds. */
  readonly expiresAt?: number;
}

function isNonce(value: unknown): value is string {
  return typeof value === "string" && b64.decodeExact(value, 16) !== undefined;
}

/** Verify an envelope, reporting any failure under one code. */
async function envelopeAs(code: "POP_CHALLENGE_INVALID" | "POP_RESPONSE_INVALID", envelope: unknown, options: EnvelopeOptions) {
  try {
    return await verifyEnvelope(envelope, options);
  } catch (e) {
    if (e instanceof AitpError) fail(code, `${code === "POP_CHALLENGE_INVALID" ? "challenge" : "response"} envelope: ${e.code}`);
    throw e;
  }
}

function payloadMembers(code: "POP_CHALLENGE_INVALID" | "POP_RESPONSE_INVALID", payload: JsonObject, members: string[]): void {
  for (const k of members) if (!(k in payload)) fail(code, `payload.${k} missing`);
  if (unknownMembers(payload, [...members, "extensions"]).length > 0) fail(code, "unknown payload member");
  if (payload.extensions !== undefined && !isJsonObject(payload.extensions)) fail(code, "payload.extensions");
}

/** Check a `pop_challenge` envelope and return the challenge it carries. */
export async function verifyPopChallenge(
  envelope: unknown,
  options: EnvelopeOptions & { readonly expiresAt?: number },
): Promise<{ envelope: VerifiedEnvelope; challenge: PopChallenge }> {
  const v = await envelopeAs("POP_CHALLENGE_INVALID", envelope, options);
  if (v.messageType !== "pop_challenge") fail("POP_CHALLENGE_INVALID", "not a pop_challenge");
  payloadMembers("POP_CHALLENGE_INVALID", v.payload, ["tct_jti", "nonce"]);
  const { tct_jti: jti, nonce } = v.payload;
  if (typeof jti !== "string" || !isNonce(nonce)) fail("POP_CHALLENGE_INVALID", "malformed challenge");
  return {
    envelope: v,
    challenge: { tctJti: jti, nonce, ...(options.expiresAt !== undefined ? { expiresAt: options.expiresAt } : {}) },
  };
}

/**
 * §6.2: verify a `pop_response` to `challenge` for the TCT `tct`. Returns
 * the AID the response proves possession for: the TCT's `sub`.
 */
export async function verifyPopResponse(
  response: unknown,
  challenge: PopChallenge,
  tct: Pick<TctClaims, "jti" | "sub" | "jkt">,
  options: EnvelopeOptions,
): Promise<Aid> {
  if (!isNonce(challenge.nonce) || challenge.tctJti !== tct.jti) fail("POP_CHALLENGE_INVALID", "challenge does not name this TCT");
  if (challenge.expiresAt !== undefined && isExpired(challenge.expiresAt, options.now)) {
    fail("POP_CHALLENGE_INVALID", "challenge has expired");
  }
  const v = await envelopeAs("POP_RESPONSE_INVALID", response, options);
  if (v.messageType !== "pop_response") fail("POP_RESPONSE_INVALID", "not a pop_response");
  payloadMembers("POP_RESPONSE_INVALID", v.payload, ["tct_jti", "nonce_echo", "pop_signature"]);
  const { tct_jti: jti, nonce_echo: echo, pop_signature: sig } = v.payload;
  if (jti !== tct.jti) fail("POP_RESPONSE_INVALID", "response names another TCT");
  if (echo !== challenge.nonce) fail("POP_RESPONSE_INVALID", "nonce_echo does not match the challenge");
  if (typeof sig !== "string") fail("POP_RESPONSE_INVALID", "pop_signature");
  if ((await verifyJcsSignature(tct.sub.key, b64.decode(challenge.nonce), sig)) !== "ok") {
    fail("POP_RESPONSE_INVALID", "pop_signature does not verify under the sub key");
  }
  if (tct.jkt !== (await jwkThumbprint(tct.sub.key))) fail("POP_RESPONSE_INVALID", "cnf.jkt does not bind the sub key");
  return tct.sub;
}
