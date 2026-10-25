// Envelope verification (RFC-AITP-0001 §5, in the order of RFC-AITP-0009
// §3.1): replay, timestamp window, version, structure, member set, then the
// signature. Every check before the signature is free, so a malformed or
// stale message never costs a verification.

import type { Aid } from "../aid.js";
import { type JsonObject, isJsonObject } from "../json.js";
import type { PublicKey } from "../keys.js";
import { envelopeSigningInput } from "../proofs.js";
import { verifyJcsSignature } from "../sigfield.js";
import { isUuidV4 } from "../fields.js";
import { DEFAULT_TOLERANCE_SECS, withinWindow } from "../timeutil.js";
import { PROTOCOL_VERSION, SIGNATURE_PATTERN, aidOf, fail, unknownMembers } from "./common.js";
import type { ReplayCache } from "./replay.js";

export const MESSAGE_TYPES = [
  "mutual_hello",
  "mutual_hello_ack",
  "mutual_commit",
  "mutual_commit_ack",
  "tct",
  "pop_challenge",
  "pop_response",
  "identity_presentation",
  "error",
] as const;

export type MessageType = (typeof MESSAGE_TYPES)[number];

const MEMBERS = ["version", "message_type", "message_id", "timestamp", "sender", "payload", "signature", "extensions"];
const REQUIRED = ["version", "message_type", "message_id", "timestamp", "sender", "payload", "signature"];

export interface EnvelopeOptions {
  /** Reference time, Unix seconds. */
  readonly now: number;
  /** Timestamp tolerance; default 300 s (§5.5). */
  readonly toleranceSecs?: number;
  /** Deny list to check and, on success, record into. */
  readonly replay?: ReplayCache;
  /**
   * The key the sender's Manifest designates. Defaults to the key encoded
   * in `sender.agent_id`, which is the same key for every v0.3 AID method.
   */
  readonly senderKey?: PublicKey;
}

export interface VerifiedEnvelope {
  readonly envelope: JsonObject;
  readonly messageType: MessageType;
  readonly messageId: string;
  readonly timestamp: number;
  readonly sender: Aid;
  readonly payload: JsonObject;
}

/**
 * The checks of §5 up to, not including, the signature. Returns the parsed
 * fields so a caller can run payload checks before the signature, as the
 * handshake does (RFC-AITP-0004 §5.1).
 */
export function checkEnvelope(envelope: unknown, options: EnvelopeOptions): VerifiedEnvelope {
  if (!isJsonObject(envelope)) fail("INVALID_ENVELOPE", "envelope is not an object");
  const { message_id: id, timestamp: ts } = envelope;
  if (typeof id === "string" && options.replay?.has(id)) fail("REPLAY_DETECTED", `message_id ${id} already seen`);
  if (typeof ts === "number" && !withinWindow(ts, options.now, options.toleranceSecs ?? DEFAULT_TOLERANCE_SECS)) {
    fail("TIMESTAMP_EXPIRED", "timestamp outside the tolerance window");
  }
  if (envelope.version !== PROTOCOL_VERSION) fail("UNKNOWN_VERSION", "unsupported envelope version");

  for (const k of REQUIRED) if (!(k in envelope)) fail("INVALID_ENVELOPE", `missing ${k}`);
  const { message_type: type, sender, payload, signature, extensions } = envelope;
  if (typeof type !== "string" || !(MESSAGE_TYPES as readonly string[]).includes(type)) {
    fail("INVALID_ENVELOPE", "unknown message_type");
  }
  if (!isUuidV4(id)) fail("INVALID_ENVELOPE", "message_id is not a lowercase UUID v4");
  if (typeof ts !== "number" || !Number.isSafeInteger(ts) || ts < 0) fail("INVALID_ENVELOPE", "timestamp is not Unix seconds");
  if (!isJsonObject(sender) || !("agent_id" in sender)) fail("INVALID_ENVELOPE", "sender.agent_id missing");
  const aid = aidOf(sender.agent_id);
  if (aid === undefined) fail("INVALID_ENVELOPE", "sender.agent_id is not a valid AID");
  if (!isJsonObject(payload)) fail("INVALID_ENVELOPE", "payload is not an object");
  if (typeof signature !== "string" || !SIGNATURE_PATTERN.test(signature)) fail("INVALID_ENVELOPE", "malformed signature");
  if (extensions !== undefined && !isJsonObject(extensions)) fail("INVALID_ENVELOPE", "extensions is not an object");

  const unknown = [...unknownMembers(envelope, MEMBERS), ...unknownMembers(sender, ["agent_id"]).map((k) => `sender.${k}`)];
  if (unknown.length > 0) fail("UNKNOWN_FIELD", `unknown member ${unknown[0]}`);

  return { envelope, messageType: type as MessageType, messageId: id, timestamp: ts, sender: aid, payload };
}

/** The §5.4 signature check, after `checkEnvelope`. */
export async function checkEnvelopeSignature(v: VerifiedEnvelope, key: PublicKey = v.sender.key): Promise<void> {
  const r = await verifyJcsSignature(key, envelopeSigningInput(v.envelope), v.envelope.signature as string);
  if (r !== "ok") fail("INVALID_SIGNATURE", `envelope signature: ${r}`);
}

/** Record an accepted envelope in the deny list for the rest of its window. */
export function recordEnvelope(v: VerifiedEnvelope, options: EnvelopeOptions): void {
  options.replay?.add(v.messageId, v.timestamp + (options.toleranceSecs ?? DEFAULT_TOLERANCE_SECS));
}

/** Verify an envelope completely and record it as seen. */
export async function verifyEnvelope(envelope: unknown, options: EnvelopeOptions): Promise<VerifiedEnvelope> {
  const v = checkEnvelope(envelope, options);
  await checkEnvelopeSignature(v, options.senderKey);
  recordEnvelope(v, options);
  return v;
}
