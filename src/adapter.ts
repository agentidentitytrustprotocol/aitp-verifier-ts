// The aitp-conformance adapter: one request in, one reply out, over the
// runner's NDJSON protocol (aitp-rs crates/aitp-conformance). This module
// only maps fixture inputs onto the verifier API; it holds no protocol
// logic of its own beyond the per-fixture state the sequence fixtures need.
// It is runtime-agnostic; bin/aitp-verifier-adapter.mjs drives it over
// stdin and stdout.

import { type Aid, sameKeyAid } from "./aid.js";
import * as b64 from "./b64.js";
import { AitpError } from "./errors.js";
import { type JsonObject, isJsonObject } from "./json.js";
import { type PublicKey, publicKeyFromRaw } from "./keys.js";
import { parseCompactJws } from "./jws.js";
import { envelopeSigningInput } from "./proofs.js";
import { verifyJcsSignature } from "./sigfield.js";
import { isExpired } from "./timeutil.js";
import { aidOf, fail } from "./verify/common.js";
import { verifyDelegation, verifyVoucher } from "./verify/delegation.js";
import { verifyEnvelope } from "./verify/envelope.js";
import { verifyCommitPayload, verifyMutualCommit, verifyMutualHello, verifyMutualHelloAck } from "./verify/handshake.js";
import { type IdentityType, verifyManifest } from "./verify/manifest.js";
import { type PopChallenge, verifyPopChallenge, verifyPopResponse } from "./verify/pop.js";
import { ReplayCache } from "./verify/replay.js";
import { type RevocationMode, type RevocationStatus, decideRevocation, snapshotStatus, verifySnapshot } from "./verify/revocation.js";
import { type TctClaims, type VerifiedTct, parseTct, verifyTct, verifyTctAsIssuer } from "./verify/tct.js";

export interface AdapterRequest {
  readonly id: string;
  readonly op: string;
  readonly params?: JsonObject;
}

export type AdapterReply =
  | { id: string; ok: true; result: JsonObject }
  | { id: string; ok: false; error_code: string; message: string };

export interface AdapterInfo {
  readonly implementation: string;
  readonly version: string;
  readonly repository: string;
  readonly commit: string;
}

export interface AdapterOptions {
  readonly info: AdapterInfo;
  /** Signing keys of the OIDC test issuers, by issuer URL. */
  readonly oidcIssuers: ReadonlyMap<string, readonly PublicKey[]>;
}

/** The protocol default when a fixture states no trust anchors (conformance README). */
const DEFAULT_TRUST_ANCHORS = ["https://auth.openai.com"];

const REVOCATION_MODES: readonly string[] = ["fail_closed", "fail_open", "soft_fail"];

class NotSupported extends Error {}

/** A request missing an input the op needs: the adapter protocol's MALFORMED_REQUEST. */
class MalformedRequest extends Error {}

/** The receiving peer's own AID; every receive-side op needs it. */
function selfAidOf(params: JsonObject): string {
  const v = params.self_aid;
  if (typeof v !== "string") throw new MalformedRequest("self_aid is required");
  return v;
}

/** State a sequence fixture carries from one step to the next. */
interface FixtureState {
  replay: ReplayCache;
  seenMessageIds: Set<string>;
  pop?: { tct: VerifiedTct; challenge?: PopChallenge; response?: unknown };
  invocation?: { challengeIssued: boolean; authorized: boolean };
}

function freshState(): FixtureState {
  return { replay: new ReplayCache(), seenMessageIds: new Set() };
}

function str(params: JsonObject, key: string): string | undefined {
  const v = params[key];
  return typeof v === "string" ? v : undefined;
}

function num(params: JsonObject, key: string): number | undefined {
  const v = params[key];
  return typeof v === "number" ? v : undefined;
}

function strings(params: JsonObject, key: string): string[] | undefined {
  const v = params[key];
  return Array.isArray(v) && v.every((x) => typeof x === "string") ? (v as string[]) : undefined;
}

/** An AID the fixture supplies as verifier configuration; a bad one is a fixture error. */
function configAid(value: unknown, what: string): Aid {
  const aid = aidOf(value);
  if (aid === undefined) throw new Error(`fixture ${what} is not an AID`);
  return aid;
}

/** The unverified claims of a compact JWS, for routing only. */
function peekClaims(token: unknown): JsonObject | undefined {
  if (typeof token !== "string") return undefined;
  try {
    return parseCompactJws(token).claims;
  } catch {
    return undefined;
  }
}

export class Adapter {
  #now = 0;
  #features: string[] = [];
  #state: FixtureState = freshState();
  readonly #options: AdapterOptions;

  constructor(options: AdapterOptions) {
    this.#options = options;
  }

  static readonly OPS = [
    "set_features",
    "set_clock",
    "begin_fixture",
    "verify_envelope",
    "verify_manifest",
    "verify_handshake_payload",
    "process_handshake_message",
    "verify_tct",
    "verify_tct_as_issuer",
    "issue_pop_challenge",
    "produce_pop_response",
    "verify_pop_response",
    "authorize_capability_invocation",
    "expect_pop_challenge_issued",
    "withhold_pop_response",
    "verify_revocation_snapshot",
    "verify_grant_voucher",
    "verify_delegation_token",
  ] as const;

  async handle(request: AdapterRequest): Promise<AdapterReply> {
    const { id, op } = request;
    const params = isJsonObject(request.params) ? request.params : {};
    try {
      const result = await this.#dispatch(op, params);
      return { id, ok: true, result };
    } catch (e) {
      if (e instanceof AitpError) return { id, ok: false, error_code: e.code, message: e.message };
      if (e instanceof NotSupported) return { id, ok: false, error_code: "OP_NOT_SUPPORTED", message: e.message };
      if (e instanceof MalformedRequest) return { id, ok: false, error_code: "MALFORMED_REQUEST", message: e.message };
      return { id, ok: false, error_code: "INTERNAL_ERROR", message: (e as Error).message ?? String(e) };
    }
  }

  async #dispatch(op: string, p: JsonObject): Promise<JsonObject> {
    switch (op) {
      case "init":
        return {
          ...this.#options.info,
          supported_ops: [...Adapter.OPS],
          supported_features: [],
        };
      case "set_features":
        this.#features = strings(p, "features") ?? [];
        return {};
      case "set_clock": {
        const now = num(p, "now_unix_secs") ?? num(p, "now");
        if (now === undefined) throw new Error("set_clock without a time");
        this.#now = now;
        return {};
      }
      case "begin_fixture":
        this.#state = freshState();
        return {};
      case "shutdown":
        return {};
      case "verify_envelope":
        return this.#verifyEnvelope(p);
      case "verify_manifest":
        return this.#verifyManifest(p);
      case "verify_handshake_payload":
        return this.#verifyHandshakePayload(p);
      case "process_handshake_message":
        return this.#seeMessageId(p);
      case "verify_tct":
        return this.#verifyTct(p);
      case "verify_tct_as_issuer":
        return this.#verifyTctAsIssuer(p);
      case "issue_pop_challenge":
        return this.#issuePopChallenge(p);
      case "produce_pop_response":
        return this.#producePopResponse(p);
      case "verify_pop_response":
        return this.#verifyPopResponse();
      case "authorize_capability_invocation":
        return this.#authorizeInvocation(p);
      case "expect_pop_challenge_issued":
        return this.#expectChallengeIssued();
      case "withhold_pop_response":
        return this.#withholdPopResponse();
      case "verify_revocation_snapshot":
        return this.#verifyRevocationSnapshot(p);
      case "verify_grant_voucher":
        return this.#verifyGrantVoucher(p);
      case "verify_delegation_token":
        return this.#verifyDelegationToken(p);
      default:
        throw new NotSupported(`op ${op} is not supported`);
    }
  }

  get features(): readonly string[] {
    return this.#features;
  }

  #nowFrom(p: JsonObject): number {
    return num(p, "now") ?? this.#now;
  }

  // --- Envelopes and replay -------------------------------------------------

  /** A message_id-only step: the replay half of RFC-AITP-0001 §5.5. */
  #seeMessageId(p: JsonObject): JsonObject {
    const id = str(p, "message_id");
    if (id === undefined) throw new Error("message_id missing");
    if (this.#state.seenMessageIds.has(id)) fail("REPLAY_DETECTED", `message_id ${id} already seen`);
    this.#state.seenMessageIds.add(id);
    return {};
  }

  async #verifyEnvelope(p: JsonObject): Promise<JsonObject> {
    if ("active_tct" in p) return this.#authorizeActiveTct(p);
    if ("needed_key_for" in p) return this.#resolveKey(p);
    if (!("envelope" in p)) return this.#seeMessageId(p);
    const tolerance = num(p, "tolerance_seconds");
    const v = await verifyEnvelope(p.envelope, {
      now: this.#now,
      replay: this.#state.replay,
      ...(tolerance !== undefined ? { toleranceSecs: tolerance } : {}),
    });
    return { message_id: v.messageId, sender: v.sender.text };
  }

  /** A request under an established TCT: the capability must be granted. */
  async #authorizeActiveTct(p: JsonObject): Promise<JsonObject> {
    const tct = await verifyTct(p.active_tct, { now: this.#now });
    const capability = str(p, "requested_capability");
    if (capability === undefined || !tct.grants.includes(capability)) {
      fail("POLICY_VIOLATION", "requested capability is not granted by the active TCT");
    }
    return { grants: [...tct.grants] };
  }

  /**
   * Key resolution from the sources the fixture describes (RFC-AITP-0007):
   * a key only comes from a Manifest that was fetched, a pinned key or a
   * well-known key; nothing is derived from an unreachable source.
   */
  #resolveKey(p: JsonObject): JsonObject {
    const target = configAid(p.needed_key_for, "needed_key_for");
    const fetched = isJsonObject(p.manifest_fetch) && p.manifest_fetch.status === "ok";
    const listed = (key: string) =>
      Array.isArray(p[key]) && (p[key] as unknown[]).some((a) => aidOf(a) !== undefined && sameKeyAid(aidOf(a) as Aid, target));
    if (!fetched && !listed("pinned_keys") && !listed("well_known_keys")) {
      fail("KEY_RESOLUTION_FAILED", "no source yields a key for the AID");
    }
    return { aid: target.text };
  }

  // --- Manifests ---------------------------------------------------------------

  async #verifyManifest(p: JsonObject): Promise<JsonObject> {
    const supportedVersions = strings(p, "supported_versions");
    const m = await verifyManifest(p.manifest, {
      now: this.#nowFrom(p),
      ...(supportedVersions !== undefined ? { supportedVersions } : {}),
    });
    return { aid: m.aid.text, expires_at: m.expiresAt };
  }

  // --- Mutual Handshake --------------------------------------------------------

  async #verifyHandshakePayload(p: JsonObject): Promise<JsonObject> {
    if (isJsonObject(p.peer_a) || isJsonObject(p.peer_b)) return this.#verifyBothCommits(p);
    const envelope = p.envelope;
    if (!isJsonObject(envelope)) throw new Error("verify_handshake_payload without an envelope");
    const selfAid = selfAidOf(p);
    const type = envelope.message_type;
    if (type === "mutual_commit" || type === "mutual_commit_ack") {
      const own = str(p, type === "mutual_commit" ? "self_pop_nonce_sent_in_hello_ack" : "self_pop_nonce_sent_in_hello");
      const bound = strings(p, "issuer_offered_capabilities");
      const c = await verifyMutualCommit(envelope, type, {
        now: this.#now,
        replay: this.#state.replay,
        selfAid,
        ...(own !== undefined ? { ownPopNonce: own } : {}),
        ...(bound !== undefined ? { grantBound: bound } : {}),
      });
      return { grants: [...c.tct.grants] };
    }
    const trustStore = (strings(p, "trust_store") ?? []).map((a) => configAid(a, "trust_store entry"));
    const accepted = strings(p, "self_accepted_identity_types") as IdentityType[] | undefined;
    const options = {
      now: this.#now,
      replay: this.#state.replay,
      selfAid,
      trustAnchors: strings(p, "self_trust_anchors") ?? DEFAULT_TRUST_ANCHORS,
      resolveIssuerKeys: (issuer: string) => this.#options.oidcIssuers.get(issuer) ?? [],
      pinnedKeys: trustStore,
      ...(accepted !== undefined ? { acceptedIdentityTypes: accepted } : {}),
    };
    let hello;
    if (type === "mutual_hello_ack") {
      const sent = str(p, "sent_pop_nonce");
      if (sent === undefined) throw new Error("a mutual_hello_ack fixture needs sent_pop_nonce");
      hello = await verifyMutualHelloAck(envelope, { ...options, sentPopNonce: sent });
    } else {
      hello = await verifyMutualHello(envelope, options);
    }
    return {
      sender: hello.envelope.sender.text,
      identity_type: hello.identity.type,
      requested_grants: [...hello.requestedGrants],
    };
  }

  /**
   * Both commit payloads of one handshake (§5.3 and §5.4). Each payload's
   * sender is the peer that issued the TCT it carries; the round-1
   * Manifests that would name those peers are not part of the input.
   */
  async #verifyBothCommits(p: JsonObject): Promise<JsonObject> {
    const grants = new Set<string>();
    for (const key of ["peer_a", "peer_b"]) {
      const peer = p[key];
      if (!isJsonObject(peer)) continue;
      const selfAid = selfAidOf(peer);
      const payload = peer.received_payload;
      const issuer = aidOf(isJsonObject(payload) ? peekClaims(payload.tct)?.iss : undefined);
      if (issuer === undefined) fail("TCT_SIGNATURE_INVALID", `${key}: the TCT names no issuer`);
      const own =
        peer.received_envelope_message_type === "mutual_commit"
          ? str(peer, "self_pop_nonce_sent_in_hello_ack")
          : str(peer, "self_pop_nonce_sent_in_hello");
      if (own === undefined) throw new Error(`${key}: no own pop_nonce`);
      const c = await verifyCommitPayload(payload, issuer, {
        now: this.#now,
        ownPopNonce: own,
        selfAid,
      });
      for (const g of c.tct.grants) grants.add(g);
    }
    return { grants: [...grants] };
  }

  // --- TCTs ----------------------------------------------------------------------

  async #verifyTct(p: JsonObject): Promise<JsonObject> {
    const audience = str(p, "expected_audience");
    const issuerKey = this.#issuerKey(p);
    const manifest = p.issuer_manifest;
    const manifestExpiry = isJsonObject(manifest) && typeof manifest.expires_at === "number" ? manifest.expires_at : undefined;
    const list = p.issuer_revocation_list;
    let mode: RevocationMode | undefined;
    let lookup: ((iss: Aid, jti: string) => Promise<RevocationStatus>) | undefined;
    if (isJsonObject(list)) {
      if (list.fail_mode !== undefined) {
        if (typeof list.fail_mode !== "string" || !REVOCATION_MODES.includes(list.fail_mode)) throw new Error("unknown fail_mode");
        mode = list.fail_mode as RevocationMode;
      }
      lookup = async (iss, jti) => {
        if (list.available === false || !("snapshot" in list)) return "unknown";
        const listIssuer = aidOf(list.issuer);
        if (listIssuer !== undefined && !sameKeyAid(listIssuer, iss)) return "unknown";
        return snapshotStatus(list.snapshot, iss, jti, this.#now);
      };
    }
    const tct = await verifyTct(p.tct_token, {
      now: this.#now,
      ...(audience !== undefined ? { expectedAudience: audience } : {}),
      ...(issuerKey !== undefined ? { issuerKey } : {}),
      ...(manifestExpiry !== undefined ? { issuerManifestExpiresAt: manifestExpiry } : {}),
      ...(lookup !== undefined ? { revocation: lookup } : {}),
      ...(mode !== undefined ? { revocationMode: mode } : {}),
    });
    return tctResult(tct);
  }

  /** `issuer_pubkey`, as raw key bytes in the algorithm of the TCT's `iss`. */
  #issuerKey(p: JsonObject): PublicKey | undefined {
    const text = str(p, "issuer_pubkey");
    if (text === undefined) return undefined;
    const iss = aidOf(peekClaims(p.tct_token)?.iss);
    const raw = b64.tryDecode(text);
    const key = iss === undefined || raw === undefined ? undefined : publicKeyFromRaw(iss.key.alg, raw);
    if (key === undefined) fail("TCT_SIGNATURE_INVALID", "issuer_pubkey is not a key in the iss algorithm");
    return key;
  }

  async #verifyTctAsIssuer(p: JsonObject): Promise<JsonObject> {
    const selfAid = configAid(p.self_aid, "self_aid");
    const outstanding = Array.isArray(p.outstanding_pop_challenges) ? p.outstanding_pop_challenges : [];
    const tct = await verifyTctAsIssuer(p.tct_token, {
      now: this.#now,
      selfAid,
      establishPresenter: (claims) => {
        const c = outstanding.find((x) => isJsonObject(x) && x.tct_jti === claims.jti);
        if (!isJsonObject(c) || typeof c.nonce !== "string") fail("POP_CHALLENGE_INVALID", "no outstanding challenge for this TCT");
        const challenge: PopChallenge = {
          tctJti: claims.jti,
          nonce: c.nonce,
          ...(typeof c.expires_at === "number" ? { expiresAt: c.expires_at } : {}),
        };
        return verifyPopResponse(p.envelope, challenge, claims, { now: this.#now, replay: this.#state.replay });
      },
    });
    return { ...tctResult(tct), presenter_aid: tct.sub.text, side_effects: { capability_authorized: true } };
  }

  // --- Downstream proof of possession -----------------------------------------------

  async #issuePopChallenge(p: JsonObject): Promise<JsonObject> {
    const tct = await verifyTct(p.tct_token, { now: this.#now });
    const { challenge } = await verifyPopChallenge(p.envelope, { now: this.#now, replay: this.#state.replay });
    if (challenge.tctJti !== tct.jti) fail("POP_CHALLENGE_INVALID", "challenge names another TCT");
    this.#state.pop = { tct, challenge };
    return { tct_jti: challenge.tctJti, nonce: challenge.nonce };
  }

  #producePopResponse(p: JsonObject): JsonObject {
    const pop = this.#state.pop;
    if (pop?.challenge === undefined) fail("POP_CHALLENGE_INVALID", "no challenge to respond to");
    pop.response = p.envelope;
    return {};
  }

  async #verifyPopResponse(): Promise<JsonObject> {
    const pop = this.#state.pop;
    if (pop?.challenge === undefined) fail("POP_CHALLENGE_INVALID", "no challenge outstanding");
    if (pop.response === undefined) fail("POP_RESPONSE_INVALID", "no response received");
    const presenter = await verifyPopResponse(pop.response, pop.challenge, pop.tct, { now: this.#now, replay: this.#state.replay });
    return { presenter_aid: presenter.text };
  }

  /**
   * A capability invocation presented to the TCT's issuer. A grant the
   * issuer's policy marks PoP-required (or every grant, under
   * `enforce-for-all`) is not authorized on the TCT alone: the issuer
   * challenges the presenter first (RFC-AITP-0005 §6).
   */
  async #authorizeInvocation(p: JsonObject): Promise<JsonObject> {
    const selfText = str(p, "self_aid");
    const claims = peekClaims(p.tct_token);
    const self = selfText !== undefined ? configAid(selfText, "self_aid") : aidOf(claims?.iss);
    if (self === undefined) fail("TCT_SIGNATURE_INVALID", "the TCT names no issuer");
    const { tct } = parseTct(p.tct_token);
    if (!sameKeyAid(tct.iss, self)) fail("TCT_SIGNATURE_INVALID", "TCT was not issued by this verifier");
    const verified = await verifyTct(p.tct_token, { now: this.#now, issuerKey: self.key });
    const invocation = await this.#invocationEnvelope(p.envelope, verified);
    const policy = isJsonObject(p.issuer_policy) ? p.issuer_policy : {};
    const required = strings(policy, "pop_required_grants") ?? [];
    const needsPop = policy.pop_posture === "enforce-for-all" || required.includes(invocation.capability);
    this.#state.invocation = { challengeIssued: needsPop, authorized: !needsPop };
    return needsPop
      ? { capability: invocation.capability, side_effects: { pop_challenge_issued: true, capability_authorized: false } }
      : { capability: invocation.capability, side_effects: { capability_authorized: true } };
  }

  /**
   * The invocation envelope: signed by the TCT's `sub`, naming the TCT, for a
   * capability the TCT grants. `capability_invocation` is an application
   * message, so only the envelope signature and these bindings are checked.
   */
  async #invocationEnvelope(envelope: unknown, tct: TctClaims): Promise<{ capability: string }> {
    if (!isJsonObject(envelope) || !isJsonObject(envelope.payload) || !isJsonObject(envelope.sender)) {
      fail("INVALID_ENVELOPE", "malformed invocation envelope");
    }
    const sender = aidOf(envelope.sender.agent_id);
    if (sender === undefined || typeof envelope.signature !== "string") fail("INVALID_ENVELOPE", "malformed invocation envelope");
    const r = await verifyJcsSignature(sender.key, envelopeSigningInput(envelope), envelope.signature);
    if (r !== "ok") fail("INVALID_SIGNATURE", `invocation signature: ${r}`);
    if (sender.text !== tct.sub.text) fail("POLICY_VIOLATION", "invocation sender is not the TCT subject");
    const { tct_jti: jti, capability } = envelope.payload;
    if (jti !== tct.jti) fail("POLICY_VIOLATION", "invocation names another TCT");
    if (typeof capability !== "string" || !tct.grants.includes(capability)) fail("POLICY_VIOLATION", "capability is not granted");
    return { capability };
  }

  #expectChallengeIssued(): JsonObject {
    if (this.#state.invocation?.challengeIssued !== true) fail("POLICY_VIOLATION", "no PoP challenge was issued");
    return { side_effects: { pop_challenge_issued: true } };
  }

  #withholdPopResponse(): JsonObject {
    const inv = this.#state.invocation;
    if (inv === undefined) throw new Error("no invocation in progress");
    if (inv.challengeIssued) fail("POP_RESPONSE_INVALID", "no pop_response arrived for the challenge");
    return { side_effects: { capability_authorized: inv.authorized } };
  }

  // --- Revocation ------------------------------------------------------------------

  async #verifyRevocationSnapshot(p: JsonObject): Promise<JsonObject> {
    const now = this.#nowFrom(p);
    const issuer = configAid(p.expected_issuer, "expected_issuer");
    const policy = isJsonObject(p.policy) ? p.policy : {};
    const mode = (str(policy, "fail_mode") ?? "fail_closed") as RevocationMode;
    if (!REVOCATION_MODES.includes(mode)) throw new Error("unknown fail_mode");
    const maxStaleness = num(policy, "max_staleness_secs");
    const v = await verifySnapshot(p.snapshot, issuer.key);
    const usable =
      sameKeyAid(v.issuer, issuer) && !isExpired(v.expiresAt, now) && (maxStaleness === undefined || now - v.publishedAt <= maxStaleness);
    const jti = str(p, "queried_jti");
    const status: RevocationStatus = !usable ? "unknown" : jti !== undefined && v.entries.some((e) => e.jti === jti) ? "revoked" : "not_revoked";
    const d = decideRevocation(status, mode);
    if (!d.allowed) fail("TCT_REVOKED", status === "revoked" ? "jti is revoked" : "snapshot unusable under fail_closed");
    return { status, degraded: d.degraded, entries: v.entries.length };
  }

  // --- Vouchers and delegation ---------------------------------------------------------

  async #verifyGrantVoucher(p: JsonObject): Promise<JsonObject> {
    const v = await verifyVoucher(p.voucher_token, { selfAid: configAid(p.verifier_aid, "verifier_aid"), now: this.#now });
    return { grants: [...v.grants], src_jti: v.srcJti, sub: v.sub.text };
  }

  async #verifyDelegationToken(p: JsonObject): Promise<JsonObject> {
    if (!("delegation_token" in p)) {
      // The frozen v0.1 delegation object: a `chain` is refused before
      // anything else is read. Any other v0.1 shape is not verified here.
      if (isJsonObject(p.delegation) && "chain" in p.delegation) {
        fail("DELEGATION_MULTIHOP_NOT_SUPPORTED", "multi-hop delegation (RFC-AITP-0011) is not supported");
      }
      throw new NotSupported("the v0.1 delegation object is not supported");
    }
    const now = this.#nowFrom(p);
    const self = configAid(p.self_aid, "self_aid");
    const manifests = Array.isArray(p.issuer_manifests) ? p.issuer_manifests : [];
    const snapshots = Array.isArray(p.revocation_snapshots) ? p.revocation_snapshots : [];
    const d = await verifyDelegation(p.delegation_token, {
      selfAid: self,
      now,
      resolveDelegatorKey: async (iss) => {
        const m = manifests.find((x) => isJsonObject(x) && x.aid === iss.text);
        if (m === undefined) return undefined;
        try {
          return (await verifyManifest(m, { now })).aid.key;
        } catch (e) {
          if (e instanceof AitpError) return undefined;
          throw e;
        }
      },
      isSourceRevoked: async (srcJti) => {
        for (const s of snapshots) {
          if (!isJsonObject(s) || aidOf(s.issuer_aid) === undefined || !sameKeyAid(aidOf(s.issuer_aid) as Aid, self)) continue;
          const v = await verifySnapshot(s.snapshot, self.key);
          if (v.entries.some((e) => e.jti === srcJti)) return true;
        }
        return false;
      },
      confirmPossession: "channel-bound",
    });
    return { delegator: d.iss.text, delegatee: d.sub.text, scope: [...d.scope], src_jti: d.voucher.srcJti };
  }
}

function tctResult(tct: VerifiedTct): JsonObject {
  return { jti: tct.jti, iss: tct.iss.text, sub: tct.sub.text, grants: [...tct.grants], degraded: tct.degraded };
}
