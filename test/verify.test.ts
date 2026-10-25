// The verify/ modules end to end: artifacts minted here from the KAT
// keypairs, then verified, with one negative per check whose position in
// the verification order matters.

import * as b64 from "../src/b64.js";
import { fromHex, utf8 } from "../src/bytes.js";
import { AitpError } from "../src/errors.js";
import { canonicalBytes } from "../src/jcs.js";
import type { JsonObject } from "../src/json.js";
import { type PrivateKey, ed25519FromSeed, p256FromScalar, signRaw } from "../src/keys.js";
import { type Aid, aidFor, parseAid } from "../src/aid.js";
import { jwkThumbprint } from "../src/jwk.js";
import { signCompactJws } from "../src/jws.js";
import { envelopeSigningInput, pinnedKeyProofInput } from "../src/proofs.js";
import { signJcs } from "../src/sigfield.js";
import { verifyEnvelope } from "../src/verify/envelope.js";
import { verifyManifest } from "../src/verify/manifest.js";
import { ReplayCache } from "../src/verify/replay.js";
import { snapshotStatus, verifySnapshot } from "../src/verify/revocation.js";
import { verifyTct, verifyTctAsIssuer } from "../src/verify/tct.js";
import { verifyPopResponse } from "../src/verify/pop.js";
import { verifyDelegation, verifyVoucher } from "../src/verify/delegation.js";
import { verifyMutualCommit, verifyMutualHello } from "../src/verify/handshake.js";
import { assert, eq, test } from "./harness.js";
import { str, vector } from "./spec.js";

const NOW = 1711900000;

interface Peer {
  readonly key: PrivateKey;
  readonly aid: Aid;
}

async function peer(id: string): Promise<Peer> {
  const v = vector("keypairs.json", id);
  const key =
    v.algorithm === "p256" ? await p256FromScalar(fromHex(str(v, "private_scalar_hex"))) : await ed25519FromSeed(fromHex(str(v, "seed_hex")));
  const aid = parseAid(aidFor(key.publicKey));
  if (aid === undefined) throw new Error(id);
  return { key, aid };
}

const A = await peer("kat-keypair-001");
const B = await peer("kat-keypair-002");
const C = await peer("kat-keypair-003");
const P = await peer("kat-keypair-005-p256");

/** The error code a verification ends with, or "ok". */
async function outcome(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return "ok";
  } catch (e) {
    if (e instanceof AitpError) return e.code;
    throw e;
  }
}

async function expectCode(p: Promise<unknown>, code: string, what = ""): Promise<void> {
  eq(await outcome(p), code, what);
}

let counter = 0;
function uuid(): string {
  counter += 1;
  return `550e8400-e29b-41d4-a716-${counter.toString(16).padStart(12, "0")}`;
}

const nonce = (byte: number) => b64.encode(new Uint8Array(16).fill(byte));

async function envelope(from: Peer, type: string, payload: JsonObject, extra: JsonObject = {}): Promise<JsonObject> {
  const e: JsonObject = {
    version: "aitp/0.3",
    message_type: type,
    message_id: uuid(),
    timestamp: NOW,
    sender: { agent_id: from.aid.text },
    payload,
    ...extra,
  };
  return { ...e, signature: await signJcs(from.key, envelopeSigningInput(e)) };
}

async function tctClaims(iss: Peer, sub: Peer, extra: JsonObject = {}): Promise<JsonObject> {
  return {
    ver: "aitp/0.3",
    jti: uuid(),
    iss: iss.aid.text,
    sub: sub.aid.text,
    aud: sub.aid.text,
    iat: NOW,
    exp: NOW + 3600,
    grants: ["macp.mode.task.v1"],
    cnf: { jkt: await jwkThumbprint(sub.aid.key) },
    ...extra,
  };
}

/** A JWS with an arbitrary header, for header negatives. */
async function rawJws(key: PrivateKey, header: JsonObject, claims: JsonObject): Promise<string> {
  const h = b64.encode(utf8(JSON.stringify(header)));
  const c = b64.encode(canonicalBytes(claims));
  return `${h}.${c}.${b64.encode(await signRaw(key, utf8(`${h}.${c}`)))}`;
}

function flipLastChar(sig: string): string {
  const last = sig.at(-1) === "A" ? "Q" : "A";
  return sig.slice(0, -1) + last;
}

// --- Envelope ---------------------------------------------------------------

test("envelope: order is replay, window, version, structure, members, signature", async () => {
  const replay = new ReplayCache();
  const e = await envelope(A, "mutual_hello", { x: 1 });
  await expectCode(verifyEnvelope(e, { now: NOW, replay }), "ok");
  await expectCode(verifyEnvelope(e, { now: NOW, replay }), "REPLAY_DETECTED", "second delivery");
  await expectCode(verifyEnvelope(e, { now: NOW + 301 }), "TIMESTAMP_EXPIRED");
  await expectCode(verifyEnvelope({ ...e, version: "aitp/0.2" }, { now: NOW }), "UNKNOWN_VERSION");
  await expectCode(verifyEnvelope({ ...e, version: "aitp/0.2", timestamp: 1 }, { now: NOW }), "TIMESTAMP_EXPIRED", "window first");
  await expectCode(verifyEnvelope({ ...e, surprise: true }, { now: NOW }), "UNKNOWN_FIELD");
  await expectCode(verifyEnvelope({ ...e, sender: { agent_id: A.aid.text, x: 1 } }, { now: NOW }), "UNKNOWN_FIELD", "sender member");
  await expectCode(verifyEnvelope({ ...e, signature: flipLastChar(e.signature as string) }, { now: NOW }), "INVALID_SIGNATURE");
  await expectCode(verifyEnvelope({ ...e, sender: { agent_id: B.aid.text } }, { now: NOW }), "INVALID_SIGNATURE", "wrong sender");
});

test("envelope: a failed message is not recorded as seen", async () => {
  const replay = new ReplayCache();
  const e = await envelope(A, "mutual_hello", {});
  await expectCode(verifyEnvelope({ ...e, signature: flipLastChar(e.signature as string) }, { now: NOW, replay }), "INVALID_SIGNATURE");
  await expectCode(verifyEnvelope(e, { now: NOW, replay }), "ok");
});

// --- Manifest ----------------------------------------------------------------

async function manifest(of: Peer, extra: JsonObject = {}): Promise<JsonObject> {
  const challenge = nonce(7);
  const body: JsonObject = {
    version: "aitp/0.3",
    aid: of.aid.text,
    handshake_endpoint: "https://agent.example.com/aitp/handshake",
    accepted_trust_anchors: [],
    accepted_identity_types: ["pinned_key"],
    offered_capabilities: ["macp.mode.task.v1"],
    required_peer_capabilities: [],
    identity_hint: { type: "pinned_key", subject: "worker", public_key: b64.encode(of.aid.key.raw) },
    proof_of_possession: { challenge, signature: await signJcs(of.key, b64.decode(challenge)) },
    published_at: NOW - 1000,
    expires_at: NOW + 86400,
    ...extra,
  };
  return { ...body, signature: await signJcs(of.key, canonicalBytes(body)) };
}

test("manifest: version, structure, members, expiry, PoP, signature", async () => {
  const m = await manifest(A);
  await expectCode(verifyManifest(m, { now: NOW }), "ok");
  await expectCode(verifyManifest(await manifest(P), { now: NOW }), "ok", "p256");
  await expectCode(verifyManifest({ ...m, version: "aitp/0.2" }, { now: NOW }), "MANIFEST_VERSION_UNKNOWN");
  await expectCode(verifyManifest({ ...m, handshake_endpoint: "http://x" }, { now: NOW }), "MANIFEST_INVALID");
  await expectCode(verifyManifest({ ...m, nickname: "x" }, { now: NOW }), "UNKNOWN_FIELD");
  await expectCode(verifyManifest(m, { now: NOW + 86400 }), "MANIFEST_EXPIRED");
  const pop = m.proof_of_possession as JsonObject;
  const badPop = { ...m, proof_of_possession: { ...pop, challenge: nonce(8) } };
  await expectCode(verifyManifest(badPop, { now: NOW }), "MANIFEST_POP_FAILED");
  await expectCode(verifyManifest({ ...m, offered_capabilities: ["admin"] }, { now: NOW }), "MANIFEST_SIGNATURE_INVALID");
});

// --- TCT -----------------------------------------------------------------------

test("tct: holder-side verification and its codes", async () => {
  const claims = await tctClaims(A, B);
  const token = await signCompactJws(A.key, "aitp-tct+jwt", claims);
  const t = await verifyTct(token, { now: NOW, expectedAudience: B.aid.text });
  eq(t.grants.join(), "macp.mode.task.v1");
  await expectCode(verifyTct(token, { now: NOW, expectedAudience: C.aid.text }), "AUDIENCE_MISMATCH");
  await expectCode(verifyTct(token, { now: NOW + 3600 }), "TCT_EXPIRED");
  await expectCode(verifyTct(token, { now: NOW, issuerManifestExpiresAt: NOW + 60 }), "TCT_EXPIRES_AFTER_MANIFEST");
  const sign = (c: JsonObject) => signCompactJws(A.key, "aitp-tct+jwt", c);
  await expectCode(verifyTct(await signCompactJws(A.key, "JWT", claims), { now: NOW }), "TOKEN_TYP_MISMATCH");
  await expectCode(verifyTct(await rawJws(A.key, { alg: "ES256", typ: "aitp-tct+jwt" }, claims), { now: NOW }), "TOKEN_ALG_MISMATCH");
  await expectCode(verifyTct(await rawJws(A.key, { alg: "none", typ: "aitp-tct+jwt" }, claims), { now: NOW }), "TOKEN_ALG_MISMATCH");
  await expectCode(verifyTct(await sign({ ...claims, role: "admin" }), { now: NOW }), "UNKNOWN_FIELD");
  await expectCode(verifyTct(await sign({ ...claims, ext: { anything: 1 } }), { now: NOW }), "ok", "ext is open");
  await expectCode(verifyTct(await sign({ ...claims, ver: "aitp/0.2" }), { now: NOW }), "UNKNOWN_VERSION");
  await expectCode(verifyTct(await sign({ ...claims, jti: "not-a-uuid" }), { now: NOW }), "TCT_SIGNATURE_INVALID");
  await expectCode(verifyTct(await sign({ ...claims, aud: C.aid.text }), { now: NOW }), "TCT_SIGNATURE_INVALID", "aud ≠ sub");
  await expectCode(verifyTct(await sign({ ...claims, cnf: { jkt: await jwkThumbprint(C.aid.key) } }), { now: NOW }), "TCT_SIGNATURE_INVALID");
  await expectCode(verifyTct(await sign(await tctClaims(A, A)), { now: NOW }), "TCT_SIGNATURE_INVALID", "self-issued");
  await expectCode(verifyTct(await sign({ ...claims, grants: ["aitp.attestation"] }), { now: NOW }), "TCT_SIGNATURE_INVALID");
  await expectCode(verifyTct(await signCompactJws(C.key, "aitp-tct+jwt", claims), { now: NOW }), "TCT_SIGNATURE_INVALID", "forged");
  const p256 = await signCompactJws(P.key, "aitp-tct+jwt", await tctClaims(P, B));
  await expectCode(verifyTct(p256, { now: NOW }), "ok", "ES256");
});

test("tct: revocation runs last, and unknown status fails closed by default", async () => {
  const claims = await tctClaims(A, B);
  const token = await signCompactJws(A.key, "aitp-tct+jwt", claims);
  let calls = 0;
  const unknown = () => {
    calls += 1;
    return "unknown" as const;
  };
  await expectCode(verifyTct(token, { now: NOW, revocation: unknown }), "TCT_REVOKED");
  await expectCode(verifyTct(token, { now: NOW, revocation: unknown, revocationMode: "fail_open" }), "ok");
  const soft = await verifyTct(token, { now: NOW, revocation: unknown, revocationMode: "soft_fail" });
  assert(soft.degraded, "soft_fail admits degraded");
  await expectCode(verifyTct(token, { now: NOW, revocation: () => "revoked", revocationMode: "fail_open" }), "TCT_REVOKED");
  eq(calls, 3);
  await expectCode(verifyTct(token, { now: NOW + 3600, revocation: unknown }), "TCT_EXPIRED");
  eq(calls, 3, "no lookup for a token that fails earlier");
});

test("tct: issuer side needs proof of possession from sub", async () => {
  const claims = await tctClaims(A, B);
  const token = await signCompactJws(A.key, "aitp-tct+jwt", claims);
  const challenge = { tctJti: claims.jti as string, nonce: nonce(3), expiresAt: NOW + 60 };
  const response = (from: Peer, n = challenge.nonce) =>
    signJcs(from.key, b64.decode(n)).then((sig) =>
      envelope(from, "pop_response", { tct_jti: claims.jti as string, nonce_echo: challenge.nonce, pop_signature: sig }),
    );
  const verify = (r: JsonObject, c = challenge) =>
    verifyTctAsIssuer(token, {
      now: NOW,
      selfAid: A.aid,
      establishPresenter: (t) => verifyPopResponse(r, c, t, { now: NOW }),
    });
  await expectCode(verify(await response(B)), "ok");
  await expectCode(verify(await response(B), { ...challenge, expiresAt: NOW - 50 }), "POP_CHALLENGE_INVALID");
  await expectCode(verify(await response(B, nonce(4))), "POP_RESPONSE_INVALID", "signature over another nonce");
  await expectCode(verify(await response(C)), "POP_RESPONSE_INVALID", "not the sub key");
  await expectCode(
    verifyTctAsIssuer(token, { now: NOW, selfAid: C.aid, establishPresenter: async () => B.aid }),
    "TCT_SIGNATURE_INVALID",
    "not our TCT",
  );
});

// --- Revocation snapshots ------------------------------------------------------------

async function snapshot(by: Peer, entries: JsonObject[], extra: JsonObject = {}): Promise<JsonObject> {
  const list: JsonObject = {
    version: "aitp/0.3",
    issuer: by.aid.text,
    published_at: NOW - 100,
    expires_at: NOW + 3600,
    entries,
    ...extra,
  };
  return { revocation_list: list, signature: await signJcs(by.key, canonicalBytes(list)) };
}

test("revocation: snapshot codes, and any discarded snapshot reads as unknown", async () => {
  const jti = uuid();
  const s = await snapshot(A, [{ jti, revoked_at: NOW - 10, reason: "key_compromised" }]);
  eq((await verifySnapshot(s, A.aid.key)).entries.length, 1);
  await expectCode(verifySnapshot(s, B.aid.key), "REVOCATION_SNAPSHOT_SIGNATURE_INVALID");
  await expectCode(verifySnapshot({ ...s, note: 1 }, A.aid.key), "UNKNOWN_FIELD");
  const list = s.revocation_list as JsonObject;
  await expectCode(verifySnapshot({ ...s, revocation_list: { ...list, version: "aitp/0.2" } }, A.aid.key), "REVOCATION_SNAPSHOT_INVALID");
  eq(await snapshotStatus(s, A.aid, jti, NOW), "revoked");
  eq(await snapshotStatus(s, A.aid, uuid(), NOW), "not_revoked");
  eq(await snapshotStatus(s, B.aid, jti, NOW), "unknown", "another issuer's key");
  eq(await snapshotStatus(s, A.aid, jti, NOW + 3600), "unknown", "expired");
  eq(await snapshotStatus(s, A.aid, jti, NOW, { maxStalenessSecs: 50 }), "unknown", "stale");
  eq(await snapshotStatus(await snapshot(A, [], { issuer: B.aid.text }), A.aid, jti, NOW), "unknown", "issuer label");
});

// --- Vouchers and delegation ------------------------------------------------------------

test("delegation: single hop under A's voucher", async () => {
  const srcJti = uuid();
  const voucherClaims: JsonObject = {
    ver: "aitp/0.3",
    iss: A.aid.text,
    sub: B.aid.text,
    grants: ["read_data", "write_data"],
    iat: NOW,
    exp: NOW + 3600,
    src_jti: srcJti,
  };
  const voucher = await signCompactJws(A.key, "aitp-grant+jwt", voucherClaims);
  eq((await verifyVoucher(voucher, { selfAid: A.aid, now: NOW })).srcJti, srcJti);
  await expectCode(verifyVoucher(voucher, { selfAid: A.aid, now: NOW + 3600 }), "DELEGATION_EXPIRED");
  await expectCode(verifyVoucher(voucher, { selfAid: B.aid, now: NOW }), "DELEGATION_INVALID_VOUCHER");

  const outer = async (extra: JsonObject = {}, signer = B) =>
    signCompactJws(signer.key, "aitp-delegation+jwt", {
      ver: "aitp/0.3",
      iss: B.aid.text,
      sub: C.aid.text,
      aud: A.aid.text,
      scope: ["read_data"],
      exp: NOW + 1800,
      cnf: { jkt: await jwkThumbprint(C.aid.key) },
      voucher,
      ...extra,
    });
  const options = {
    selfAid: A.aid,
    now: NOW,
    resolveDelegatorKey: (iss: Aid) => (iss.text === B.aid.text ? B.aid.key : undefined),
    isSourceRevoked: () => false,
    confirmPossession: "channel-bound" as const,
  };
  eq((await verifyDelegation(await outer(), options)).sub.text, C.aid.text);
  await expectCode(verifyDelegation(await outer({ chain: [] }), options), "DELEGATION_MULTIHOP_NOT_SUPPORTED");
  await expectCode(verifyDelegation(await outer({}, C), options), "DELEGATION_INVALID_SIGNATURE");
  await expectCode(verifyDelegation(await outer(), { ...options, resolveDelegatorKey: () => undefined }), "KEY_RESOLUTION_FAILED");
  await expectCode(verifyDelegation(await outer({ aud: C.aid.text }), options), "DELEGATION_AUDIENCE_MISMATCH");
  await expectCode(verifyDelegation(await outer({ scope: ["admin"] }), options), "DELEGATION_SCOPE_EXCEEDED");
  await expectCode(verifyDelegation(await outer({ exp: NOW + 7200 }), options), "DELEGATION_EXPIRED", "outlives voucher");
  await expectCode(verifyDelegation(await outer(), { ...options, isSourceRevoked: () => true }), "DELEGATION_SOURCE_TCT_REVOKED");
  const failPop = async () => {
    throw new Error("no response");
  };
  await expectCode(verifyDelegation(await outer(), { ...options, confirmPossession: failPop }), "DELEGATION_POP_FAILED");
});

// --- Mutual Handshake ----------------------------------------------------------------------

test("handshake: pinned-key MUTUAL_HELLO through policy", async () => {
  const m = await manifest(C);
  const popNonce = nonce(9);
  const base: JsonObject = {
    version: "aitp/0.3",
    message_type: "mutual_hello",
    message_id: uuid(),
    timestamp: NOW,
    sender: { agent_id: C.aid.text },
  };
  const proof = await signJcs(
    C.key,
    pinnedKeyProofInput({
      senderAid: C.aid.text,
      receiverAid: A.aid.text,
      messageId: base.message_id as string,
      timestamp: NOW,
      popNonce,
    }),
  );
  const payload: JsonObject = {
    identity: { type: "pinned_key", subject: "worker", public_key: b64.encode(C.aid.key.raw), proof },
    manifest: m,
    requested_grants: ["macp.mode.task.v1"],
    pop_nonce: popNonce,
  };
  const sign = async (p: JsonObject) => {
    const e = { ...base, payload: p };
    return { ...e, signature: await signJcs(C.key, envelopeSigningInput(e)) };
  };
  const options = {
    now: NOW,
    selfAid: A.aid.text,
    trustAnchors: [],
    resolveIssuerKeys: () => [],
    pinnedKeys: [C.aid],
  };
  const hello = await verifyMutualHello(await sign(payload), options);
  eq(hello.identity.type, "pinned_key");
  await expectCode(verifyMutualHello(await sign(payload), { ...options, pinnedKeys: [] }), "IDENTITY_FAILED");
  await expectCode(verifyMutualHello(await sign(payload), { ...options, selfAid: B.aid.text }), "IDENTITY_FAILED", "other receiver");
  await expectCode(
    verifyMutualHello(await sign(payload), { ...options, acceptedIdentityTypes: ["oidc"] }),
    "INCOMPATIBLE_IDENTITY_TYPE",
  );
  await expectCode(verifyMutualHello(await sign({ ...payload, extra: 1 }), options), "UNKNOWN_FIELD");
  await expectCode(verifyMutualHello(await sign({ ...payload, manifest: await manifest(B) }), options), "INVALID_ENVELOPE");
  const e = await sign(payload);
  await expectCode(verifyMutualHello({ ...e, signature: flipLastChar(e.signature as string) }, options), "INVALID_SIGNATURE");
});

test("handshake: MUTUAL_COMMIT nonce echo, PoP signature, then the TCT", async () => {
  const own = nonce(5);
  const commit = async (extra: JsonObject = {}, signer = A) =>
    envelope(signer, "mutual_commit", {
      tct: await signCompactJws(A.key, "aitp-tct+jwt", await tctClaims(A, B)),
      pop_signature: await signJcs(signer.key, b64.decode(own)),
      pop_nonce_echo: own,
      ...extra,
    });
  const options = { now: NOW, selfAid: B.aid.text, ownPopNonce: own, grantBound: ["macp.mode.task.v1"] };
  eq((await verifyMutualCommit(await commit(), "mutual_commit", options)).tct.iss.text, A.aid.text);
  await expectCode(verifyMutualCommit(await commit({ pop_nonce_echo: nonce(6) }), "mutual_commit", options), "NONCE_MISMATCH");
  const wrongSig = await signJcs(A.key, b64.decode(nonce(6)));
  await expectCode(verifyMutualCommit(await commit({ pop_signature: wrongSig }), "mutual_commit", options), "POP_VERIFICATION_FAILED");
  await expectCode(verifyMutualCommit(await commit(), "mutual_commit", { ...options, selfAid: C.aid.text }), "AUDIENCE_MISMATCH");
  await expectCode(verifyMutualCommit(await commit(), "mutual_commit", { ...options, grantBound: [] }), "GRANT_OVERFLOW");
  await expectCode(
    verifyMutualCommit(await commit(), "mutual_commit", { ...options, requiredPeerCapabilities: ["macp.session.start"] }),
    "INSUFFICIENT_GRANTS",
  );
  await expectCode(verifyMutualCommit(await commit({ note: 1 }), "mutual_commit", options), "UNKNOWN_FIELD");
});
