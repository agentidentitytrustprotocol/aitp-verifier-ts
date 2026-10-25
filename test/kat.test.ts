// The known-answer vectors at the pinned spec commit
// (schemas/conformance/known-answer). Every value is checked as committed:
// nothing is re-minted before it is verified.

import * as b64 from "../src/b64.js";
import { concat, fromHex, toHex, utf8 } from "../src/bytes.js";
import { canonicalBytes } from "../src/jcs.js";
import { type JsonObject, isJsonObject } from "../src/json.js";
import { type PrivateKey, ed25519FromSeed, p256FromScalar, sha256, verifyRaw } from "../src/keys.js";
import { aidFor, parseAid, type Aid } from "../src/aid.js";
import { jwkThumbprint, jwkThumbprintInput, publicKeyFromJwk } from "../src/jwk.js";
import { parseSignatureField, signJcs, verifyJcsPrimitive, verifyJcsSignature } from "../src/sigfield.js";
import { expectedAlg, headerProblem, parseCompactJws, signCompactJws, verifyJwsSignature } from "../src/jws.js";
import { derivedUuid } from "../src/fields.js";
import { envelopeSigningInput, pinnedKeyProofInput, popInput, spiffeX509ProofInput } from "../src/proofs.js";
import { assert, eq, test } from "./harness.js";
import { KAT, readJson, str, vector, vectors } from "./spec.js";

function aid(text: string): Aid {
  const a = parseAid(text);
  if (a === undefined) throw new Error(`not an AID: ${text}`);
  return a;
}

async function privateKey(id: string): Promise<PrivateKey> {
  const v = vector("keypairs.json", id);
  return v.algorithm === "p256" ? p256FromScalar(fromHex(str(v, "private_scalar_hex"))) : ed25519FromSeed(fromHex(str(v, "seed_hex")));
}

const ok = async (p: Promise<string>) => eq(await p, "ok");
const notOk = async (p: Promise<string>, why = "") => assert((await p) !== "ok", `must not verify ${why}`);

test("keypairs: seed or scalar → public key → AID", async () => {
  const all = vectors("keypairs.json");
  eq(all.length, 7, "vector count");
  for (const v of all) {
    const key = await privateKey(str(v, "id"));
    eq(b64.encode(key.publicKey.raw), str(v, "pubkey_b64url"), str(v, "id"));
    if (typeof v.pubkey_compressed_hex === "string") eq(toHex(key.publicKey.raw), v.pubkey_compressed_hex);
    const text = str(v, "aid");
    eq(aidFor(key.publicKey, { tagged: text.startsWith("aid:pubkey:ed25519:") }), text);
    const parsed = aid(text);
    eq(b64.encode(parsed.key.raw), str(v, "pubkey_b64url"));
  }
  const tagged = vector("keypairs.json", "kat-keypair-001-tagged");
  const a = aid(str(tagged, "aid"));
  const b = aid(str(tagged, "untagged_aid"));
  assert(a.text !== b.text && a.key.alg === b.key.alg && b64.encode(a.key.raw) === b64.encode(b.key.raw));
});

test("jwk-thumbprints: canonical JWK input and jkt", async () => {
  const all = vectors("jwk-thumbprints.json");
  eq(all.length, 5, "vector count");
  for (const v of all) {
    const kp = vector("keypairs.json", str(v, "keypair_ref"));
    const key = aid(str(kp, "aid")).key;
    eq(jwkThumbprintInput(key), str(v, "jwk_canonical"), str(v, "id"));
    eq(toHex(utf8(jwkThumbprintInput(key))), str(v, "jwk_canonical_hex"));
    eq(await jwkThumbprint(key), str(v, "jkt"), str(v, "id"));
  }
});

test("oidc-test-issuers: seeds match the published JWKs", async () => {
  for (const v of vectors("oidc-test-issuers.json")) {
    const key = await ed25519FromSeed(fromHex(str(v, "seed_hex")));
    eq(b64.encode(key.publicKey.raw), str(v, "pubkey_b64url"), str(v, "id"));
    const fromJwk = publicKeyFromJwk(v.jwk);
    eq(fromJwk === undefined ? "" : b64.encode(fromJwk.raw), str(v, "pubkey_b64url"));
  }
});

test("jcs-sha256: JCS-profile bodies → canonical bytes → digest", async () => {
  for (const v of vectors("jcs-sha256.json").filter((x) => x.signing_input === "body")) {
    const bytes = canonicalBytes(v.object);
    eq(toHex(bytes), str(v, "jcs_canonical_hex"), str(v, "id"));
    eq(bytes.length, v.jcs_canonical_len_bytes);
    eq(toHex(await sha256(bytes)), str(v, "sha256_hex"));
    eq(b64.encode(await sha256(bytes)), str(v, "sha256_b64url"));
  }
});

test("kat-session-bundle-001: coordinator signature over the body", async () => {
  const v = vector("jcs-sha256.json", "kat-session-bundle-001");
  const coordinator = aid(str(v.object as JsonObject, "coordinator"));
  await ok(verifyJcsSignature(coordinator.key, canonicalBytes(v.object), str(v, "coordinator_signature_b64url")));
});

test("kat-manifest-pop-001/002: PoP over the decoded challenge", async () => {
  for (const id of ["kat-manifest-pop-001", "kat-manifest-pop-002-p256"]) {
    const v = vector("jcs-sha256.json", id);
    const input = popInput(str(v, "challenge"));
    eq(toHex(input), str(v, "decoded_hex"));
    eq(toHex(await sha256(input)), str(v, "sha256_hex"));
    const signer = aid(str(v, "signer_aid"));
    const field = typeof v.signature === "string" ? v.signature : str(v, "signature_b64url");
    await ok(verifyJcsSignature(signer.key, input, field));
    // The ASCII form of the challenge is not the input.
    await notOk(verifyJcsSignature(signer.key, utf8(str(v, "challenge")), field), "over ASCII challenge");
    if (typeof v.double_hash_signature_MUST_NOT_verify === "string") {
      await notOk(verifyJcsSignature(signer.key, input, v.double_hash_signature_MUST_NOT_verify), "double hash");
    }
  }
  // The Ed25519 PoP is deterministic: every PoP path must reproduce it.
  const v = vector("jcs-sha256.json", "kat-manifest-pop-001");
  const key = await privateKey(str(v, "signing_keypair_id"));
  eq(await signJcs(key, popInput(str(v, "challenge"))), str(v, "signature_b64url"));
});

test("kat-pinned-key-proof-*: proof input and signature", async () => {
  for (const id of ["kat-pinned-key-proof-001", "kat-pinned-key-proof-002-p256", "kat-pinned-key-proof-003-tagged-ed25519"]) {
    const v = vector("jcs-sha256.json", id);
    const ctx = {
      senderAid: str(v, "sender_aid"),
      receiverAid: str(v, "receiver_aid"),
      messageId: str(v, "message_id"),
      timestamp: v.timestamp as number,
      popNonce: str(v, "pop_nonce"),
    };
    const input = pinnedKeyProofInput(ctx);
    eq(toHex(input), str(v, "proof_input_hex"), id);
    eq(input.length, v.proof_input_len_bytes);
    eq(toHex(await sha256(input)), str(v, "sha256_hex"));
    const signer = aid(str(v, "signer_aid"));
    const field = typeof v.signature === "string" ? v.signature : str(v, "signature_b64url");
    await ok(verifyJcsSignature(signer.key, input, field));
    if (signer.key.alg === "ed25519") {
      await ok(verifyJcsSignature(signer.key, input, `ed25519.${str(v, "signature_b64url")}`));
      await notOk(verifyJcsSignature(signer.key, input, `p256.${str(v, "signature_b64url")}`), "tag mismatch");
      const key = await privateKey(str(v, "signing_keypair_id"));
      eq(await signJcs(key, input), str(v, "signature_b64url"), "re-sign");
    } else {
      // An untagged proof from a p256 sender reads as ed25519.
      eq(await verifyJcsSignature(signer.key, input, str(v, "signature_b64url")), "alg_mismatch");
      await notOk(verifyJcsSignature(signer.key, input, str(v, "double_hash_signature_MUST_NOT_verify")), "double hash");
    }
  }
  // -001: the erratum. An 8-byte big-endian timestamp is not the input.
  const v = vector("jcs-sha256.json", "kat-pinned-key-proof-001");
  const ts = new Uint8Array(8);
  new DataView(ts.buffer).setBigInt64(0, BigInt(v.timestamp as number));
  const nul = new Uint8Array([0]);
  const be = concat(
    utf8("aitp-pinned-key-v1"), nul, utf8(str(v, "sender_aid")), nul, utf8(str(v, "receiver_aid")), nul,
    utf8(str(v, "message_id")), nul, ts, nul, b64.decode(str(v, "pop_nonce")),
  );
  await notOk(verifyJcsSignature(aid(str(v, "signer_aid")).key, be, str(v, "signature_b64url")), "big-endian timestamp");
  // -003's input carries the tagged sender string, so -001's proof fails there.
  const v3 = vector("jcs-sha256.json", "kat-pinned-key-proof-003-tagged-ed25519");
  await notOk(verifyJcsSignature(aid(str(v3, "signer_aid")).key, fromHex(str(v3, "proof_input_hex")), str(v, "signature_b64url")));
});

test("kat-spiffe-x509-proof-001: domain-separated proof input", async () => {
  const v = vector("jcs-sha256.json", "kat-spiffe-x509-proof-001");
  const ctx = {
    senderAid: str(v, "sender_aid"),
    receiverAid: str(v, "receiver_aid"),
    messageId: str(v, "message_id"),
    timestamp: v.timestamp as number,
    popNonce: str(v, "pop_nonce"),
  };
  const input = spiffeX509ProofInput(ctx);
  eq(toHex(input), str(v, "proof_input_hex"));
  eq(toHex(await sha256(input)), str(v, "sha256_hex"));
  const sig = str(v, "signature_b64url");
  await ok(verifyJcsSignature(aid(str(v, "signer_aid")).key, input, sig));
  await notOk(verifyJcsSignature(aid(str(v, "sender_aid")).key, input, sig), "under the AID key");
  await notOk(verifyJcsSignature(aid(str(v, "signer_aid")).key, pinnedKeyProofInput(ctx), sig), "over the pinned-key input");
});

test("kat-p256-jcs-sign-001: e = d, low S", async () => {
  const v = vector("jcs-sha256.json", "kat-p256-jcs-sign-001");
  const input = fromHex(str(v, "preimage_hex"));
  eq(toHex(canonicalBytes(v.preimage_json)), str(v, "preimage_hex"));
  eq(toHex(await sha256(input)), str(v, "sha256_hex"));
  const signer = aid(str(v, "signer_aid"));
  await ok(verifyJcsSignature(signer.key, input, str(v, "signature")));
  await notOk(verifyJcsSignature(signer.key, input, str(v, "double_hash_signature_MUST_NOT_verify")), "double hash");
  await notOk(verifyJcsSignature(signer.key, input, str(v, "high_s_sibling_MUST_NOT_verify")), "high S");
  // A fresh P-256 signature from the pinned scalar verifies and is low-S.
  const key = await privateKey(str(v, "signing_keypair_id"));
  for (let i = 0; i < 8; i++) await ok(verifyJcsSignature(signer.key, input, await signJcs(key, input)));
});

test("kat-derived-uuid-001", async () => {
  const v = vector("jcs-sha256.json", "kat-derived-uuid-001");
  const input = fromHex(str(v, "input_hex"));
  eq(toHex(concat(utf8(str(v, "domain_tag")), new Uint8Array([0]), input)), str(v, "preimage_hex"));
  eq(await derivedUuid(str(v, "domain_tag"), input), str(v, "uuid"));
});

test("signature-strictness: §5.4.7 rejections", async () => {
  const sig1 = vector("signature-strictness.json", "sig-001-ed25519-small-order-key-rejected");
  const key1 = { alg: "ed25519" as const, raw: b64.decode(str(sig1, "public_key_b64url")) };
  eq(await verifyRaw(key1, fromHex(str(sig1, "message_hex")), b64.decode(str(sig1, "signature_b64url"))), false, "sig-001");

  const sig2 = vector("signature-strictness.json", "sig-002-ed25519-noncanonical-s-rejected");
  const key2 = aid(str(sig2, "signer_aid")).key;
  const msg2 = fromHex(str(sig2, "message_hex"));
  eq(await verifyRaw(key2, msg2, b64.decode(str(sig2, "valid_signature_b64url"))), true, "sig-002 valid sibling");
  eq(await verifyRaw(key2, msg2, b64.decode(str(sig2, "signature_b64url"))), false, "sig-002");

  const sig3 = vector("signature-strictness.json", "sig-003-p256-high-s-rejected");
  const key3 = aid(str(sig3, "signer_aid")).key;
  const pre = vector("jcs-sha256.json", "kat-p256-jcs-sign-001");
  const input3 = fromHex(str(pre, "preimage_hex"));
  eq(toHex(await sha256(input3)), str(sig3, "sha256_hex"));
  await ok(verifyJcsSignature(key3, input3, str(sig3, "low_s_signature")));
  eq(await verifyJcsSignature(key3, input3, str(sig3, "signature")), "bad_signature", "sig-003");
  // r = 0 and r = n are out of range.
  const zero = new Uint8Array(64);
  zero.set(parseSignatureField(str(sig3, "low_s_signature"))!.bytes.subarray(32), 32);
  eq(await verifyJcsPrimitive(key3, input3, zero), false, "r = 0");
});

const SE = KAT + "signed-examples/";

function signedJws(file: string, member: string): { file: JsonObject; token: string } {
  const f = readJson(SE + file);
  return { file: f, token: str(f, member) };
}

test("signed-examples: compact JWS artifacts verify as committed", async () => {
  const cases: [string, string, string, string][] = [
    ["tct/kat-keypair-001-issues-002.json", "tct_token", "aitp-tct+jwt", "iss"],
    ["tct/kat-keypair-005-issues-002.json", "tct_token", "aitp-tct+jwt", "iss"],
    ["tct/kat-keypair-001-self-attestation.json", "tct_token", "aitp-tct+jwt", "iss"],
    ["tct/kat-keypair-005-self-attestation.json", "tct_token", "aitp-tct+jwt", "iss"],
    ["grant-voucher/kat-voucher-001.json", "voucher_token", "aitp-grant+jwt", "iss"],
    ["delegation/single-hop-001-002-003.json", "delegation_token", "aitp-delegation+jwt", "iss"],
  ];
  for (const [file, member, typ, signerClaim] of cases) {
    const { file: f, token } = signedJws(file, member);
    const jws = parseCompactJws(token);
    eq(toHex(canonicalBytes(jws.claims)), toHex(canonicalBytes(f.decoded_claims)), `${file} decoded_claims`);
    const signer = aid(str(jws.claims, signerClaim));
    eq(headerProblem(jws.header, typ, expectedAlg(signer.key.alg)), undefined, `${file} header`);
    assert(await verifyJwsSignature(jws, signer.key), `${file} signature`);
    // The signer's thumbprint binding: cnf.jkt names the subject's key.
    if (isJsonObject(jws.claims.cnf)) {
      eq(await jwkThumbprint(aid(str(jws.claims, "sub")).key), jws.claims.cnf.jkt, `${file} cnf.jkt`);
    }
    // Pinned alg and typ come from the AID and the context, never the token.
    eq(headerProblem(jws.header, "aitp-other+jwt", expectedAlg(signer.key.alg)), "typ");
    eq(headerProblem(jws.header, typ, signer.key.alg === "ed25519" ? "ES256" : "EdDSA"), "alg");
    const mustNot = f._must_not_verify;
    if (isJsonObject(mustNot) && typeof mustNot.double_hash_jws === "string") {
      const bad = parseCompactJws(mustNot.double_hash_jws);
      assert(!(await verifyJwsSignature(bad, signer.key)), `${file} double-hash JWS must not verify`);
    }
    // One flipped signature bit, or a re-encoded payload, breaks it.
    const [h, p, s] = token.split(".") as [string, string, string];
    const flipped = b64.decode(s);
    flipped[0] = (flipped[0] as number) ^ 1;
    assert(!(await verifyJwsSignature(parseCompactJws(`${h}.${p}.${b64.encode(flipped)}`), signer.key)), `${file} tampered`);
    const spaced = b64.encode(utf8(` ${new TextDecoder().decode(b64.decode(p))}`));
    assert(!(await verifyJwsSignature(parseCompactJws(`${h}.${spaced}.${s}`), signer.key)), `${file} re-serialized`);
  }
});

test("signed-examples: delegation embeds kat-voucher-001 verbatim", () => {
  const d = parseCompactJws(signedJws("delegation/single-hop-001-002-003.json", "delegation_token").token);
  eq(d.claims.voucher, signedJws("grant-voucher/kat-voucher-001.json", "voucher_token").token);
});

test("signed-examples: Ed25519 JWS minting is byte-reproducible", async () => {
  const { file: f, token } = signedJws("tct/kat-keypair-001-issues-002.json", "tct_token");
  const key = await privateKey(str(f._kat_input as JsonObject, "issuer_seed_id"));
  eq(await signCompactJws(key, "aitp-tct+jwt", f.decoded_claims as JsonObject), token);
});

test("signed-examples: envelopes sign sig_input_v2", async () => {
  for (const file of ["envelope/kat-keypair-001-envelope.json", "envelope/kat-keypair-005-envelope.json"]) {
    const f = readJson(SE + file);
    eq(f.signing_input, "sig_input_v2");
    const env = f.envelope as JsonObject;
    const input = envelopeSigningInput(env);
    eq(toHex(input), str(f, "sig_input_v2_hex"), file);
    eq(input.length, f.sig_input_v2_len_bytes);
    eq(toHex(await sha256(input)), str(f, "sig_input_v2_sha256_hex"));
    const sender = aid(str(env.sender as JsonObject, "agent_id"));
    await ok(verifyJcsSignature(sender.key, input, str(env, "signature")));
    const mustNot = f._must_not_verify as JsonObject;
    await notOk(verifyJcsSignature(sender.key, input, str(mustNot, "v1_signature")), `${file} v1`);
    // The v1 value is a real signature over the retired pipe input.
    await ok(verifyJcsSignature(sender.key, utf8(str(mustNot, "v1_sig_input")), str(mustNot, "v1_signature")));
    if (typeof mustNot.double_hash_signature === "string") {
      await notOk(verifyJcsSignature(sender.key, input, mustNot.double_hash_signature), `${file} double hash`);
    }
  }
});

function withoutSignature(o: JsonObject): JsonObject {
  const { signature: _s, ...rest } = o;
  return rest;
}

test("signed-examples: Manifests sign the body; PoP signs the challenge", async () => {
  for (const file of ["manifest/kat-keypair-001-manifest.json", "manifest/kat-keypair-005-manifest.json"]) {
    const f = readJson(SE + file);
    eq(f.signing_input, "body");
    const m = f.manifest as JsonObject;
    const key = aid(str(m, "aid")).key;
    const body = canonicalBytes(withoutSignature(m));
    await ok(verifyJcsSignature(key, body, str(m, "signature")));
    await notOk(verifyJcsSignature(key, canonicalBytes({ manifest: withoutSignature(m) }), str(m, "signature")), "wrapper");
    const pop = m.proof_of_possession as JsonObject;
    await ok(verifyJcsSignature(key, popInput(str(pop, "challenge")), str(pop, "signature")));
    if (isJsonObject(f._must_not_verify)) {
      await notOk(verifyJcsSignature(key, body, str(f._must_not_verify, "double_hash_signature")), "double hash");
      await notOk(verifyJcsSignature(key, popInput(str(pop, "challenge")), str(f._must_not_verify, "double_hash_pop_signature")), "double hash PoP");
    } else {
      eq(await signJcs(await privateKey(str(f._kat_input as JsonObject, "issuer_seed_id")), body), str(m, "signature"), "re-sign");
    }
  }
});

test("signed-examples: revocation snapshots sign the inner list", async () => {
  for (const file of ["revocation/kat-keypair-001-snapshot.json", "revocation/kat-keypair-005-snapshot.json"]) {
    const f = readJson(SE + file);
    eq(f.signing_input, "body");
    const list = f.revocation_list as JsonObject;
    const key = aid(str(list, "issuer")).key;
    await ok(verifyJcsSignature(key, canonicalBytes(list), str(f, "signature")));
    await notOk(verifyJcsSignature(key, canonicalBytes({ revocation_list: list }), str(f, "signature")), "wrapper");
    if (isJsonObject(f._must_not_verify)) {
      await notOk(verifyJcsSignature(key, canonicalBytes(list), str(f._must_not_verify, "double_hash_signature")), "double hash");
    }
  }
});

test("signed-examples: session bundle signs its body", async () => {
  const f = readJson(SE + "session-bundle/kat-keypair-001-bundle.json");
  const bundle = f.session_bundle as JsonObject;
  const key = aid(str(bundle, "coordinator")).key;
  const body = canonicalBytes(withoutSignature(bundle));
  eq(toHex(body), str(vector("jcs-sha256.json", "kat-session-bundle-001"), "jcs_canonical_hex"));
  await ok(verifyJcsSignature(key, body, str(bundle, "signature")));
  await notOk(verifyJcsSignature(key, canonicalBytes({ session_bundle: withoutSignature(bundle) }), str(bundle, "signature")), "wrapper");
});
