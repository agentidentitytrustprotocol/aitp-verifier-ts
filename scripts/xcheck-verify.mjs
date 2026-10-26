#!/usr/bin/env node
// Cross-implementation check: artifacts minted by aitp-rs (its xcheck-mint
// tool, read from stdin) verified by this verifier, byte for byte. Nothing
// is re-signed here: each negative changes exactly one thing in a positive
// artifact (a high-S twin, a stripped `p256.` tag, a withheld or confused
// key) or is a negative aitp-rs minted itself (the double-hashed digest).
//
//   cargo run -p mint-signed-examples --bin xcheck-mint | node scripts/xcheck-verify.mjs
//
// Needs `npm run build` first. Exits non-zero if any check fails.

import { readFileSync } from "node:fs";
import {
  AitpError,
  b64,
  parseAid,
  parseJson,
  pinnedKeyProofInput,
  publicKeyFromJwk,
  snapshotStatus,
  verifyEnvelope,
  verifyIdentity,
  verifyManifest,
  verifySnapshot,
  verifyTct,
} from "../dist/index.js";

const minted = parseJson(readFileSync(0, "utf8"));
if (minted.minted_by !== "aitp-rs") {
  console.error("stdin is not xcheck-mint output");
  process.exit(2);
}

// The verification time sits inside every artifact's validity window.
const now = minted.now + 100;
let failed = 0;

async function check(name, fn) {
  try {
    await fn();
    console.log(`  ok    ${name}`);
  } catch (e) {
    failed++;
    console.log(`  FAIL  ${name}\n          ${e instanceof AitpError ? e.code : e.name}: ${e.message}`);
  }
}

async function rejects(name, fn) {
  try {
    await fn();
  } catch (e) {
    if (e instanceof AitpError) {
      console.log(`  ok    ${name} (${e.code})`);
      return;
    }
    failed++;
    console.log(`  FAIL  ${name}\n          unexpected ${e.name}: ${e.message}`);
    return;
  }
  failed++;
  console.log(`  FAIL  ${name}\n          accepted`);
}

function assert(cond, message) {
  if (!cond) throw new Error(message);
}

function aid(text) {
  const a = parseAid(text);
  assert(a !== undefined, `not an AID: ${text}`);
  return a;
}

// ── Signature tampering ──────────────────────────────────────────────

const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

function bytesToBig(bytes) {
  return BigInt(`0x${Buffer.from(bytes).toString("hex")}`);
}

function bigTo32(n) {
  return Uint8Array.from(Buffer.from(n.toString(16).padStart(64, "0"), "hex"));
}

/** The (r, n - s) twin of a low-S P-256 signature: valid in raw ECDSA. */
function highS(raw) {
  assert(raw.length === 64, "not a raw P-256 signature");
  const s = bytesToBig(raw.subarray(32));
  return Uint8Array.from([...raw.subarray(0, 32), ...bigTo32(P256_N - s)]);
}

function p256Raw(field) {
  assert(field.startsWith("p256."), `expected a p256-tagged signature, got ${field.slice(0, 12)}`);
  return b64.decode(field.slice(5));
}

const highSTagged = (field) => `p256.${b64.encode(highS(p256Raw(field)))}`;
const untagged = (field) => b64.encode(p256Raw(field));

function highSJws(token) {
  const [h, p, s] = token.split(".");
  return `${h}.${p}.${b64.encode(highS(b64.decode(s)))}`;
}

// ── Verifier calls in the shape a relying party makes them ───────────

async function snapshot(snap, issuerText) {
  const issuer = aid(issuerText);
  const v = await verifySnapshot(snap, issuer.key);
  assert(v.issuer.text === issuerText, "snapshot issuer differs");
  // Every minted entry reads back as revoked, under fail_closed staleness.
  for (const e of v.entries) {
    const status = await snapshotStatus(snap, issuer, e.jti, now, { mode: "fail_closed", maxStalenessSecs: 86400 });
    assert(status === "revoked", `${e.jti} reads ${status}`);
  }
}

function contextOf(envelope) {
  return {
    senderAid: envelope.sender.agent_id,
    messageId: envelope.message_id,
    timestamp: envelope.timestamp,
    popNonce: envelope.payload.pop_nonce,
  };
}

function oidcIdentity(vec, proof, keys) {
  const identity = { type: "oidc", issuer: vec.issuer, subject: vec.subject, proof };
  return verifyIdentity(
    identity,
    { type: "oidc", issuer: vec.issuer, subject: vec.subject },
    contextOf(vec.envelope),
    aid(vec.envelope.sender.agent_id),
    {
      now: minted.oidc_identity.now + 100,
      selfAid: vec.self_aid,
      trustAnchors: [vec.issuer],
      resolveIssuerKeys: () => keys,
      pinnedKeys: [],
    },
  );
}

console.log("Minted by aitp-rs, verified by aitp-verifier-ts:");

await check("revocation snapshot", () => snapshot(minted.snapshot, minted.expected_issuer));
await check("revocation snapshot with populated extensions", () => snapshot(minted.snapshot_with_extensions, minted.expected_issuer));
await check("manifest (no extensions)", () => verifyManifest(minted.manifest_no_extensions, { now }));
await check("manifest with populated extensions", () => verifyManifest(minted.manifest_with_extensions, { now }));

for (const label of ["eddsa", "es256"]) {
  const vec = minted.oidc_identity[label];
  const key = publicKeyFromJwk(vec.issuer_jwk);
  await check(`oidc identity binding (${label})`, async () => {
    assert(key !== undefined, "issuer_jwk is not a supported key");
    await oidcIdentity(vec, vec.proof, [key]);
  });
  await rejects(`oidc identity binding (${label}) -- withheld issuer key is rejected`, () => oidcIdentity(vec, vec.proof, []));
  const [h, p, s] = vec.proof.split(".");
  const header = parseJson(new TextDecoder().decode(b64.decode(h)));
  const confused = { ...header, alg: label === "eddsa" ? "ES256" : "EdDSA" };
  const proof = `${b64.encode(new TextEncoder().encode(JSON.stringify(confused)))}.${p}.${s}`;
  await rejects(`oidc identity binding (${label}) -- alg-confusion header rewrite is rejected`, () => oidcIdentity(vec, proof, [key]));
}

console.log("\nP-256 legs (kat-keypair-005-p256):");

const p = minted.p256;
const pinned = p.pinned_key;
// The minted identity stands alone, not inside a MUTUAL_HELLO, so the hint
// it must match is its own: the checks under test are the key and proof.
const pinnedHint = { type: "pinned_key", subject: pinned.identity.subject, publicKey: pinned.identity.public_key };

function pinnedIdentity(identity, trusted = [p.aid]) {
  return verifyIdentity(identity, pinnedHint, contextOf(pinned.envelope), aid(pinned.envelope.sender.agent_id), {
    now,
    selfAid: p.verifier_aid,
    trustAnchors: [],
    resolveIssuerKeys: () => [],
    pinnedKeys: trusted.map(aid),
  });
}

async function tct(token, audience) {
  const issuer = aid(p.aid);
  return verifyTct(token, {
    now,
    expectedAudience: audience,
    revocation: (iss, jti) => snapshotStatus(p.snapshot, iss, jti, now, { maxStalenessSecs: 86400 }),
    revocationMode: "fail_closed",
    issuerKey: issuer.key,
  });
}

await check("p256 revocation snapshot", () => snapshot(p.snapshot, p.aid));
await check("p256 manifest (44-char pinned_key identity_hint)", () => verifyManifest(p.manifest, { now }));
await check("p256 envelope (single-hash JCS primitive)", () => verifyEnvelope(p.envelope, { now }));
await check("p256 pinned-key five-field proof input is byte-identical", () => {
  const ours = Buffer.from(pinnedKeyProofInput({ ...contextOf(pinned.envelope), receiverAid: p.verifier_aid })).toString("hex");
  assert(ours === pinned.proof_input_hex, `five-field input differs:\n  rs ${pinned.proof_input_hex}\n  ts ${ours}`);
});
await check("p256 pinned-key identity (tagged proof, pinned_keys store)", () => pinnedIdentity(pinned.identity));
await check("p256 TCT (ES256)", async () => {
  const out = await tct(p.tct, p.participant_aid);
  assert(JSON.stringify(out.grants) === '["session.participate"]', `unexpected grants ${JSON.stringify(out.grants)}`);
});
await check("p256 self-attestation is iss == sub == aud and rejected in a grant context", async () => {
  const claims = parseJson(new TextDecoder().decode(b64.decode(p.attestation.split(".")[1])));
  assert(claims.iss === p.aid && claims.sub === p.aid && claims.aud === p.aid, "attestation is not iss == sub == aud");
  try {
    await tct(p.attestation, p.aid);
  } catch (e) {
    if (e instanceof AitpError && e.code === "TCT_SIGNATURE_INVALID") return;
    throw e;
  }
  throw new Error("verifyTct accepted a self-attestation in a grant context");
});

await rejects("p256 envelope -- double-hashed digest is rejected", () => verifyEnvelope(p.envelope_double_hash, { now }));
await rejects("p256 envelope -- high-S twin is rejected", () =>
  verifyEnvelope({ ...p.envelope, signature: highSTagged(p.envelope.signature) }, { now }),
);
await rejects("p256 envelope -- untagged signature under a p256 AID is rejected", () =>
  verifyEnvelope({ ...p.envelope, signature: untagged(p.envelope.signature) }, { now }),
);
await rejects("p256 manifest -- high-S twin is rejected", () =>
  verifyManifest({ ...p.manifest, signature: highSTagged(p.manifest.signature) }, { now }),
);
await rejects("p256 revocation snapshot -- high-S twin is rejected", () =>
  verifySnapshot({ ...p.snapshot, signature: highSTagged(p.snapshot.signature) }, aid(p.aid).key),
);
await rejects("p256 TCT -- high-S ES256 twin is rejected", () => tct(highSJws(p.tct), p.participant_aid));
await rejects("p256 pinned-key -- high-S proof is rejected", () =>
  pinnedIdentity({ ...pinned.identity, proof: highSTagged(pinned.identity.proof) }),
);
await rejects("p256 pinned-key -- untagged proof is rejected", () =>
  pinnedIdentity({ ...pinned.identity, proof: untagged(pinned.identity.proof) }),
);
await rejects("p256 pinned-key -- key outside the pinned_keys store is rejected", () =>
  pinnedIdentity(pinned.identity, [minted.expected_issuer]),
);

// Session trust bundles are an experimental extension this verifier does
// not implement; say so rather than pass silently.
console.log("\n  skip  session trust bundles (experimental-session-bundle is not implemented)");

if (failed > 0) {
  console.error(`\n${failed} cross-implementation check(s) FAILED: aitp-rs and aitp-verifier-ts disagree on the wire.`);
  process.exit(1);
}
console.log("\nCross-implementation acceptance PASSED (no re-signing).");
