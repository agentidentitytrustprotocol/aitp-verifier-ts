# aitp-verifier-ts

An independent TypeScript verifier for the
[Agent Identity & Trust Protocol](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol)
(AITP) v0.3, written from the RFCs.

- **Strict TypeScript, ESM only.**
- **Zero runtime dependencies.** All cryptography is WebCrypto
  (`globalThis.crypto.subtle`). There is no JOSE library: the compact JWS
  profile is implemented from RFC 7515 and RFC-AITP-0001 §5.4.5.
- **Spec-pinned.** `SPEC_VERSION` names the spec commit this package
  implements. The known-answer vectors and the error-code registry at that
  commit are vendored under `vendor/spec/`. CI checks both against a spec
  checkout at the pin. `src/errors.ts` is generated from the registry.

> Status: TS4.4 of the
> [adoption plan](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/plans/cross-repo/aitp-ts-verifier-adoption-90-day.md).
> Under `aitp-conformance` the adapter passes the "AITP v0.3" core claim at
> the pinned spec commit with no core fixture skipped. Artifacts that aitp-rs
> mints verify here. Releases publish to npm from CI with provenance.

## Install

```sh
npm i @agentidentitytrustprotocol/verifier
```

```js
import { parseJson, systemNow, verifyEnvelope } from "@agentidentitytrustprotocol/verifier";

// parseJson rejects duplicate keys, which JSON.parse silently accepts.
const envelope = await verifyEnvelope(parseJson(message), { now: systemNow() });
```

## Runtimes

| Runtime | Supported | Checked in CI |
|---|---|---|
| Node.js | 20, 22 and later | 20, 22 |
| Deno | 2.x | 2.9.8 |
| Bun | 1.3 and later | not yet (the suite passes locally) |
| Browsers | Any with WebCrypto Ed25519 and P-256 | not yet |

Ed25519 needs WebCrypto Ed25519 support. Where a runtime lacks it,
`ed25519Available()` returns false. Verification then fails closed with
`AlgorithmUnavailableError`: it never passes.

## Verifiers

Every verifier takes `now` (Unix seconds) and its trust inputs as
arguments. Each failure throws an `AitpError` whose `code` is a registry
code, and each verifier runs its checks in the order its RFC fixes.

| Function | Verifies | Spec |
|---|---|---|
| `verifyEnvelope` | Envelope replay, timestamp window, version, structure, member set, then signature. | RFC-AITP-0001 §5; RFC-AITP-0009 §3.1 |
| `verifyManifest` | Manifest version, structure, member set, expiry, proof of possession, then signature. | RFC-AITP-0003 §5 |
| `verifyIdentity` | OIDC and pinned-key identity bindings, with the trust-anchor check before any key resolution. | RFC-AITP-0002; RFC-AITP-0004 §5.1 step 6 |
| `verifyMutualHello`, `verifyMutualHelloAck` | Round 1 of the handshake: the trust bootstrap from the inline Manifest, identity, then policy. | RFC-AITP-0004 §5.1, §5.2 |
| `verifyMutualCommit`, `verifyCommitPayload` | Round 2: nonce echo, PoP signature, the TCT, then grant bounds. | RFC-AITP-0004 §5.3, §5.4 |
| `verifyTct` | Holder-side TCT verification, with revocation behind a callback that is only reached last. | RFC-AITP-0005 §7.2 |
| `verifyTctAsIssuer` | A TCT presented back to its issuer, with downstream proof of possession. | RFC-AITP-0005 §10.5 |
| `verifyPopChallenge`, `verifyPopResponse` | Downstream proof of possession. | RFC-AITP-0005 §6 |
| `verifySnapshot`, `snapshotStatus`, `decideRevocation` | Signed revocation snapshots, and the revocation mode (default `fail_closed`). | RFC-AITP-0008 |
| `verifyVoucher`, `verifyDelegation` | Grant vouchers and single-hop delegation tokens. | RFC-AITP-0005 §8; RFC-AITP-0006 §4 |

## Conformance adapter

`bin/aitp-verifier-adapter.mjs` speaks the `aitp-conformance` NDJSON adapter
protocol over stdin and stdout. It maps fixture inputs onto the verifiers
above. The package ships it as the `aitp-verifier-adapter` bin, along with the
spec's OIDC test-issuer keys it trusts. Its `init` reply reports the commit
stamped at build time.

```sh
npm i @agentidentitytrustprotocol/verifier
aitp-conformance run --target node_modules/.bin/aitp-verifier-adapter \
  --fixtures-dir ../agentidentitytrustprotocol/schemas/conformance
```

From a checkout, run `npm run build` and use `bin/aitp-verifier-adapter.mjs`
as the target.

| Op | Verifier |
|---|---|
| `verify_envelope` | `verifyEnvelope`, or the replay, policy or key-resolution case the fixture describes |
| `verify_manifest` | `verifyManifest` |
| `verify_handshake_payload` | `verifyMutualHello`, `verifyMutualHelloAck`, `verifyMutualCommit`, `verifyCommitPayload` |
| `process_handshake_message` | message-id replay |
| `verify_tct` | `verifyTct` with the fixture's revocation list |
| `verify_tct_as_issuer` | `verifyTctAsIssuer` with `verifyPopResponse` |
| `issue_pop_challenge`, `produce_pop_response`, `verify_pop_response` | `verifyPopChallenge`, `verifyPopResponse` |
| `authorize_capability_invocation`, `expect_pop_challenge_issued`, `withhold_pop_response` | issuer-side PoP enforcement over `verifyTct` |
| `verify_revocation_snapshot` | `verifySnapshot` and `decideRevocation` |
| `verify_grant_voucher` | `verifyVoucher` |
| `verify_delegation_token` | `verifyDelegation`; the frozen v0.1 object is refused at its `chain` (del-004) and otherwise not verified |

Receive-side handshake ops need the fixture's `self_aid`. Without it the
reply is `MALFORMED_REQUEST`, as it is for a line that is not JSON. The
audience checks are never skipped.

## CI

All of these run against the spec commit in `SPEC_VERSION`. Runner and
minter come from the aitp-rs commit in `AITP_RS_COMMIT`. aitp-rs publishes
neither as a binary, so CI builds them.

| Check | What it proves |
|---|---|
| `spec pin + generated files` | `vendor/spec` and `src/errors.ts` match the spec at the pin; strict types; no runtime dependencies |
| `tests (node 20)`, `tests (node 22)`, `tests (deno)` | the known-answer, primitive, verifier and adapter suites |
| `conformance (aitp-conformance)` | the adapter passes every gate with zero core skips; the report validates against `aitp-conformance-report.schema.json` and `check-conformance-report.py`, and is uploaded |
| `mint (aitp-rs) -> verify` | artifacts aitp-rs mints in that run verify here byte for byte, and the negatives (high-S, untagged, double-hashed, withheld or confused keys) fail |

Pin maintenance:

- `bump-spec.yml` handles a new spec. It runs on the spec repo's
  `spec-released` dispatch and opens a held PR that moves `SPEC_VERSION`.
  The PR regenerates `vendor/spec` and `src/errors.ts` at the new pin.
- `bump-aitp-rs.yml` handles a new aitp-rs. It runs on an `aitp-released`
  dispatch and daily, and opens a held PR that moves `AITP_RS_COMMIT` to the
  newest `aitp-v*` release ahead of the pin.
- `spec-canary.yml` (daily, not required) runs the suite and conformance
  against spec `main`. It keeps one tracking issue open while that fails.
- `auto-merge.yml` arms auto-merge on patch and minor Dependabot PRs.

Releases: `release.yml` runs on every PR and push. It packs the tarball,
installs it into an empty project, imports the library, runs the adapter
through `npx`, and does an `npm publish --dry-run`. A `v*` tag that matches
`package.json` then publishes that tarball through npm trusted publishing
(OIDC, with provenance, and no token). The one-time npmjs.com setup is in
[`scripts/handoff/npm-trusted-publisher.md`](scripts/handoff/npm-trusted-publisher.md).

To run the mint check locally from an aitp-rs checkout next to this one:

```sh
npm run build
(cd ../aitp-rs && cargo run --quiet -p mint-signed-examples --bin xcheck-mint) | node scripts/xcheck-verify.mjs
```

## Primitives

| Module | What it does | Spec |
|---|---|---|
| `json.ts` | Strict JSON parser. It rejects duplicate keys at any depth, lone surrogates, non-finite numbers and anything outside RFC 8259. `__proto__` is an ordinary key. | RFC-AITP-0001 §5.4.5; RFC 8259; RFC 7493 |
| `jcs.ts` | RFC 8785 canonicalization: UTF-16 key order and ECMAScript number formatting. | RFC 8785 |
| `b64.ts` | Strict unpadded base64url. It rejects padding, whitespace, impossible lengths and non-zero trailing bits. | RFC 4648 §5 |
| `curves.ts`, `keys.ts` | Ed25519 and P-256 on WebCrypto, with the §5.4.7 strictness checks done in BigInt first: S < L, canonical points and no small-order keys or R for Ed25519; low-S and range checks for P-256. P-256 point decompression. | RFC-AITP-0001 §5.4.6, §5.4.7 |
| `aid.ts` | AID grammar: legacy, `ed25519:` and `p256:` forms. | RFC-AITP-0001 §5.3 |
| `jwk.ts` | RFC 7638 thumbprints for `cnf.jkt`. | RFC-AITP-0002 §2.2.1 |
| `sigfield.ts` | JCS-profile signature fields (`ed25519.`, `p256.`, untagged) and the single-hash primitive. | RFC-AITP-0001 §5.4.3, §5.4.6 |
| `jws.ts` | Compact JWS parsing, header checks and alg pinning from the signer's AID. | RFC-AITP-0001 §5.4.5 |
| `proofs.ts` | Signing inputs for PoP, the envelope and the pinned-key and SPIFFE proofs. | RFC-AITP-0001 §5.4, §5.4.2; RFC-AITP-0002 §3.1, §6.4.1 |
| `fields.ts` | Member-set checks, the UUIDv4 layout and derived UUIDs. | RFC-AITP-0005 §2.2 |
| `errors.ts` | Generated from `registries/error-codes.md`. | — |

Verification takes the current time as an argument. Nothing on a verify
path reads the clock or the network.

## Non-goals

- **Issuing or operating.** This package verifies artifacts. Its signing
  helpers exist for tests and the conformance adapter. It does not run a
  handshake endpoint, store keys or rotate keys.
- **Key fetching.** No network I/O. Keys come from the trust inputs the
  caller passes (RFC-AITP-0007 resolution is the caller's job).
- **Draft and extension profiles.** Multi-hop delegation (RFC-AITP-0011),
  session bundles (RFC-AITP-0010), SPIFFE identities and pinned admission
  are out of scope for the core claim. The primitives needed for them are
  tested against their vectors.
- **Backward compatibility** with `aitp/0.1` or `aitp/0.2` artifacts.

## Development

```sh
npm ci
npm test              # Node: compile the suite, then run it
deno run --allow-read=. build-test/test/run.js   # Deno, on the same build
npm run typecheck
npm run check:errors  # src/errors.ts vs the vendored registry
npm run check:spec    # vendor/spec vs ../agentidentitytrustprotocol at the pin
```

To move the pin, check out the spec at the new commit next to this repo.
Write the commit to `SPEC_VERSION`, then run `npm run sync:spec` and
`npm run gen:errors`.

## License

Apache-2.0. See [LICENSE](LICENSE).
