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

> Status: TS4.1 of the
> [adoption plan](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/plans/cross-repo/aitp-ts-verifier-adoption-90-day.md).
> The primitives and every known-answer vector are in place. The artifact
> verifiers and the conformance adapter come in TS4.2. Not yet published to npm.

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

## What is here (TS4.1)

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
