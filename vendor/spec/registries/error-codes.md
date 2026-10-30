# Error Code Registry

AITP error codes returned in error envelopes (`AitpError.code`), with one exception: `CHALLENGE_REFUSED` travels in the transport of the challenge it refuses (see [Pinned-admission codes](#pinned-admission-codes-rfc-aitp-0002-34)). AITP is JSON-only; codes are string constants in the canonical JSON wire format (see [RFC-AITP-0001 §5.6](../rfcs/RFC-AITP-0001-core.md#56-error-envelope)).

> **Stability:** The codes listed below are stable for v0.3. Implementations MUST treat unknown codes as opaque failures and MUST NOT key behavior off codes that are not in this registry. New codes can be added without an RFC; renaming or removing an existing code is a breaking change and requires the RFC process. (v0.2 renamed `DELEGATION_INVALID_GRANT_PROOF` → `DELEGATION_INVALID_VOUCHER` via that process, as part of the JWS migration — see the delegation table below.) "Without an RFC" waives the need for a new RFC *document*, not [VERSIONING.md](../VERSIONING.md)'s change classes: adding a code is a **backward-compatible addition** there. Note that the change *class* and the version *position* are separate questions: pre-1.0, VERSIONING.md reserves the minor position for the protocol revision, so a backward-compatible addition made inside an existing protocol revision takes a **patch-position** bump on the RFCs whose normative text gains the code, and records its minor class in the CHANGELOG. The two policies answer different questions — whether a new document is required (no) and how the version numbers move (patch position, minor class) — and compose rather than conflict.

> **`spec_status` column.** Each code below carries a `spec_status` of either `core` or `draft`. `core` codes are part of v0.3 conformance and MAY be emitted by any conformant implementation. `draft` codes are reserved for the opt-in draft RFCs (currently RFC-AITP-0010 Session Trust Bundle, RFC-AITP-0011 Multi-hop Delegation and RFC-AITP-0013 TCT Renewal) and MUST NOT be used except when implementing the cited draft RFC. Conformance runners MUST treat receipt of a `draft` code from an implementation that does not opt into the corresponding draft as a non-conformance.

## Code naming convention

Object-level failures use the `<OBJECT>_<FAILURE>` form (e.g.
`MANIFEST_SIGNATURE_INVALID`, `TCT_EXPIRED`,
`DELEGATION_SCOPE_EXCEEDED`). Envelope-level failures use bare codes
(e.g. `INVALID_SIGNATURE`, `REPLAY_DETECTED`). This granularity is
deliberate: a consumer needs to know *which* object failed, not only
that something failed. Codes that apply uniformly across objects —
`UNKNOWN_VERSION`, `UNKNOWN_FIELD` — also use the bare form: the
failing object is whichever one was being verified, and prefixed
variants per object would multiply names without adding information.
New codes proposed via the RFC process MUST follow this convention.

## Structural rejection

A verifier rejects an artifact **structurally** when the object does not match its
schema at all — a missing REQUIRED member, a member of the wrong type, a value
outside its grammar. Every artifact RFC positions this check before the
cryptographic steps, so a malformed object is rejected before any signature work is
spent on it. This table is normative: implementations MUST use the code named here
so that two independent implementations reject the same malformed artifact with the
same code.

| Artifact | Structural rejection code |
|---|---|
| Envelope | `INVALID_ENVELOPE` |
| Handshake payload | `INVALID_ENVELOPE` — the payload is a member of the envelope, and RFC-AITP-0004 §5.2 step 4 and §6 already map payload-level defects this way |
| Manifest | `MANIFEST_INVALID` |
| Identity descriptor | `IDENTITY_FAILED` |
| Revocation snapshot | `REVOCATION_SNAPSHOT_INVALID` |
| Session Trust Bundle | `SESSION_BUNDLE_INVALID` (`draft`) |
| TCT | `TCT_SIGNATURE_INVALID` |
| Grant voucher | `DELEGATION_INVALID_VOUCHER` |
| Delegation token | `DELEGATION_INVALID_SIGNATURE` |

Two rules govern the table:

- **`UNKNOWN_FIELD` is more specific and wins.** When the object's *only* defect is
  a member outside its schema and outside its `extensions` / `ext` namespace, the
  code is `UNKNOWN_FIELD` ([RFC-AITP-0001 §7](../rfcs/RFC-AITP-0001-core.md#7-compatibility-model)),
  not the code above. The codes above cover every other structural defect.
- **The compact-JWS artifacts deliberately collapse onto their signature-family
  code.** A TCT, voucher, or delegation token is verified by decoding a JWS; a
  payload that will not decode into the expected claim set is indistinguishable, to
  the caller, from one whose signature does not verify — in both cases the artifact
  failed to produce a trustworthy claim set, and distinguishing them would leak
  parse detail about an unauthenticated token. This collapse is intentional; it is
  written down here because it was previously only a convention, which let two
  implementations diverge and both believe they were conformant (issue #39).

The JCS-profile artifacts do **not** collapse this way: they are verified as JSON
objects against a published schema, the caller is expected to fix the object, and a
misleading code sends an operator looking in the wrong place. `MANIFEST_INVALID` and
`REVOCATION_SNAPSHOT_INVALID` exist so that a Manifest or snapshot with a shape
defect is not reported as a *signature* failure — the mapping two implementations
were previously forced to invent for themselves.

## Envelope-level codes

| Code | Meaning | Retryable | spec_status | Spec |
|---|---|---|---|---|
| `INVALID_ENVELOPE` | Envelope failed schema validation. | false | core | [RFC-AITP-0001 §5.6](../rfcs/RFC-AITP-0001-core.md#56-error-envelope) |
| `INVALID_SIGNATURE` | Signature verification failed. | false | core | [RFC-AITP-0001 §5.4](../rfcs/RFC-AITP-0001-core.md#54-signature) |
| `REPLAY_DETECTED` | Duplicate `message_id`. | false | core | [RFC-AITP-0001 §5.5](../rfcs/RFC-AITP-0001-core.md#55-replay-protection) |
| `TIMESTAMP_EXPIRED` | Timestamp outside tolerance. | true | core | [RFC-AITP-0001 §5.5](../rfcs/RFC-AITP-0001-core.md#55-replay-protection) |
| `UNKNOWN_VERSION` | Unsupported `version` field. | false | core | [RFC-AITP-0001 §7](../rfcs/RFC-AITP-0001-core.md#7-compatibility-model) |
| `UNKNOWN_FIELD` | A signed object carried a member outside its schema and outside its `extensions` / `ext` extension namespace. Unknown keys *inside* the namespace are ignored, never rejected — the asymmetry is deliberate (forward compatibility rides exclusively on the namespace). One generic code for every signed AITP object: the JCS-profile artifacts (envelope, Manifest, handshake payloads, revocation snapshot, session bundle) spell the namespace `extensions`; the compact-JWS artifacts (TCT, grant voucher, delegation token) spell it `ext`, and the unknown member is an unknown claim in the decoded payload. More specific than `INVALID_ENVELOPE` when an envelope's only defect is an unknown member. | false | core | [RFC-AITP-0001 §7](../rfcs/RFC-AITP-0001-core.md#7-compatibility-model) |
| `IDENTITY_FAILED` | Identity binding could not be verified. | false | core | [RFC-AITP-0002](../rfcs/RFC-AITP-0002-identity.md) |
| `POLICY_VIOLATION` | Requested capability not granted. | false | core | [RFC-AITP-0004 §4](../rfcs/RFC-AITP-0004-mutual-handshake.md#4-tct-issuance-rules) |
| `GRANT_OVERFLOW` | Peer-issued TCT grants exceed `offered_capabilities`. | false | core | [RFC-AITP-0004](../rfcs/RFC-AITP-0004-mutual-handshake.md) |
| `INSUFFICIENT_GRANTS` | Received peer-issued TCT lacks a capability listed in the receiver's own `required_peer_capabilities`. | false | core | [RFC-AITP-0004 §5.3/§5.4](../rfcs/RFC-AITP-0004-mutual-handshake.md) |
| `KEY_RESOLUTION_FAILED` | Could not resolve issuer or peer keys. | true | core | [RFC-AITP-0007](../rfcs/RFC-AITP-0007-key-resolution.md) |

## Token-format codes (RFC-AITP-0001 §5.4.5)

Returned when a compact-JWS artifact (TCT, grant voucher, delegation token) fails the JOSE-header enforcement rules. The two codes are deliberately distinct so conformance fixtures can assert the rejection reason.

| Code | Meaning | Retryable | spec_status |
|---|---|---|---|
| `TOKEN_ALG_MISMATCH` | JWS header `alg` is not the sole value derived from the signer's AID — including `none` (any capitalization) and unknown algorithms. | false | core |
| `TOKEN_TYP_MISMATCH` | JWS header `typ` does not exactly match the value expected for the verification context (`aitp-tct+jwt`, `aitp-grant+jwt`, or `aitp-delegation+jwt`). | false | core |

## TCT-verification codes (RFC-AITP-0005)

Returned when a peer evaluates a TCT outside the handshake context — e.g. via a TCT verification API or local verification of a presented TCT.

| Code | Meaning | Retryable | spec_status |
|---|---|---|---|
| `TCT_EXPIRED` | TCT `exp` is in the past. | false | core |
| `TCT_REVOKED` | TCT `jti` is in the issuing peer's deny list. | false | core |
| `TCT_SIGNATURE_INVALID` | TCT JWS signature does not validate under the issuing peer's key. Also the TCT's structural-rejection code (see [Structural rejection](#structural-rejection)): a claim set that does not decode, or a `jti` outside the RFC-AITP-0005 §2.2 layout. It is also the code for these rejections, which run after the signature has verified and so are not structural: in a grant context, a self-issued TCT (`iss == sub`) or any TCT carrying the `aitp.attestation` marker grant (RFC-AITP-0005 §7.2 step 5); and, to a relying party verifying a self-attestation, an attestation-shape defect, an `ext` lacking the key it expects, or an issuer key the relying party's records do not show as trusted at `iat` ([RFC-AITP-0005 §5.3](../rfcs/RFC-AITP-0005-tct.md#53-self-issued-attestation-tcts)). | false | core |
| `TCT_EXPIRES_AFTER_MANIFEST` | TCT `exp` exceeds the issuing peer's Manifest `expires_at` (RFC-AITP-0004 §4.3). The peer-issued TCT cannot outlive the credential that authenticates its issuer's key. | false | core |

## Downstream PoP codes (RFC-AITP-0005 §6)

| Code | Meaning | Retryable | spec_status |
|---|---|---|---|
| `POP_CHALLENGE_INVALID` | Challenge envelope was malformed or stale. | false | core |
| `POP_RESPONSE_INVALID` | Response signature failed verification against the subject key bound via `cnf.jkt`. | false | core |

## Pinned-admission codes (RFC-AITP-0002 §3.4)

Returned by a verifier implementing the OPTIONAL one-way pinned-admission profile of [RFC-AITP-0002 §3.4](../rfcs/RFC-AITP-0002-identity.md#34-one-way-pinned-key-admission-optional-profile-pinned-admission). A presentation that fails verification uses the existing codes (`IDENTITY_FAILED`, `INVALID_ENVELOPE`, `INVALID_SIGNATURE`, `REPLAY_DETECTED`, `TIMESTAMP_EXPIRED`), per the §3.4 check order.

> **Transport note.** `CHALLENGE_REFUSED` is the one code in this registry that is not delivered in an AITP error envelope. The challenge it refuses is not an envelope ([RFC-AITP-0002 §3.4](../rfcs/RFC-AITP-0002-identity.md#34-one-way-pinned-key-admission-optional-profile-pinned-admission), challenge format), so the refusal travels in the challenge's own transport. RFC-AITP-0002 §3.4 gives an informative HTTP mapping: status 503, a `Retry-After` header, and the body `{"error":"CHALLENGE_REFUSED"}`.

| Code | Meaning | Retryable | spec_status |
|---|---|---|---|
| `CHALLENGE_REFUSED` | The verifier refused to issue a new `pop_nonce` challenge because its bound on outstanding nonces is reached; RFC-AITP-0002 §3.4 requires refusal rather than eviction of unexpired nonces. Retrying after outstanding nonces are consumed or expire can succeed. A per-source rate-limit refusal is an HTTP 429 instead, which the profile REQUIRES (RFC-AITP-0002 §3.4, tightening RFC-AITP-0009 §3.1); a client MUST be able to tell the two apart. | true | core |

## Manifest codes (RFC-AITP-0003)

| Code | Meaning | Retryable | spec_status |
|---|---|---|---|
| `MANIFEST_EXPIRED` | `expires_at` is in the past. | false | core |
| `MANIFEST_SIGNATURE_INVALID` | Signature verification failed. | false | core |
| `MANIFEST_INVALID` | Manifest failed schema validation — a missing REQUIRED member, a member of the wrong type, or a value outside its grammar ([RFC-AITP-0003 §5](../rfcs/RFC-AITP-0003-manifest.md#5-manifest-verification) step 2). Mirrors `INVALID_ENVELOPE` for the Manifest. MUST NOT be reported as `MANIFEST_SIGNATURE_INVALID`: the signature was never reached. When the only defect is an unknown member outside `extensions`, use the more specific `UNKNOWN_FIELD` instead. | false | core |
| `MANIFEST_POP_FAILED` | Proof-of-possession verification failed. | false | core |
| `INCOMPATIBLE_TRUST_ANCHORS` | No overlap in accepted trust anchors. | false | core |
| `INCOMPATIBLE_IDENTITY_TYPE` | Peer's `identity.type` is not present in the receiver's `accepted_identity_types`. More specific than `INCOMPATIBLE_TRUST_ANCHORS`: signals identity-type incompatibility (e.g. `pinned_key` vs. `oidc`) rather than trust-anchor incompatibility. | false | core |
| `MANIFEST_VERSION_UNKNOWN` | `version` not supported by this implementation. | false | core |

## Mutual Handshake codes (RFC-AITP-0004)

Returned in error envelopes during the four-message handshake.

| Code | Meaning | spec_status |
|---|---|---|
| `INCOMPATIBLE_TRUST_ANCHORS` | No trust-anchor overlap. | core |
| `INCOMPATIBLE_IDENTITY_TYPE` | Peer's identity type not in `accepted_identity_types`. | core |
| `MANIFEST_INVALID` | Peer's Manifest failed schema validation. | core |
| `MANIFEST_SIGNATURE_INVALID` | Peer's Manifest signature invalid. | core |
| `MANIFEST_POP_FAILED` | Peer's Manifest PoP failed. | core |
| `POP_VERIFICATION_FAILED` | Round-2 PoP signature failed. | core |
| `NONCE_MISMATCH` | `pop_nonce_echo` mismatch. | core |
| `PEER_MISMATCH` | `MUTUAL_HELLO_ACK` sender is not the AID the initiator addressed in MUTUAL_HELLO ([RFC-AITP-0004 §5.2](../rfcs/RFC-AITP-0004-mutual-handshake.md#52-on-receiving-mutual_hello_ack-a-verifies-b) step 3). | core |
| `AUDIENCE_MISMATCH` | TCT `aud` ≠ self AID. | core |
| `GRANT_OVERFLOW` | TCT grants exceed peer's `offered_capabilities`. | core |
| `TCT_EXPIRED` | TCT already expired. | core |
| `TCT_EXPIRES_AFTER_MANIFEST` | TCT `exp` exceeds issuer's Manifest `expires_at`. | core |
| `TOKEN_ALG_MISMATCH` | Received TCT/voucher JWS `alg` not the AID-derived value. | core |
| `TOKEN_TYP_MISMATCH` | Received TCT/voucher JWS `typ` not the expected value. | core |
| `IDENTITY_FAILED` | Peer identity verification failed. | core |
| `REPLAY_DETECTED` | Duplicate `message_id`. | core |
| `TIMESTAMP_EXPIRED` | Envelope timestamp outside tolerance. | core |
| `UNKNOWN_FIELD` | A handshake payload (or other signed object in the exchange) carried a member outside its schema and outside `extensions` ([RFC-AITP-0001 §7](../rfcs/RFC-AITP-0001-core.md#7-compatibility-model)). | core |

## Manifest-service codes

Returned by an HTTP endpoint serving `/.well-known/aitp-manifest` or by an out-of-band manifest lookup.

| Code | Meaning | spec_status |
|---|---|---|
| `MANIFEST_EXPIRED` | `expires_at` in the past. | core |
| `MANIFEST_SIGNATURE_INVALID` | Signature verification failed. | core |
| `MANIFEST_POP_FAILED` | Proof-of-possession failed. | core |
| `MANIFEST_INVALID` | Manifest failed schema validation. | core |
| `MANIFEST_VERSION_UNKNOWN` | Version not supported. | core |
| `MANIFEST_NOT_FOUND` | No manifest for the requested AID. | core |

## Revocation codes (RFC-AITP-0008)

Returned when a consuming peer verifies a signed revocation snapshot pulled from an
issuing peer's `ListRevoked` endpoint ([RFC-AITP-0008 §1.5](../rfcs/RFC-AITP-0008-revocation.md#15-signed-revocation-response)).
Before these codes existed the registry had no revocation-specific family at all, and
implementations borrowed `TCT_SIGNATURE_INVALID` — a code about a *token*, for a
failure of the *snapshot* that lists tokens (issue #39).

| Code | Meaning | Retryable | spec_status |
|---|---|---|---|
| `REVOCATION_SNAPSHOT_INVALID` | Revocation snapshot failed schema validation — the transport wrapper carried members other than `revocation_list` and `signature`, or the inner body has a missing/mistyped member. When the only defect is an unknown member outside `extensions`, use `UNKNOWN_FIELD` instead. | false | core |
| `REVOCATION_SNAPSHOT_SIGNATURE_INVALID` | Snapshot signature does not validate under the issuing peer's key, resolved from that peer's Manifest. Distinct from `TCT_SIGNATURE_INVALID`, which is about a token's own JWS. | false | core |

> **Not to be confused with `TCT_REVOKED`.** A snapshot that is merely *stale* or
> *unreachable* is not invalid — it is absent, and what happens next is the consuming
> peer's `revocation_policy.mode` decision ([RFC-AITP-0008 §3.1](../rfcs/RFC-AITP-0008-revocation.md#31-modes)),
> not a snapshot-verification failure. Under `fail_closed` that decision surfaces as
> `TCT_REVOKED` — unknown revocation status is treated as revoked, which is what
> fail-closed means — and conformance fixture `rev-001` pins it. The two codes above
> are for a snapshot the peer *did* obtain and could not trust, and they are reported
> by an operation that verifies the snapshot itself. For the token decision that
> snapshot is discarded and counts as absent, so the mode decides it the same way
> (`tct-022`, `tct-023`; [RFC-AITP-0008 §1.5](../rfcs/RFC-AITP-0008-revocation.md#15-signed-revocation-response)).

## Delegation codes (RFC-AITP-0006)

Delegation-layer codes carry the `DELEGATION_` prefix so they cannot be confused with the envelope-level or manifest-level codes that share the same root.

| Code | Meaning | spec_status |
|---|---|---|
| `DELEGATION_AUDIENCE_MISMATCH` | `aud` ≠ verifier's AID. | core |
| `DELEGATION_SCOPE_EXCEEDED` | `scope ⊄ voucher.grants`. | core |
| `DELEGATION_INVALID_VOUCHER` | Embedded voucher JWS signature invalid, `voucher.iss` ≠ verifier's AID, or `voucher.sub` ≠ outer `iss`. **Renamed in v0.2** from `DELEGATION_INVALID_GRANT_PROOF` (the `grant_proof` reconstruction mechanism was removed by the JWS migration). | core |
| `DELEGATION_SOURCE_TCT_REVOKED` | `voucher.src_jti` is in the issuing peer's deny list. | core |
| `DELEGATION_INVALID_SIGNATURE` | Outer delegation JWS signature invalid, or self-delegation (`iss` == `sub`). | core |
| `DELEGATION_EXPIRED` | Token or voucher expired, or `exp` > `voucher.exp`. | core |
| `DELEGATION_POP_FAILED` | Proof-of-possession failed. | core |
| `DELEGATION_MULTIHOP_NOT_SUPPORTED` | Multi-hop attempt detected (`chain` claim present without RFC-AITP-0011 opt-in). | core |

> **`DELEGATION_MULTIHOP_NOT_SUPPORTED` is a core code, not a draft code.** Implementations with default `max_hops = 0` MUST emit this code for any delegation token carrying a `chain` claim — rejecting multi-hop is the **required core behavior**, not an optional one. The code is distinct from the `draft` codes in the "Multi-hop delegation codes (RFC-AITP-0011, opt-in)" table below: those codes (`DELEGATION_HOP_LIMIT_EXCEEDED`, `DELEGATION_CHAIN_HASH_MISMATCH`) are emitted by implementations that have opted into multi-hop and are validating chain semantics. `DELEGATION_MULTIHOP_NOT_SUPPORTED` is the core *refusal* to even process the chain — a structural rejection before any per-hop verification. See [conformance fixture `del-004`](../schemas/conformance/del-004-multihop-rejected-v01.json) for the pinned v0.1-era behavior and its v0.2 sibling for the claim-shaped equivalent.

## Multi-hop delegation codes (RFC-AITP-0011, opt-in)

These codes are reserved for multi-hop delegation (RFC-AITP-0011 is Draft and not part of core conformance). Implementations that do not opt in will not emit them.

| Code | Meaning | spec_status |
|---|---|---|
| `DELEGATION_HOP_LIMIT_EXCEEDED` | Chain length exceeds `max_delegation_hops` (default 3). | draft |
| `DELEGATION_CHAIN_HASH_MISMATCH` | `chain_hash` does not match the `chain` array contents (truncation or tampering detected). | draft |

## Session Trust Bundle codes (RFC-AITP-0010, opt-in)

These codes are reserved for Session Trust Bundles (RFC-AITP-0010 is Draft and not part of core conformance). The granular code set was pinned to align with the `aitp-rs` adapter that emits them ahead of bundle conformance.

| Code | Meaning | spec_status |
|---|---|---|
| `BUNDLE_INVALID_SIGNATURE` | Coordinator's outer bundle signature failed verification under the coordinator's Manifest key. | draft |
| `BUNDLE_VERSION_MISMATCH` | `version` is not `"aitp/0.3"` (or a later version this implementation supports). | draft |
| `BUNDLE_EXPIRED` | `expires_at` is in the past at verification time. | draft |
| `BUNDLE_EXPIRY_WINDOW_INVARIANT` | `expires_at` is greater than `min(participants[*].tct.exp)` (violates RFC-AITP-0010 §6). | draft |
| `BUNDLE_COORDINATOR_ISSUER_MISMATCH` | One or more participant TCT `iss` claims do not equal `coordinator`. | draft |
| `BUNDLE_AUDIENCE_MISMATCH` | A participant TCT `aud` claim does not equal that participant's `aid`. | draft |
| `BUNDLE_EMPTY_PARTICIPANTS` | `participants` array is empty. | draft |
| `BUNDLE_PARTICIPANT_TCT_INVALID` | At least one embedded participant TCT failed standard TCT verification. | draft |
| `BUNDLE_NOT_MEMBER` | Receiver's AID is not in `participants[*].aid`. | draft |
| `SESSION_BUNDLE_INVALID` | Aggregate fallback — implementations MAY return this when a deployment policy requires a single-error surface for bundles, in lieu of the specific codes above. | draft |

## TCT renewal codes (RFC-AITP-0013, opt-in)

TCT renewal (RFC-AITP-0013 is Draft and not part of core conformance) registers one code of its own, below. An issuer that does not offer renewal advertises no `renew_uri` and never emits it.

| Code | Meaning | Retryable | spec_status |
|---|---|---|---|
| `RENEWAL_UNAVAILABLE` | The issuer could not complete renewal because an issuer-side dependency it must consult (its revocation state, its renewal nonce store) was unavailable. The issuer does not mint. It is not `TCT_REVOKED`: the current TCT is not known to be revoked. The issuer SHOULD send it with HTTP `503`; the holder MAY retry with backoff and a fresh `pop_nonce` before the current TCT's `exp` ([RFC-AITP-0013 §4 step 4, §5, §6](../rfcs/RFC-AITP-0013-tct-renewal-extension.md#4-issuer-processing)). | true | draft |

Every other renewal failure reuses a code defined in its own table above; the table below gives the meaning each takes in renewal, and lists `RENEWAL_UNAVAILABLE` at the steps that raise it. An issuer that does not offer renewal emits none of them for renewal.

| Step | Code | Meaning in renewal |
|---|---|---|
| Issuer, [§4](../rfcs/RFC-AITP-0013-tct-renewal-extension.md#4-issuer-processing) step 1 | `POP_RESPONSE_INVALID` | The renewal request is not an object with exactly `current_tct`, `pop_nonce` and `pop_signature`, or `pop_nonce` is not 16 bytes in 22 unpadded base64url characters. |
| Issuer, §4 step 2 | `TCT_SIGNATURE_INVALID`, `TOKEN_TYP_MISMATCH`, `TOKEN_ALG_MISMATCH`, `UNKNOWN_FIELD` | `current_tct` fails RFC-AITP-0005 §7.2 as read by its issuer: not issued by this issuer, `aud` ≠ `sub`, or a grant-context defect. |
| Issuer, §4 step 2 | `TCT_EXPIRED` | `current_tct` has expired. An expired TCT is never renewed. |
| Issuer, §4 step 2 | `TCT_EXPIRES_AFTER_MANIFEST` | `current_tct.exp` exceeds the issuer's current Manifest `expires_at`. |
| Issuer, §4 step 3 | `POP_RESPONSE_INVALID` | `pop_signature` does not verify under the `sub` key over the renewal PoP input (RFC-AITP-0013 §3.1). |
| Issuer, §4 step 4 | `TCT_REVOKED` | `current_tct.jti` is in the issuer's deny list. Only then: an issuer that cannot read its own revocation state answers `RENEWAL_UNAVAILABLE`. |
| Issuer, §4 step 4 | `RENEWAL_UNAVAILABLE` | The issuer cannot determine its own revocation state for `current_tct.jti`: its deny list, or the source that produces it, cannot be read. |
| Issuer, §4 step 5 ([§5](../rfcs/RFC-AITP-0013-tct-renewal-extension.md#5-nonce-store)) | `RENEWAL_UNAVAILABLE` | The renewal nonce store cannot be read or cannot record the nonce. |
| Issuer, §4 step 5 | `REPLAY_DETECTED` | The issuer has already accepted a renewal request with this `pop_nonce`. |
| Issuer, §4 step 6 | `POLICY_VIOLATION` | No grant survives re-evaluation against the issuer's current Manifest and policy, or policy refuses renewal to this holder. |
| Holder, [§6.1](../rfcs/RFC-AITP-0013-tct-renewal-extension.md#61-holder-verification) step 2 | `PEER_MISMATCH` | The response envelope's `sender.agent_id` is not the current TCT's `iss`. |
| Holder, §6.1 step 3 | `NONCE_MISMATCH` | `pop_nonce_echo` is not the `pop_nonce` the holder sent. |
| Holder, §6.1 step 5 | `AUDIENCE_MISMATCH` | The renewed TCT's `sub` is not the holder, or its `cnf.jkt` differs from the current TCT's. |
| Holder, §6.1 step 6 | `GRANT_OVERFLOW` | The renewed TCT carries a grant the current TCT does not. |

## Adding a code

Open a PR adding a row to one of the tables above. Verifiers MUST NOT reveal which specific policy check failed beyond the registered code; `reason` strings are informational only.
