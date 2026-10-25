# Handoff: npm trusted publisher for `@agentidentitytrustprotocol/verifier`

**Who:** an owner of the `agentidentitytrustprotocol` npm organization. No session can
do this, because it needs that account's logged-in session and 2FA.
**Why:** [`release.yml`](../../.github/workflows/release.yml) is meant to publish with OIDC
trusted publishing, so that no npm token exists to leak or rotate. Every release carries a
provenance attestation that ties it to the workflow run that built it.

> **Current state: token upload, OIDC provenance.** npm's OIDC token exchange rejects
> GitHub's immutable `sub` claim, which GitHub forces on repositories created after
> 2026-07-15, including this one. It answers `404 "OIDC token exchange error - package not
> found"`; see [npm/cli#9969](https://github.com/npm/cli/issues/9969). Until npm fixes it,
> the publish step authenticates with the org `NPM_TOKEN` and still signs provenance with
> the job's OIDC token. Publishing access must therefore be "Require two-factor
> authentication" (step 2), not "…and disallow tokens". Switching back is tracked in
> aitp-verifier-ts#12.

The GitHub side is already in place. The `npm` environment exists on the repository and
deploys only from `v*` tags. Every pull request packs the tarball, installs it into an
empty project, runs the adapter through `npx`, and runs `npm publish --dry-run`.

## 1. Create the package

npm configures a trusted publisher on an existing package only, so the name has to be
published once by hand. Publish a placeholder, not a release, so that `0.1.0` is the first
version, and it comes from CI with provenance.

```sh
mkdir /tmp/reserve && cd /tmp/reserve
npm init -y --scope=@agentidentitytrustprotocol
npm pkg set name=@agentidentitytrustprotocol/verifier version=0.0.0 \
  description="Placeholder. Use >=0.1.0." license=Apache-2.0
npm login                       # the org owner's account, with 2FA
npm publish --access public
npm deprecate @agentidentitytrustprotocol/verifier@0.0.0 "Name reservation. Use >=0.1.0."
```

## 2. Configure the trusted publisher

On npmjs.com, go to the package, then Settings, then Trusted Publisher, then GitHub
Actions:

| Field | Value |
|---|---|
| Organization or user | `agentidentitytrustprotocol` |
| Repository | `aitp-verifier-ts` |
| Workflow filename | `release.yml` |
| Environment name | `npm` |

Then, on the same page under Publishing access, choose "Require two-factor
authentication". While npm/cli#9969 is open, the token upload needs that setting, which
still requires 2FA for people publishing by hand. Once #12 lands, switch to "Require
two-factor authentication and disallow tokens", so that only the workflow can publish.

## 3. Release

1. Make sure `version` in `package.json` is the version to publish, for example `0.1.0`.
2. `git tag v0.1.0 && git push origin v0.1.0`. The `package` job fails closed if the tag
   is not `v` plus the package version. The `publish` job then publishes the exact
   tarball that was smoke-tested, and passes only once the registry serves that tarball
   with its provenance attestation and `latest` on it. It waits up to 10 minutes for
   npm's processing lag. If the job fails after npm accepted the upload, re-run it: a
   version that is already published is verified, never published again.
3. Verify from an empty directory:
   ```sh
   npm init -y && npm i @agentidentitytrustprotocol/verifier
   echo '{"id":"r1","op":"init","params":{"version":"1"}}' | npx aitp-verifier-adapter
   ```
   The reply is one line with `"ok":true` and `"implementation":"aitp-verifier-ts"`. The
   package page on npmjs.com shows the provenance badge.

## Rollback

- **A bad release:** `npm deprecate @agentidentitytrustprotocol/verifier@<version> "<why>"`,
  then fix it and release the next patch version. Unpublishing works only within 72 hours,
  and the version number can never be reused, so avoid it.
- **A wrong or unwanted publisher:** remove it in the package's Trusted Publisher
  settings. Deleting the `npm` GitHub environment also stops publishing, because the
  publisher is bound to that environment name.
