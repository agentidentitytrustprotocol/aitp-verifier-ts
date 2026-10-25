#!/usr/bin/env node
// Checks a packed tarball against what the npm registry serves for its
// name and version: the release job's acceptance test, read from the
// registry itself rather than from `npm publish`'s exit status.
//
//   node scripts/verify-published.mjs <tarball> --exists
//       exit 0 if the version is on the registry, 3 if it is not.
//   node scripts/verify-published.mjs <tarball> [--budget-secs 600]
//       exit 0 once the registry serves the version as this tarball (same
//       integrity and shasum, or the same tar compressed differently), with
//       a provenance attestation whose subject is the served tarball and,
//       for a non-prerelease, dist-tags.latest on it.
//
// npm can take minutes to serve a version it has accepted (#11), so a
// version or attestation that is not there yet is retried with backoff
// until the budget runs out. A version served with different bytes is a
// failure at once: waiting never changes it.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";

const REGISTRY = "https://registry.npmjs.org";
const SLSA_V1 = "https://slsa.dev/provenance/v1";
const BACKOFF_SECS = [5, 10, 20, 40, 60];

class Mismatch extends Error {}

function usage() {
  console.error("usage: verify-published.mjs <tarball> [--exists | --budget-secs N]");
  process.exit(2);
}

const args = process.argv.slice(2);
const tarball = args.shift();
if (tarball === undefined || tarball.startsWith("--")) usage();
let existsOnly = false;
let budgetSecs = 600;
while (args.length > 0) {
  const flag = args.shift();
  if (flag === "--exists") existsOnly = true;
  else if (flag === "--budget-secs" && /^\d+$/.test(args[0] ?? "")) budgetSecs = Number(args.shift());
  else usage();
}

const bytes = readFileSync(tarball);
const pkg = JSON.parse(execFileSync("tar", ["-xzOf", tarball, "package/package.json"], { encoding: "utf8" }));
const { name, version } = pkg;
const integrity = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
const sha512Hex = createHash("sha512").update(bytes).digest("hex");
const shasum = createHash("sha1").update(bytes).digest("hex");
const prerelease = version.includes("-");
const spec = `${name}@${version}`;

async function getJson(url) {
  const res = await fetch(url, { headers: { accept: "application/json", "cache-control": "no-cache" } });
  if (res.status === 404) return undefined;
  if (!res.ok) throw new Error(`GET ${url}: HTTP ${res.status}`);
  return res.json();
}

/** The registry's view of this version, or undefined if it is not served. */
async function served() {
  const doc = await getJson(`${REGISTRY}/${name.replace("/", "%2f")}`);
  const v = doc?.versions?.[version];
  return v === undefined ? undefined : { dist: v.dist, latest: doc["dist-tags"]?.latest };
}

/**
 * The sha512 (hex) of the tarball the registry serves, once it is shown to
 * hold this tarball. The bytes normally match exactly. A re-run of an
 * already published tag repacks, and a different zlib can compress the same
 * tar differently, so then the published tarball is fetched and its
 * uncompressed tar must equal ours.
 */
async function servedDigest(dist) {
  if (dist.integrity === integrity) {
    if (dist.shasum !== shasum) throw new Mismatch(`shasum: registry ${dist.shasum}, tarball ${shasum}`);
    return sha512Hex;
  }
  const res = await fetch(dist.tarball);
  if (!res.ok) throw new Error(`GET ${dist.tarball}: HTTP ${res.status}`);
  const published = Buffer.from(await res.arrayBuffer());
  if (`sha512-${createHash("sha512").update(published).digest("base64")}` !== dist.integrity) {
    throw new Error("the served tarball does not match its own dist.integrity"); // retried
  }
  if (!gunzipSync(published).equals(gunzipSync(bytes))) {
    throw new Mismatch(`integrity: registry ${dist.integrity}, tarball ${integrity}, and the contents differ`);
  }
  console.log(`  ${spec} is served with this tarball's contents, compressed differently (${dist.integrity})`);
  return createHash("sha512").update(published).digest("hex");
}

/** Undefined when everything checks out, else what is still pending. */
async function check() {
  const s = await served();
  if (s === undefined) return `${spec} is not served yet`;
  const digest = await servedDigest(s.dist);
  const att = s.dist.attestations;
  if (att?.provenance?.predicateType !== SLSA_V1 || typeof att.url !== "string") return "provenance attestation not served yet";
  const bundles = (await getJson(att.url))?.attestations ?? [];
  const statements = bundles.map((a) => JSON.parse(Buffer.from(a.bundle.dsseEnvelope.payload, "base64").toString("utf8")));
  const provenance = statements.find((st) => st.predicateType === SLSA_V1);
  if (provenance === undefined) return "provenance bundle not served yet";
  if (!provenance.subject.some((sub) => sub.digest?.sha512 === digest)) {
    throw new Mismatch("the provenance attestation's subject is not this tarball");
  }
  if (!prerelease && s.latest !== version) return `dist-tags.latest is ${s.latest}, not ${version} yet`;
  return undefined;
}

if (existsOnly) {
  const s = await served();
  console.log(s === undefined ? `${spec} is not on the registry` : `${spec} is already on the registry`);
  process.exit(s === undefined ? 3 : 0);
}

console.log(`verifying ${spec} (${integrity}) against ${REGISTRY}, budget ${budgetSecs}s`);
const start = Date.now();
for (let attempt = 0; ; attempt++) {
  let pending;
  try {
    pending = await check();
  } catch (e) {
    if (e instanceof Mismatch) {
      console.error(`::error::${spec} on the registry is not this tarball: ${e.message}`);
      process.exit(1);
    }
    pending = e.message; // a transient registry or network error: retry
  }
  const elapsed = Math.round((Date.now() - start) / 1000);
  if (pending === undefined) {
    console.log(`ok: ${spec} is served as this tarball, with its provenance attestation (after ${elapsed}s)`);
    process.exit(0);
  }
  const wait = BACKOFF_SECS[Math.min(attempt, BACKOFF_SECS.length - 1)];
  if (elapsed + wait > budgetSecs) {
    console.error(`::error::${spec} not verified within ${budgetSecs}s: ${pending}`);
    process.exit(1);
  }
  console.log(`  ${elapsed}s: ${pending}; retrying in ${wait}s`);
  await new Promise((r) => setTimeout(r, wait * 1000));
}
