#!/usr/bin/env node
// Vendors the spec files this package reads at the commit pinned in
// SPEC_VERSION: the known-answer vectors and the error-code registry.
//
//   node scripts/sync-spec.mjs --spec-dir ../agentidentitytrustprotocol          copy
//   node scripts/sync-spec.mjs --spec-dir ../agentidentitytrustprotocol --check  diff only
//
// The spec checkout must be at the pinned commit. --check fails on any
// difference, missing file or extra file, so the vendored copy can never
// drift from the pin.
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const VENDOR = join(ROOT, "vendor", "spec");
const PATHS = ["schemas/conformance/known-answer", "registries/error-codes.md"];

function arg(name) {
  const i = process.argv.indexOf(name);
  return i === -1 ? undefined : process.argv[i + 1];
}

const specDir = arg("--spec-dir");
const check = process.argv.includes("--check");
if (!specDir) {
  console.error("usage: sync-spec.mjs --spec-dir <spec checkout> [--check]");
  process.exit(2);
}

const pin = readFileSync(join(ROOT, "SPEC_VERSION"), "utf8").trim();
if (existsSync(join(specDir, ".git"))) {
  const head = execFileSync("git", ["-C", specDir, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  if (head !== pin) {
    console.error(`spec checkout is at ${head}, SPEC_VERSION pins ${pin}`);
    process.exit(1);
  }
}

function listFiles(base, rel) {
  const abs = join(base, rel);
  if (!existsSync(abs)) return [];
  if (statSync(abs).isFile()) return [rel];
  return readdirSync(abs).flatMap((name) => listFiles(base, join(rel, name)));
}

if (!check) {
  rmSync(VENDOR, { recursive: true, force: true });
  for (const p of PATHS) {
    mkdirSync(dirname(join(VENDOR, p)), { recursive: true });
    cpSync(join(specDir, p), join(VENDOR, p), { recursive: true });
  }
  console.log(`vendored ${PATHS.join(", ")} at ${pin}`);
  process.exit(0);
}

const want = new Set(PATHS.flatMap((p) => listFiles(specDir, p)));
const have = new Set(PATHS.flatMap((p) => listFiles(VENDOR, p)));
const problems = [];
for (const f of want) {
  if (!have.has(f)) problems.push(`missing: ${f}`);
  else if (!readFileSync(join(specDir, f)).equals(readFileSync(join(VENDOR, f)))) problems.push(`differs: ${f}`);
}
for (const f of have) if (!want.has(f)) problems.push(`extra: ${relative(ROOT, join(VENDOR, f))}`);
if (problems.length) {
  console.error(problems.join("\n"));
  console.error("vendor/spec is out of sync with the pin; run npm run sync:spec");
  process.exit(1);
}
console.log(`vendor/spec matches the spec at ${pin} (${want.size} files)`);
