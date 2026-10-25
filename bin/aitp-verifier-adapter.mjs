#!/usr/bin/env node
// aitp-conformance adapter: NDJSON requests on stdin, one reply per line on
// stdout. Run with --target bin/aitp-verifier-adapter.mjs after `npm run build`.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { Adapter } from "../dist/adapter.js";
import * as b64 from "../dist/b64.js";
import { publicKeyFromRaw } from "../dist/keys.js";

const root = fileURLToPath(new URL("..", import.meta.url));
const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

function commit() {
  if (process.env.AITP_ADAPTER_COMMIT) return process.env.AITP_ADAPTER_COMMIT;
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
  } catch {
    return "unknown";
  }
}

// Only the trusted test issuer resolves; the untrusted one never does.
const kat = JSON.parse(
  readFileSync(new URL("../vendor/spec/schemas/conformance/known-answer/oidc-test-issuers.json", import.meta.url), "utf8"),
);
const oidcIssuers = new Map();
for (const v of kat.vectors) {
  if (v.role !== "trusted") continue;
  const key = publicKeyFromRaw("ed25519", b64.decode(v.pubkey_b64url));
  if (key === undefined) throw new Error(`${v.id}: bad issuer key`);
  oidcIssuers.set(v.issuer, [...(oidcIssuers.get(v.issuer) ?? []), key]);
}

const adapter = new Adapter({
  info: { implementation: "aitp-verifier-ts", version: pkg.version, repository: pkg.homepage.replace(/#.*$/, ""), commit: commit() },
  oidcIssuers,
});

// The verifier never fetches; a fixture must not reach the network.
globalThis.fetch = () => Promise.reject(new Error("network access is disabled in the conformance adapter"));

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of rl) {
  if (line.trim() === "") continue;
  let request;
  try {
    request = JSON.parse(line);
  } catch (e) {
    process.stdout.write(`${JSON.stringify({ id: null, ok: false, error_code: "INTERNAL_ERROR", message: `bad request: ${e.message}` })}\n`);
    continue;
  }
  const reply = await adapter.handle(request);
  process.stdout.write(`${JSON.stringify(reply)}\n`);
  if (request.op === "shutdown") break;
}
