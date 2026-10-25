#!/usr/bin/env node
// Writes dist/build-info.json, the commit the adapter reports in its init
// reply. An installed package has no git checkout of its own (and may sit
// inside someone else's), so the commit is fixed at build time.
//
// The source is GITHUB_SHA in CI, else this checkout's HEAD, else "unknown".
import { execFileSync } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

function commit() {
  if (process.env.GITHUB_SHA) return process.env.GITHUB_SHA;
  if (!existsSync(join(ROOT, ".git"))) return "unknown";
  try {
    return execFileSync("git", ["-C", ROOT, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  } catch {
    return "unknown";
  }
}

writeFileSync(join(ROOT, "dist", "build-info.json"), `${JSON.stringify({ commit: commit() })}\n`);
