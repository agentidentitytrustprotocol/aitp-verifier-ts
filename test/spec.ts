// Access to the vendored spec files (vendor/spec, pinned by SPEC_VERSION).

import { readFileSync } from "node:fs";
import { parseJson, type JsonObject } from "../src/json.js";

const ROOT = new URL("../../", import.meta.url);

export function readText(rel: string): string {
  return readFileSync(new URL(rel, ROOT), "utf8");
}

/** Parsed with the package's own strict parser, so duplicate keys fail loudly. */
export function readJson(rel: string): JsonObject {
  return parseJson(readText(rel)) as JsonObject;
}

export const KAT = "vendor/spec/schemas/conformance/known-answer/";

export interface Vector extends JsonObject {}

export function vectors(file: string): Vector[] {
  return readJson(KAT + file).vectors as Vector[];
}

export function vector(file: string, id: string): Vector {
  const v = vectors(file).find((x) => x.id === id);
  if (v === undefined) throw new Error(`${file}: no vector ${id}`);
  return v;
}

export function str(v: JsonObject, key: string): string {
  const x = v[key];
  if (typeof x !== "string") throw new Error(`${String(v.id)}.${key} is not a string`);
  return x;
}
