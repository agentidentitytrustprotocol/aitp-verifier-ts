// Agent IDs (RFC-AITP-0001 §5.3).
//
//   aid:pubkey:<43>            legacy, Ed25519
//   aid:pubkey:ed25519:<43>    tagged Ed25519
//   aid:pubkey:p256:<44>       SEC1-compressed P-256
//
// The legacy and the ed25519-tagged spelling name the same key and are
// equivalent for trust (`sameKeyAid`), but they are different strings, and
// every signing input and every byte-for-byte comparison (`aud`, `iss`,
// `sub`) uses the string as written. Nothing here rewrites one into the other.

import * as b64 from "./b64.js";
import { type Alg, type PublicKey, publicKeyFromRaw, publicKeyLength, sameKey } from "./keys.js";

export interface Aid {
  /** The AID exactly as written. */
  readonly text: string;
  readonly key: PublicKey;
  /** Whether the AID carries an algorithm tag. */
  readonly tagged: boolean;
}

const PREFIX = "aid:pubkey:";
const IDENT = /^[A-Za-z0-9_-]+$/;

export function parseAid(text: string): Aid | undefined {
  if (!text.startsWith(PREFIX)) return undefined;
  const rest = text.slice(PREFIX.length);
  const colon = rest.indexOf(":");
  let alg: Alg;
  let ident: string;
  if (colon === -1) {
    alg = "ed25519";
    ident = rest;
  } else {
    const tag = rest.slice(0, colon);
    if (tag !== "ed25519" && tag !== "p256") return undefined;
    alg = tag;
    ident = rest.slice(colon + 1);
  }
  const chars = alg === "ed25519" ? 43 : 44;
  if (ident.length !== chars || !IDENT.test(ident)) return undefined;
  const raw = b64.decodeExact(ident, publicKeyLength(alg));
  if (raw === undefined) return undefined;
  const key = publicKeyFromRaw(alg, raw);
  if (key === undefined) return undefined;
  return { text, key, tagged: colon !== -1 };
}

/** The AID for a key: tagged for P-256 (the only form it has), legacy or tagged for Ed25519. */
export function aidFor(key: PublicKey, options: { tagged?: boolean } = {}): string {
  const ident = b64.encode(key.raw);
  if (key.alg === "p256") return `${PREFIX}p256:${ident}`;
  return options.tagged ? `${PREFIX}ed25519:${ident}` : `${PREFIX}${ident}`;
}

/** The AID-identifier component (43 or 44 chars). */
export function aidIdentifier(aid: Aid): string {
  return b64.encode(aid.key.raw);
}

/** True when two AIDs name the same key: same algorithm, same bytes. */
export function sameKeyAid(a: Aid, b: Aid): boolean {
  return sameKey(a.key, b.key);
}
