// Public and private keys, and the two signature primitives, on WebCrypto.
//
// RFC-AITP-0001 §5.4.3 makes Ed25519 and P-256 the only algorithms and both
// mandatory. A key is held as its AID encoding: 32 raw bytes for Ed25519, the
// 33-byte SEC1 compressed point for P-256.
//
// `verifyRaw` is the one place a signature meets WebCrypto, and it applies
// the §5.4.7 strictness checks first. Its `message` is what the primitive
// itself consumes: Ed25519 signs `message` (PureEdDSA); P-256 is ECDSA with
// SHA-256 over `message`. The JCS profile and the JWS profile differ only in
// what they pass as `message` (see sigfield.ts and jws.ts).

import * as b64 from "./b64.js";
import { bigToBytesBE, buf, bytesToBigBE, concat } from "./bytes.js";
import {
  ed25519PublicKeyIsStrict,
  ed25519SignatureIsStrict,
  p256Compress,
  p256Decompress,
  p256NormalizeLowS,
  p256PublicFromScalar,
  p256SignatureIsStrict,
} from "./curves.js";

export type Alg = "ed25519" | "p256";

export const ALGS: readonly Alg[] = ["ed25519", "p256"];

export interface PublicKey {
  readonly alg: Alg;
  /** 32 bytes (Ed25519) or the 33-byte compressed point (P-256). */
  readonly raw: Uint8Array;
}

export interface PrivateKey {
  readonly alg: Alg;
  readonly publicKey: PublicKey;
  readonly cryptoKey: CryptoKey;
}

/** The runtime has no WebCrypto, or no support for the algorithm. */
export class AlgorithmUnavailableError extends Error {
  constructor(readonly alg: Alg, cause?: unknown) {
    super(`${alg} is not available in this runtime's WebCrypto`, { cause });
    this.name = "AlgorithmUnavailableError";
  }
}

function subtle(alg: Alg): SubtleCrypto {
  const s = globalThis.crypto?.subtle;
  if (s === undefined) throw new AlgorithmUnavailableError(alg);
  return s;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const s = globalThis.crypto?.subtle;
  if (s === undefined) throw new Error("WebCrypto is not available");
  return new Uint8Array(await s.digest("SHA-256", buf(data)));
}

export function publicKeyLength(alg: Alg): number {
  return alg === "ed25519" ? 32 : 33;
}

/** Validate an AID-encoded key: right length, and a point on the curve. */
export function publicKeyFromRaw(alg: Alg, raw: Uint8Array): PublicKey | undefined {
  if (raw.length !== publicKeyLength(alg)) return undefined;
  if (alg === "p256" && p256Decompress(raw) === undefined) return undefined;
  return { alg, raw: raw.slice() };
}

export function sameKey(a: PublicKey, b: PublicKey): boolean {
  return a.alg === b.alg && b64.encode(a.raw) === b64.encode(b.raw);
}

/** The JWK members of a public key (RFC 8037 OKP, RFC 7518 EC). */
export function publicJwk(key: PublicKey): { crv: string; kty: string; x: string; y?: string } {
  if (key.alg === "ed25519") return { crv: "Ed25519", kty: "OKP", x: b64.encode(key.raw) };
  const pt = p256Decompress(key.raw);
  if (pt === undefined) throw new RangeError("invalid P-256 point");
  return { crv: "P-256", kty: "EC", x: b64.encode(bigToBytesBE(pt.x, 32)), y: b64.encode(bigToBytesBE(pt.y, 32)) };
}

/** The key behind uncompressed P-256 JWK coordinates, if they are on the curve. */
export function p256FromCoordinates(x: Uint8Array, y: Uint8Array): PublicKey | undefined {
  if (x.length !== 32 || y.length !== 32) return undefined;
  const raw = p256Compress({ x: bytesToBigBE(x), y: bytesToBigBE(y) });
  return raw === undefined ? undefined : { alg: "p256", raw };
}

async function importPublic(key: PublicKey): Promise<CryptoKey> {
  const s = subtle(key.alg);
  try {
    if (key.alg === "ed25519") {
      return await s.importKey("raw", buf(key.raw), { name: "Ed25519" }, false, ["verify"]);
    }
    return await s.importKey("jwk", { ...publicJwk(key), ext: true }, { name: "ECDSA", namedCurve: "P-256" }, false, [
      "verify",
    ]);
  } catch (e) {
    if (key.alg === "ed25519") throw new AlgorithmUnavailableError("ed25519", e);
    throw e;
  }
}

/**
 * Verify `sig` over `message` under `key`, strictly (§5.4.7). False for any
 * signature that is malformed, non-canonical or does not verify. Throws
 * AlgorithmUnavailableError when the runtime cannot check the algorithm at
 * all; callers turn that into a rejection, never a pass.
 */
export async function verifyRaw(key: PublicKey, message: Uint8Array, sig: Uint8Array): Promise<boolean> {
  if (key.alg === "ed25519") {
    if (!ed25519PublicKeyIsStrict(key.raw) || !ed25519SignatureIsStrict(sig)) return false;
  } else if (!p256SignatureIsStrict(sig)) {
    return false;
  }
  const cryptoKey = await importPublic(key);
  const algorithm = key.alg === "ed25519" ? { name: "Ed25519" } : { name: "ECDSA", hash: "SHA-256" };
  try {
    return await subtle(key.alg).verify(algorithm, cryptoKey, buf(sig), buf(message));
  } catch {
    return false;
  }
}

const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

/** An Ed25519 private key from its 32-byte RFC 8032 seed. */
export async function ed25519FromSeed(seed: Uint8Array): Promise<PrivateKey> {
  if (seed.length !== 32) throw new RangeError("an Ed25519 seed is 32 bytes");
  const s = subtle("ed25519");
  let cryptoKey: CryptoKey;
  let jwk: JsonWebKey;
  try {
    cryptoKey = await s.importKey("pkcs8", buf(concat(ED25519_PKCS8_PREFIX, seed)), { name: "Ed25519" }, true, ["sign"]);
    jwk = await s.exportKey("jwk", cryptoKey);
  } catch (e) {
    throw new AlgorithmUnavailableError("ed25519", e);
  }
  if (typeof jwk.x !== "string") throw new Error("WebCrypto did not export the Ed25519 public key");
  return { alg: "ed25519", cryptoKey, publicKey: { alg: "ed25519", raw: b64.decode(jwk.x) } };
}

/** A P-256 private key from its 32-byte big-endian scalar. */
export async function p256FromScalar(scalar: Uint8Array): Promise<PrivateKey> {
  if (scalar.length !== 32) throw new RangeError("a P-256 scalar is 32 bytes");
  const pt = p256PublicFromScalar(bytesToBigBE(scalar));
  const raw = p256Compress(pt);
  if (raw === undefined) throw new RangeError("derived point is not on the curve");
  const jwk = {
    kty: "EC",
    crv: "P-256",
    x: b64.encode(bigToBytesBE(pt.x, 32)),
    y: b64.encode(bigToBytesBE(pt.y, 32)),
    d: b64.encode(scalar),
    ext: true,
  };
  const cryptoKey = await subtle("p256").importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  return { alg: "p256", cryptoKey, publicKey: { alg: "p256", raw } };
}

/**
 * Sign `message` with the primitive `verifyRaw` checks. P-256 signatures
 * come out of WebCrypto with a random k and are normalized to low S
 * (§5.4.7), so they verify everywhere but are not byte-reproducible.
 */
export async function signRaw(key: PrivateKey, message: Uint8Array): Promise<Uint8Array> {
  const algorithm = key.alg === "ed25519" ? { name: "Ed25519" } : { name: "ECDSA", hash: "SHA-256" };
  const sig = new Uint8Array(await subtle(key.alg).sign(algorithm, key.cryptoKey, buf(message)));
  return key.alg === "p256" ? p256NormalizeLowS(sig) : sig;
}

let ed25519Probe: Promise<boolean> | undefined;

/** Whether this runtime's WebCrypto implements Ed25519. */
export function ed25519Available(): Promise<boolean> {
  ed25519Probe ??= (async () => {
    try {
      const s = globalThis.crypto?.subtle;
      if (s === undefined) return false;
      await s.importKey("raw", buf(new Uint8Array(32).fill(1)), { name: "Ed25519" }, false, ["verify"]);
      return true;
    } catch {
      return false;
    }
  })();
  return ed25519Probe;
}
