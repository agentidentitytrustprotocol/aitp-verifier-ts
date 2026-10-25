// Field and curve arithmetic for the checks WebCrypto does not make.
//
// WebCrypto verifies signatures; it does not promise RFC-AITP-0001 §5.4.7
// strictness, and implementations differ (OpenSSL accepts a small-order
// Ed25519 key, and no WebCrypto ECDSA rejects a high-S signature). So these
// checks run here, in BigInt, before any signature reaches WebCrypto. The
// same code decompresses SEC1 P-256 points, which not every WebCrypto
// imports, and derives a P-256 public key from a private scalar.
//
// None of this is constant time. It handles public values only, except
// `p256PublicFromScalar`, which is used for the published KAT keys.

import { bigToBytesBE, bytesToBigBE, bytesToBigLE } from "./bytes.js";

function mod(a: bigint, m: bigint): bigint {
  const r = a % m;
  return r < 0n ? r + m : r;
}

function pow(base: bigint, exp: bigint, m: bigint): bigint {
  let result = 1n;
  base = mod(base, m);
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % m;
    base = (base * base) % m;
    exp >>= 1n;
  }
  return result;
}

function inv(a: bigint, m: bigint): bigint {
  let [r0, r1] = [mod(a, m), m];
  let [s0, s1] = [1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  if (r0 !== 1n) throw new RangeError("not invertible");
  return mod(s0, m);
}

// ---------------------------------------------------------------- Ed25519

const ED_P = 2n ** 255n - 19n;
const ED_D = mod(-121665n * inv(121666n, ED_P), ED_P);
const ED_SQRT_M1 = pow(2n, (ED_P - 1n) / 4n, ED_P);
/** The prime order of the Ed25519 base point (RFC 8032 §5.1). */
export const ED25519_L = 2n ** 252n + 27742317777372353535851937790883648493n;

interface EdPoint {
  x: bigint;
  y: bigint;
  z: bigint;
  t: bigint;
}

/**
 * Decode a 32-byte Ed25519 point (RFC 8032 §5.1.3), rejecting every
 * non-canonical encoding: y ≥ p, and x = 0 with the sign bit set.
 */
function edDecode(bytes: Uint8Array): EdPoint | undefined {
  if (bytes.length !== 32) return undefined;
  const sign = ((bytes[31] as number) >> 7) & 1;
  const y = bytesToBigLE(bytes) & ((1n << 255n) - 1n);
  if (y >= ED_P) return undefined;
  const y2 = (y * y) % ED_P;
  const u = mod(y2 - 1n, ED_P);
  const v = mod(ED_D * y2 + 1n, ED_P);
  const v3 = (v * v * v) % ED_P;
  const v7 = (v3 * v3 * v) % ED_P;
  let x = (u * v3 * pow(u * v7, (ED_P - 5n) / 8n, ED_P)) % ED_P;
  const vx2 = (v * x * x) % ED_P;
  if (vx2 === u) {
    // x is a root
  } else if (vx2 === mod(-u, ED_P)) {
    x = (x * ED_SQRT_M1) % ED_P;
  } else {
    return undefined;
  }
  if (x === 0n && sign === 1) return undefined;
  if (Number(x & 1n) !== sign) x = ED_P - x;
  return { x, y, z: 1n, t: (x * y) % ED_P };
}

function edDouble(p: EdPoint): EdPoint {
  // RFC 8032 §5.1.4 doubling, extended coordinates, a = -1.
  const a = (p.x * p.x) % ED_P;
  const b = (p.y * p.y) % ED_P;
  const c = (2n * p.z * p.z) % ED_P;
  const h = (a + b) % ED_P;
  const e = mod(h - ((p.x + p.y) * (p.x + p.y)), ED_P);
  const g = mod(a - b, ED_P);
  const f = (c + g) % ED_P;
  return { x: (e * f) % ED_P, y: (g * h) % ED_P, t: (e * h) % ED_P, z: (f * g) % ED_P };
}

function edIsSmallOrder(p: EdPoint): boolean {
  const q = edDouble(edDouble(edDouble(p)));
  return q.x === 0n && q.y === q.z;
}

/** A canonical, decodable encoding of a point that is not of small order. */
export function ed25519PublicKeyIsStrict(bytes: Uint8Array): boolean {
  const p = edDecode(bytes);
  return p !== undefined && !edIsSmallOrder(p);
}

/**
 * The §5.4.7 checks on a 64-byte Ed25519 signature `R || S`: S < L, and R a
 * canonical encoding of a point not of small order (the verify_strict
 * profile; §5.4.7 permits the small-order R check).
 */
export function ed25519SignatureIsStrict(sig: Uint8Array): boolean {
  if (sig.length !== 64) return false;
  if (bytesToBigLE(sig.subarray(32)) >= ED25519_L) return false;
  const r = edDecode(sig.subarray(0, 32));
  return r !== undefined && !edIsSmallOrder(r);
}

// ------------------------------------------------------------------ P-256

const P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
/** The order of the P-256 base point. */
export const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
const P256_G = {
  x: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  y: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
};

export interface AffinePoint {
  x: bigint;
  y: bigint;
}

function p256OnCurve(pt: AffinePoint): boolean {
  if (pt.x >= P256_P || pt.y >= P256_P) return false;
  const rhs = mod(pt.x * pt.x * pt.x - 3n * pt.x + P256_B, P256_P);
  return (pt.y * pt.y) % P256_P === rhs;
}

/** Decompress a 33-byte SEC1 compressed point (SEC 1 §2.3.4). */
export function p256Decompress(bytes: Uint8Array): AffinePoint | undefined {
  if (bytes.length !== 33) return undefined;
  const prefix = bytes[0];
  if (prefix !== 0x02 && prefix !== 0x03) return undefined;
  const x = bytesToBigBE(bytes.subarray(1));
  if (x >= P256_P) return undefined;
  const rhs = mod(x * x * x - 3n * x + P256_B, P256_P);
  let y = pow(rhs, (P256_P + 1n) / 4n, P256_P);
  if ((y * y) % P256_P !== rhs) return undefined;
  if (Number(y & 1n) !== (prefix & 1)) y = P256_P - y;
  return { x, y };
}

/** SEC1-compress an affine point, after checking it is on the curve. */
export function p256Compress(pt: AffinePoint): Uint8Array | undefined {
  if (!p256OnCurve(pt)) return undefined;
  const out = new Uint8Array(33);
  out[0] = pt.y & 1n ? 0x03 : 0x02;
  out.set(bigToBytesBE(pt.x, 32), 1);
  return out;
}

function p256Add(a: AffinePoint | null, b: AffinePoint | null): AffinePoint | null {
  if (a === null) return b;
  if (b === null) return a;
  if (a.x === b.x) {
    if (mod(a.y + b.y, P256_P) === 0n) return null;
    const l = mod(3n * a.x * a.x - 3n, P256_P) * inv(2n * a.y, P256_P);
    const x = mod(l * l - 2n * a.x, P256_P);
    return { x, y: mod(l * (a.x - x) - a.y, P256_P) };
  }
  const l = mod(b.y - a.y, P256_P) * inv(b.x - a.x, P256_P);
  const x = mod(l * l - a.x - b.x, P256_P);
  return { x, y: mod(l * (a.x - x) - a.y, P256_P) };
}

/** The public point for a private scalar in [1, n-1]. */
export function p256PublicFromScalar(d: bigint): AffinePoint {
  if (d <= 0n || d >= P256_N) throw new RangeError("P-256 scalar out of range");
  let result: AffinePoint | null = null;
  let addend: AffinePoint | null = P256_G;
  for (let k = d; k > 0n; k >>= 1n) {
    if (k & 1n) result = p256Add(result, addend);
    addend = p256Add(addend, addend);
  }
  if (result === null) throw new RangeError("scalar is a multiple of n");
  return result;
}

/** The §5.4.7 checks on a 64-byte `R || S`: 0 < R, S < n and S ≤ n/2. */
export function p256SignatureIsStrict(sig: Uint8Array): boolean {
  if (sig.length !== 64) return false;
  const r = bytesToBigBE(sig.subarray(0, 32));
  const s = bytesToBigBE(sig.subarray(32));
  return r > 0n && r < P256_N && s > 0n && s <= P256_N >> 1n;
}

/** Replace S by n − S when S > n/2, as §5.4.7 requires of a signer. */
export function p256NormalizeLowS(sig: Uint8Array): Uint8Array {
  const s = bytesToBigBE(sig.subarray(32));
  if (s <= P256_N >> 1n) return sig;
  const out = new Uint8Array(64);
  out.set(sig.subarray(0, 32));
  out.set(bigToBytesBE(P256_N - s, 32), 32);
  return out;
}
