// Time, always passed in. Every verify path takes `now` (Unix seconds) from
// its caller, so a verdict depends only on its inputs: conformance fixtures
// supply their own `now`, and nothing here reads the clock.

/** RFC-AITP-0001 §5.5 default timestamp tolerance, in seconds. */
export const DEFAULT_TOLERANCE_SECS = 300;

/** Throws unless `now` is a non-negative safe integer number of seconds. */
export function checkNow(now: number): number {
  if (!Number.isSafeInteger(now) || now < 0) throw new RangeError(`now must be Unix seconds, got ${now}`);
  return now;
}

/** "`exp` in the future": anything at or before `now` is expired. */
export function isExpired(exp: number, now: number): boolean {
  return exp <= now;
}

/** RFC-AITP-0001 §5.5: |now − timestamp| ≤ tolerance. */
export function withinWindow(timestamp: number, now: number, tolerance = DEFAULT_TOLERANCE_SECS): boolean {
  return Math.abs(now - timestamp) <= tolerance;
}

/**
 * The current time in Unix seconds, for callers outside a verify path that
 * have no clock of their own. Verification functions never call it.
 */
export function systemNow(): number {
  return Math.floor(Date.now() / 1000);
}
