// The message_id deny list of RFC-AITP-0001 §5.5.
//
// A message_id is remembered once the message carrying it has verified,
// until its timestamp leaves the tolerance window; after that the
// timestamp check alone rejects a replay. Holding a rejected message's id
// would let an attacker who guesses an id burn it before the real sender
// uses it, so only verified messages are recorded.

export class ReplayCache {
  readonly #seen = new Map<string, number>();

  /** Whether `messageId` has already been accepted. */
  has(messageId: string): boolean {
    return this.#seen.has(messageId);
  }

  /** Record an accepted message, kept until `until` (Unix seconds). */
  add(messageId: string, until: number): void {
    this.#seen.set(messageId, until);
  }

  /** Forget every id whose window closed before `now`. */
  prune(now: number): void {
    for (const [id, until] of this.#seen) if (until < now) this.#seen.delete(id);
  }

  clear(): void {
    this.#seen.clear();
  }
}
