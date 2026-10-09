/** In-memory map with per-entry TTL and lazy + periodic cleanup. No persistence. */
export class TtlMap {
  constructor() {
    this.map = new Map();
  }

  set(key, value, ttlMs) {
    this.map.set(key, { value, expiresAt: Date.now() + ttlMs });
  }

  get(key) {
    const entry = this.map.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAt) {
      this.map.delete(key);
      return undefined;
    }
    return entry.value;
  }

  delete(key) {
    this.map.delete(key);
  }

  take(key) {
    const value = this.get(key);
    if (value === undefined) return undefined;
    this.map.delete(key);
    return value;
  }

  entries() {
    // Lazily skips nothing; caller should treat expired-but-not-yet-swept
    // entries as still possibly present. Use get() for authoritative reads.
    return this.map.entries();
  }

  get size() {
    return this.map.size;
  }

  cleanup() {
    const now = Date.now();
    for (const [key, entry] of this.map) {
      if (now > entry.expiresAt) this.map.delete(key);
    }
  }
}
