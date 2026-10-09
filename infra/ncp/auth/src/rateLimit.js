/** Simple in-memory sliding-window rate limiter keyed by caller-supplied string. */
export class RateLimiter {
  constructor({ windowMs, max }) {
    this.windowMs = windowMs;
    this.max = max;
    this.hits = new Map(); // key -> array of timestamps (ms)
  }

  /** Returns true if the call is allowed (and records it), false if rate-limited. */
  check(key) {
    const now = Date.now();
    let arr = this.hits.get(key);
    if (!arr) {
      arr = [];
      this.hits.set(key, arr);
    }
    while (arr.length && now - arr[0] > this.windowMs) arr.shift();
    if (arr.length >= this.max) return false;
    arr.push(now);
    return true;
  }

  cleanup() {
    const now = Date.now();
    for (const [key, arr] of this.hits) {
      while (arr.length && now - arr[0] > this.windowMs) arr.shift();
      if (arr.length === 0) this.hits.delete(key);
    }
  }

  get size() {
    return this.hits.size;
  }
}
