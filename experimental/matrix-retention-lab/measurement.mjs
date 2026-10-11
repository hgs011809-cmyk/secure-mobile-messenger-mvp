/** Conservative, in-memory timing evidence. Does not contain Matrix or network code. */
const SAFE_COHORT = /^[a-z-]{1,32}$/;
const finite = (value) => typeof value === 'number' && Number.isFinite(value);
const counts = () => ({ total: 0, scrubbed: 0, withinTarget: 0, confirmedMiss: 0, boundaryNotProven: 0, pending: 0 });
const percentile = (sorted, fraction) => sorted.length ? sorted[Math.max(0, Math.ceil(sorted.length * fraction) - 1)] : null;

export class ScrubMeasurements {
  #targetMs;
  #events = new Map();
  #lastProbeFinished = null;

  constructor({ targetMs = 300000 } = {}) {
    if (!finite(targetMs) || targetMs < 0) throw new TypeError('targetMs must be finite and nonnegative');
    this.#targetMs = targetMs;
  }

  register({ eventId, cohort, requestedAtMs, acknowledgedAtMs } = {}) {
    if (typeof eventId !== 'string' || !eventId.trim()) throw new TypeError('eventId must be a nonempty string');
    if (this.#events.has(eventId)) throw new Error('Duplicate event ID');
    if (typeof cohort !== 'string' || !SAFE_COHORT.test(cohort)) throw new TypeError('Invalid safe cohort');
    if (!finite(requestedAtMs) || !finite(acknowledgedAtMs) || requestedAtMs > acknowledgedAtMs) {
      throw new TypeError('Request and acknowledgement timestamps must be finite and ordered');
    }
    this.#events.set(eventId, { cohort, requestedAtMs, acknowledgedAtMs, lastEncryptedLower: null, firstScrubUpper: null, confirmedMiss: false });
  }

  observe({ eventIds, states, probeStartedAtMs, probeFinishedAtMs } = {}) {
    if (!Array.isArray(eventIds) || !Array.isArray(states) || eventIds.length !== states.length || eventIds.length !== this.#events.size || !eventIds.length) {
      throw new TypeError('Observation must contain an exact nonempty parallel batch');
    }
    if (!finite(probeStartedAtMs) || !finite(probeFinishedAtMs) || probeStartedAtMs > probeFinishedAtMs || (this.#lastProbeFinished !== null && probeStartedAtMs < this.#lastProbeFinished)) {
      throw new TypeError('Probe timestamps must be finite and monotonic');
    }
    const expected = [...this.#events.keys()];
    const seen = new Set();
    // Validate the entire batch before mutating evidence or the clock.
    for (let index = 0; index < eventIds.length; index++) {
      const id = eventIds[index];
      if (seen.has(id)) throw new Error('Duplicate observation ID');
      seen.add(id);
      if (!this.#events.has(id)) throw new Error('Unknown observation ID');
      if (id !== expected[index]) throw new Error('Observation IDs must match registration order');
      const event = this.#events.get(id);
      if (states[index] !== 'encrypted' && states[index] !== 'scrubbed') throw new TypeError('Invalid observation state');
      if (event.acknowledgedAtMs > probeStartedAtMs) throw new Error('Probe precedes an acknowledgement');
      if (states[index] === 'encrypted' && event.firstScrubUpper !== null) throw new Error('Scrubbed state cannot regress to encrypted');
    }
    for (let index = 0; index < eventIds.length; index++) {
      const event = this.#events.get(eventIds[index]);
      if (states[index] === 'encrypted') {
        event.lastEncryptedLower = probeStartedAtMs;
        if (probeStartedAtMs - event.acknowledgedAtMs >= this.#targetMs) event.confirmedMiss = true;
      } else if (event.firstScrubUpper === null) {
        event.firstScrubUpper = probeFinishedAtMs;
      }
    }
    this.#lastProbeFinished = probeFinishedAtMs;
  }

  get completed() {
    return this.#events.size > 0 && [...this.#events.values()].every(event => event.firstScrubUpper !== null);
  }

  report() {
    const total = counts();
    const cohorts = new Map();
    const timings = [];
    for (const event of this.#events.values()) {
      if (!cohorts.has(event.cohort)) cohorts.set(event.cohort, counts());
      const cohortCounts = cohorts.get(event.cohort);
      const scrubbed = event.firstScrubUpper !== null;
      const upperMs = scrubbed ? event.firstScrubUpper - event.requestedAtMs : null;
      // A confirmed miss is sticky, including the exact-boundary case.
      const withinTarget = scrubbed && !event.confirmedMiss && upperMs <= this.#targetMs;
      for (const tally of [total, cohortCounts]) {
        tally.total++;
        if (scrubbed) tally.scrubbed++; else tally.pending++;
        if (withinTarget) tally.withinTarget++;
        if (event.confirmedMiss) tally.confirmedMiss++;
        else if (scrubbed && !withinTarget) tally.boundaryNotProven++;
      }
      if (scrubbed) timings.push(upperMs);
    }
    timings.sort((a, b) => a - b);
    return {
      targetMs: this.#targetMs,
      passed: this.completed && total.withinTarget === total.total,
      counts: total,
      cohorts: [...cohorts].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([cohort, tally]) => ({ cohort, ...tally })),
      scrubUpperMs: { min: timings[0] ?? null, p50: percentile(timings, 0.5), p95: percentile(timings, 0.95), max: timings.at(-1) ?? null },
    };
  }
}
