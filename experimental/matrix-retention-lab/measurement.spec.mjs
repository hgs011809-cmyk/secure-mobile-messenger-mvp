import test from 'node:test';
import assert from 'node:assert/strict';
import { ScrubMeasurements } from './measurement.mjs';

const register = (m, eventId = '$private-event:server', cohort = 'baseline', requestedAtMs = 0, acknowledgedAtMs = requestedAtMs) => m.register({ eventId, cohort, requestedAtMs, acknowledgedAtMs });
const probe = (m, state, start, finish = start, eventIds = ['$private-event:server']) => m.observe({ eventIds, states: Array.isArray(state) ? state : [state], probeStartedAtMs: start, probeFinishedAtMs: finish });

test('defaults and empty evidence cannot pass', () => {
  const m = new ScrubMeasurements();
  assert.equal(m.report().targetMs, 300000);
  assert.equal(m.completed, false);
  assert.equal(m.report().passed, false);
  assert.deepEqual(m.report().scrubUpperMs, { min: null, p50: null, p95: null, max: null });
});

test('scrub upper bound exactly at target proves compliance', () => {
  const m = new ScrubMeasurements({ targetMs: 100 }); register(m);
  probe(m, 'encrypted', 90, 95); probe(m, 'scrubbed', 95, 100);
  assert.equal(m.completed, true); assert.equal(m.report().passed, true);
  assert.equal(m.report().counts.withinTarget, 1); assert.equal(m.report().scrubUpperMs.max, 100);
});

test('encrypted lower bound exactly at target confirms a sticky miss', () => {
  const m = new ScrubMeasurements({ targetMs: 100 }); register(m);
  probe(m, 'encrypted', 100);
  assert.equal(m.report().counts.confirmedMiss, 1); assert.equal(m.report().counts.pending, 1);
  probe(m, 'scrubbed', 100);
  assert.equal(m.completed, true); assert.equal(m.report().counts.confirmedMiss, 1);
  assert.equal(m.report().counts.withinTarget, 0); assert.equal(m.report().passed, false);
});

test('delayed first probe is boundary not proven, not a confirmed miss', () => {
  const m = new ScrubMeasurements({ targetMs: 100 }); register(m);
  probe(m, 'scrubbed', 500, 510);
  assert.equal(m.report().counts.boundaryNotProven, 1);
  assert.equal(m.report().counts.confirmedMiss, 0); assert.equal(m.report().passed, false);
});

test('probe finish, not start, is the conservative scrub upper bound', () => {
  const m = new ScrubMeasurements({ targetMs: 100 }); register(m);
  probe(m, 'scrubbed', 90, 101);
  assert.equal(m.report().counts.boundaryNotProven, 1); assert.equal(m.report().scrubUpperMs.max, 101);
});

test('proof uses request while confirmed miss uses acknowledgement', () => {
  const m = new ScrubMeasurements({ targetMs: 100 });
  register(m, '$private-event:server', 'baseline', 0, 20);
  probe(m, 'encrypted', 110); assert.equal(m.report().counts.confirmedMiss, 0);
  probe(m, 'scrubbed', 111, 115);
  assert.equal(m.report().counts.boundaryNotProven, 1); assert.equal(m.report().scrubUpperMs.max, 115);
});

test('late acknowledgement cannot create a false within-target result', () => {
  const m = new ScrubMeasurements({ targetMs: 100 });
  register(m, '$private-event:server', 'baseline', 0, 80); probe(m, 'scrubbed', 120, 130);
  assert.equal(m.report().counts.withinTarget, 0); assert.equal(m.report().counts.boundaryNotProven, 1);
});

test('restart downtime is counted without resetting the clock', () => {
  const m = new ScrubMeasurements({ targetMs: 300000 });
  register(m, '$private-event:server', 'restart-pending', 1000, 1010);
  probe(m, 'encrypted', 2000);
  // Service was down until 401010; the observer retains the original clock.
  probe(m, 'encrypted', 401010, 401020); probe(m, 'scrubbed', 401020, 401030);
  assert.equal(m.report().counts.confirmedMiss, 1); assert.equal(m.report().scrubUpperMs.max, 400030);
  assert.equal(m.report().passed, false);
});

test('repeated scrub observations never reset the first scrub time', () => {
  const m = new ScrubMeasurements({ targetMs: 100 }); register(m);
  probe(m, 'scrubbed', 50, 60); probe(m, 'scrubbed', 200, 210);
  assert.equal(m.report().scrubUpperMs.max, 60); assert.equal(m.report().passed, true);
});

test('state regression is rejected without changing evidence', () => {
  const m = new ScrubMeasurements(); register(m); probe(m, 'scrubbed', 10);
  const before = m.report();
  assert.throws(() => probe(m, 'encrypted', 20), /regress/); assert.deepEqual(m.report(), before);
});

test('invalid registration, cohorts, and targets fail closed', () => {
  for (const targetMs of [NaN, Infinity, -1, '100']) assert.throws(() => new ScrubMeasurements({ targetMs }));
  const m = new ScrubMeasurements();
  for (const cohort of ['', 'A', 'has space', 'has_underscore', 'a'.repeat(33), null]) assert.throws(() => register(m, 'secret', cohort));
  for (const eventId of ['', ' ', null, 3]) assert.throws(() => register(m, eventId));
  for (const [requestedAtMs, acknowledgedAtMs] of [[2, 1], [NaN, 1], [0, Infinity], ['0', 1]]) assert.throws(() => register(m, 'secret', 'baseline', requestedAtMs, acknowledgedAtMs));
  register(m); assert.throws(() => register(m), /Duplicate/); assert.equal(m.report().counts.total, 1);
});

test('exact batches reject missing, unexpected, unknown, duplicate and reordered IDs', () => {
  const m = new ScrubMeasurements(); register(m, 'id-a'); register(m, 'id-b');
  for (const eventIds of [['id-a'], ['id-a', 'id-b', 'id-c'], ['id-a', 'unknown'], ['id-a', 'id-a'], ['id-b', 'id-a']]) assert.throws(() => m.observe({ eventIds, states: eventIds.map(() => 'scrubbed'), probeStartedAtMs: 10, probeFinishedAtMs: 20 }));
  assert.equal(m.report().counts.scrubbed, 0);
  probe(m, ['scrubbed', 'scrubbed'], 10, 20, ['id-a', 'id-b']); assert.equal(m.completed, true);
});

test('invalid shapes and states are rejected atomically', () => {
  const m = new ScrubMeasurements(); register(m, 'id-a'); register(m, 'id-b');
  const valid = { eventIds: ['id-a', 'id-b'], states: ['scrubbed', 'scrubbed'], probeStartedAtMs: 10, probeFinishedAtMs: 20 };
  for (const changes of [{ eventIds: 'id-a' }, { states: 'scrubbed' }, { states: ['scrubbed'] }, { states: ['scrubbed', 'unknown'] }, { states: new Array(2) }, { eventIds: new Array(2) }]) {
    assert.throws(() => m.observe({ ...valid, ...changes })); assert.equal(m.report().counts.scrubbed, 0);
  }
  m.observe(valid); assert.equal(m.completed, true);
});

test('probe clock is finite, ordered, nonoverlapping and after acknowledgement', () => {
  const m = new ScrubMeasurements(); register(m, '$private-event:server', 'baseline', 0, 10);
  for (const [start, finish] of [[9, 10], [20, 19], [NaN, 20], [10, Infinity], ['10', 20]]) assert.throws(() => probe(m, 'encrypted', start, finish));
  probe(m, 'encrypted', 10, 20);
  assert.throws(() => probe(m, 'encrypted', 19, 30)); assert.throws(() => probe(m, 'encrypted', 0, 1));
  probe(m, 'scrubbed', 20, 30); assert.equal(m.report().scrubUpperMs.max, 30);
});

test('latest acknowledgement across all events bounds probe start', () => {
  const m = new ScrubMeasurements(); register(m, 'id-a', 'baseline', 0, 1); register(m, 'id-b', 'baseline', 0, 25);
  assert.throws(() => probe(m, ['scrubbed', 'scrubbed'], 20, 30, ['id-a', 'id-b'])); assert.equal(m.report().counts.scrubbed, 0);
});

test('safe cohort counts and nearest-rank completed timing percentiles', () => {
  const m = new ScrubMeasurements({ targetMs: 100 });
  for (let i = 0; i < 20; i++) register(m, 'private-' + i, i % 2 ? 'bounded-burst' : 'baseline');
  const ids = Array.from({ length: 20 }, (_, i) => 'private-' + i);
  for (let i = 0; i < 20; i++) probe(m, ids.map((_, j) => j <= i ? 'scrubbed' : 'encrypted'), i + 1, i + 1, ids);
  const r = m.report();
  assert.deepEqual(r.scrubUpperMs, { min: 1, p50: 10, p95: 19, max: 20 });
  assert.deepEqual(r.counts, { total: 20, scrubbed: 20, withinTarget: 20, confirmedMiss: 0, boundaryNotProven: 0, pending: 0 });
  assert.equal(r.cohorts.length, 2); assert.equal(r.cohorts[0].cohort, 'baseline'); assert.equal(r.cohorts[0].total, 10); assert.equal(r.passed, true);
  r.counts.total = 999; assert.equal(m.report().counts.total, 20);
});

test('report does not leak IDs, tokens, payloads, or input timestamp records', () => {
  const m = new ScrubMeasurements();
  m.register({ eventId: '$SUPER_SECRET_ID:example', cohort: 'baseline', requestedAtMs: 123, acknowledgedAtMs: 125, token: 'TOKEN_SECRET', payload: 'PAYLOAD_SECRET' });
  m.observe({ eventIds: ['$SUPER_SECRET_ID:example'], states: ['scrubbed'], probeStartedAtMs: 130, probeFinishedAtMs: 140, token: 'PROBE_TOKEN_SECRET' });
  const serialized = JSON.stringify(m.report());
  for (const secret of ['SUPER_SECRET_ID', 'TOKEN_SECRET', 'PAYLOAD_SECRET', 'PROBE_TOKEN_SECRET', 'requestedAtMs', 'acknowledgedAtMs', 'eventIds']) assert.equal(serialized.includes(secret), false);
  assert.deepEqual(Object.keys(m.report()).sort(), ['cohorts', 'counts', 'passed', 'scrubUpperMs', 'targetMs']);
});

test('pending events are excluded from timing percentiles and cannot pass', () => {
  const m = new ScrubMeasurements(); register(m, 'id-a'); register(m, 'id-b');
  probe(m, ['scrubbed', 'encrypted'], 10, 20, ['id-a', 'id-b']);
  assert.deepEqual(m.report().scrubUpperMs, { min: 20, p50: 20, p95: 20, max: 20 });
  assert.equal(m.completed, false); assert.equal(m.report().passed, false); assert.equal(m.report().counts.pending, 1);
});
