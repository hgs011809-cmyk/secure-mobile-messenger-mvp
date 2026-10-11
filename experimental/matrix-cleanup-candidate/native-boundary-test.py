#!/usr/bin/env python3
"""Native synthetic unit tests, NOT a real database or encryption test.

CI (CANDIDATE_IMAGE is the built Candidate.Dockerfile image ID/digest):
  docker run --rm --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --entrypoint python \
    --mount type=bind,src="$PWD/experimental/matrix-cleanup-candidate/native-boundary-test.py",dst=/native-boundary-test.py,readonly \
    "$CANDIDATE_IMAGE" -B /native-boundary-test.py

Execute installed decorated CensorEventsStore._censor_redactions, its native
JSON writer, Rust event pruning, and native Clock. Only DB/event retrieval and
DB-heavy superclass initialization are fake. No replica cleanup algorithm.
Fake selection/atomic rollback model DB contracts; they do NOT prove SQL/index,
real DB rollback, authorization, encryption, caches, backups or disk erasure.
Encrypted-shaped events are synthetic, not cryptographically encrypted.
No server, sockets, runtime configs or secrets. No local Node/tests required.
Source gate restores only the scheduler substitution and checks source-policy's
pinned SHA256. No native function, cap, auth or rates are changed.
Nine cases, deterministic Twisted time, no wall-clock waits. Output is fixed
case names/statuses/counts ONLY; library output and tracebacks are discarded.
"""

import contextlib
import hashlib
import json
import logging
import os
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import warnings

PINNED_SHA256 = "6e995c5ddcc078f9ae099af8924ee2a2e40d2f5bf5349d148a1cfc7ad2030f2f"
OLD = "hs.get_clock().looping_call(self._censor_redactions, Duration(minutes=5))"
NEW = "hs.get_clock().looping_call_now(self._censor_redactions, Duration(seconds=30))"
CASES = (
    "test_01_installed_source_gate", "test_02_retention_disabled",
    "test_03_index_transition", "test_04_batch_100", "test_05_batch_101",
    "test_06_invalid_redactions", "test_07_transaction_order_failure_retry",
    "test_08_immediate_and_30_second_ticks", "test_09_async_nonoverlap_error_retry",
)


def build_suite():
    # Import errors are also inside the sanitized output boundary.
    import synapse.storage.databases.main.censor_events as native
    from synapse.api.room_versions import RoomVersions
    from synapse.events import make_event_from_dict
    from synapse.logging.context import make_deferred_yieldable
    from synapse.metrics.background_process_metrics import run_as_background_process
    from synapse.util.clock import Clock
    from twisted.internet import defer, task

    class Updates:
        def __init__(self):
            self.ready, self.checks = True, 0

        async def has_completed_background_update(self, name):
            assert name == "redactions_have_censored_ts_idx"
            self.checks += 1
            return self.ready

    class FakePool:
        def __init__(self, rows):
            self.updates = Updates()
            self.rows = rows
            self.marked, self.json_writes = set(), {}
            self.selects, self.selected_counts, self.attempts = [], [], []
            self.transactions, self.commits = 0, 0
            self.fail_marker_once, self.gate = False, None
            self.active, self.max_active = 0, 0

        async def execute(self, name, sql, cutoff, limit):
            assert name == "_censor_redactions_fetch"
            assert " ".join(sql.split()) == (
                "SELECT redactions.event_id, redacts FROM redactions "
                "LEFT JOIN events AS original_event ON ( redacts = original_event.event_id ) "
                "WHERE NOT have_censored AND redactions.received_ts <= ? "
                "ORDER BY redactions.received_ts ASC LIMIT ?"
            )
            assert limit == 100
            self.selects.append((cutoff, limit))
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            try:
                if self.gate is not None:
                    gate, self.gate = self.gate, None
                    await make_deferred_yieldable(gate)
                # DB fake only: ordered eligible rows obeying native parameter.
                # This does not run or claim to validate SQL selection semantics.
                rows = [(r, e) for r, e in self.rows if r not in self.marked][:limit]
                self.selected_counts.append(len(rows))
                return rows
            finally:
                self.active -= 1

        async def runInteraction(self, name, callback):
            assert name == "_update_censor_txn"
            self.transactions += 1
            txn = SimpleNamespace(pending=[], trace=[])
            self.attempts.append(txn.trace)
            # Exception discards staged writes, modeling the DB pool contract.
            callback(txn)
            for table, identifier, value in txn.pending:
                if table == "event_json":
                    self.json_writes[identifier] = value
                else:
                    self.marked.add(identifier)
            self.commits += 1

        def simple_update_one_txn(self, txn, *, table, keyvalues, updatevalues):
            assert set(keyvalues) == {"event_id"}
            identifier = keyvalues["event_id"]
            txn.trace.append((table, identifier))
            if table == "event_json":
                assert set(updatevalues) == {"json"}
                value = updatevalues["json"]
            else:
                assert table == "redactions"
                assert updatevalues == {"have_censored": True}
                if self.fail_marker_once:
                    self.fail_marker_once = False
                    raise RuntimeError("synthetic_failure")
                value = True
            txn.pending.append((table, identifier, value))

    def event(identifier, *, redaction=False, redacted=True, target=None):
        data = {
            "event_id": identifier, "room_id": "!synthetic:unit.invalid",
            "sender": "@synthetic:unit.invalid",
            "type": "m.room.redaction" if redaction else "m.room.encrypted",
            "content": {} if redaction else {
                "algorithm": "synthetic-unit-only",
                "ciphertext": "synthetic-unit-only-not-encrypted",
            },
            "origin": "unit.invalid", "origin_server_ts": 1, "depth": 1,
            "prev_events": [], "auth_events": [], "hashes": {}, "signatures": {},
        }
        if redaction:
            data["redacts"] = target
        return make_event_from_dict(
            data, RoomVersions.V1, {"redacted": redacted and not redaction}
        )

    class NativeBoundaryTests(unittest.TestCase):
        def setUp(self):
            self.clocks = []

        def tearDown(self):
            for clock in self.clocks:
                clock.shutdown()

        def fixture(self, count=1, *, retention=1000):
            reactor = task.Clock()
            reactor.advance(1000)
            clock = Clock(reactor, "unit.invalid")
            self.clocks.append(clock)
            rows, events = [], {}
            for number in range(count):
                r, e = "$redaction%d:unit.invalid" % number, "$original%d:unit.invalid" % number
                rows.append((r, e))
                events[r], events[e] = event(r, redaction=True, target=e), event(e)
            pool = FakePool(rows)
            hs = SimpleNamespace(
                config=SimpleNamespace(
                    server=SimpleNamespace(redaction_retention_period=retention),
                    worker=SimpleNamespace(run_background_tasks=True),
                ), get_clock=lambda: clock,
            )
            # Installed decorator delegates through this HS boundary to the REAL
            # runner, including native background exception consumption.
            hs.run_as_background_process = lambda desc, func, *args, **kwargs: (
                run_as_background_process(
                    desc, "unit.invalid", func, *args, bg_start_span=False, **kwargs
                )
            )
            store = object.__new__(native.CensorEventsStore)
            store.hs, store.clock, store.db_pool = hs, clock, pool
            lookups = []

            async def get_event(identifier, **kwargs):
                lookups.append((identifier, kwargs))
                return events.get(identifier)

            store.get_event = get_event
            return SimpleNamespace(
                store=store, pool=pool, events=events, rows=rows,
                clock=clock, reactor=reactor, lookups=lookups, hs=hs,
            )

        def invoke(self, f):
            completed, failed = [], []
            d = f.store._censor_redactions()
            self.assertIsInstance(d, defer.Deferred)
            d.addCallbacks(lambda value: completed.append(True), lambda failure: failed.append(True))
            self.assertEqual(failed, [])
            self.assertEqual(completed, [True])

        def schedule(self, f):
            # Installed candidate constructor, not a copied scheduler expression.
            # Only DB-heavy superclass initialization is suppressed.
            with patch.object(native.EventsWorkerStore, "__init__", return_value=None):
                native.CensorEventsStore.__init__(f.store, f.pool, None, f.hs)

        def assert_pruned(self, f, count):
            self.assertEqual(len(f.pool.json_writes), count)
            for raw in f.pool.json_writes.values():
                parsed = json.loads(raw)
                self.assertEqual(parsed["content"], {})
                self.assertEqual(parsed["type"], "m.room.encrypted")

        def test_01_installed_source_gate(self):
            source = Path(native.__file__).read_text(encoding="utf-8")
            self.assertEqual(source.count(NEW), 1)
            self.assertNotIn(OLD, source)
            self.assertEqual(hashlib.sha256(source.replace(NEW, OLD).encode()).hexdigest(), PINNED_SHA256)

        def test_02_retention_disabled(self):
            f = self.fixture(retention=None)
            self.invoke(f)
            self.assertEqual(f.pool.updates.checks, 0)
            self.assertEqual(f.pool.selects, [])
            self.assertEqual(f.lookups, [])
            self.assertEqual(f.pool.transactions, 0)
            self.assertEqual(f.pool.marked, set())

        def test_03_index_transition(self):
            f = self.fixture()
            f.pool.updates.ready = False
            self.invoke(f)
            self.assertEqual(f.pool.updates.checks, 1)
            self.assertEqual(f.pool.selects, [])
            self.assertEqual(f.lookups, [])
            self.assertEqual(f.pool.transactions, 0)
            self.assertEqual(f.pool.json_writes, {})
            self.assertEqual(f.pool.marked, set())
            f.pool.updates.ready = True
            self.invoke(f)
            self.assertEqual(f.pool.updates.checks, 2)
            self.assertEqual(f.pool.selects, [(999000, 100)])
            self.assertEqual(len(f.pool.marked), 1)
            self.assert_pruned(f, 1)

        def test_04_batch_100(self):
            f = self.fixture(100)
            self.invoke(f)
            self.assertEqual(f.pool.selected_counts, [100])
            self.assertEqual(f.pool.selects, [(999000, 100)])
            self.assertEqual(len(f.pool.marked), 100)
            self.assertEqual(f.pool.commits, 1)
            self.assert_pruned(f, 100)
            for number, (r, e) in enumerate(f.rows):
                self.assertEqual(f.lookups[2 * number], (r, {"allow_none": True}))
                self.assertEqual(f.lookups[2 * number + 1], (
                    e, {"allow_rejected": True, "allow_none": True}
                ))

        def test_05_batch_101(self):
            f = self.fixture(101)
            self.invoke(f)
            self.assertEqual(f.pool.selected_counts, [100])
            self.assertEqual(len(f.pool.marked), 100)
            self.assertNotIn(f.rows[-1][0], f.pool.marked)
            self.assert_pruned(f, 100)
            self.invoke(f)
            self.assertEqual(f.pool.selected_counts, [100, 1])
            self.assertEqual(f.pool.selects, [(999000, 100), (999000, 100)])
            self.assertEqual(len(f.pool.marked), 101)
            self.assertEqual(f.pool.commits, 2)
            self.assert_pruned(f, 101)

        def test_06_invalid_redactions(self):
            f = self.fixture(3)
            f.events[f.rows[0][1]] = event(f.rows[0][1], redacted=False)
            f.events.pop(f.rows[1][0])
            f.events.pop(f.rows[2][1])
            self.invoke(f)
            self.assertEqual(f.pool.json_writes, {})
            self.assertEqual(len(f.pool.marked), 3)
            self.assertEqual(f.pool.attempts, [[("redactions", r) for r, _ in f.rows]])
            self.invoke(f)
            self.assertEqual(f.pool.selected_counts, [3, 0])
            self.assertEqual(f.pool.json_writes, {})

        def test_07_transaction_order_failure_retry(self):
            f = self.fixture(2)
            f.pool.fail_marker_once = True
            self.invoke(f)  # REAL background wrapper consumes the DB exception.
            self.assertEqual(f.pool.transactions, 1)
            self.assertEqual(f.pool.commits, 0)
            self.assertEqual(f.pool.json_writes, {})
            self.assertEqual(f.pool.marked, set())
            r, e = f.rows[0]
            self.assertEqual(f.pool.attempts[0], [("event_json", e), ("redactions", r)])
            self.invoke(f)
            self.assertEqual(f.pool.selected_counts, [2, 2])
            self.assertEqual(f.pool.commits, 1)
            self.assertEqual(len(f.pool.marked), 2)
            self.assert_pruned(f, 2)
            expected = []
            for r, e in f.rows:
                expected.extend([("event_json", e), ("redactions", r)])
            self.assertEqual(f.pool.attempts[1], expected)

        def test_08_immediate_and_30_second_ticks(self):
            f = self.fixture()
            self.schedule(f)
            self.assertEqual(f.pool.selected_counts, [1])
            self.assert_pruned(f, 1)
            f.reactor.advance(29)
            self.assertEqual(len(f.pool.selects), 1)
            f.reactor.advance(1)
            self.assertEqual(f.pool.selected_counts, [1, 0])
            self.assertEqual(f.pool.selects[-1], (1029000, 100))
            f.reactor.advance(30)
            self.assertEqual(f.pool.selected_counts, [1, 0, 0])

        def test_09_async_nonoverlap_error_retry(self):
            f = self.fixture()
            gate = defer.Deferred()
            f.pool.gate = gate
            self.schedule(f)
            self.assertEqual(f.pool.active, 1)
            self.assertEqual(len(f.pool.selects), 1)
            f.reactor.advance(90)
            self.assertEqual(len(f.pool.selects), 1)
            self.assertEqual(f.pool.transactions, 0)
            gate.errback(RuntimeError("synthetic_failure"))
            self.assertEqual(f.pool.active, 0)
            self.assertEqual(f.pool.json_writes, {})
            self.assertEqual(f.pool.marked, set())
            f.reactor.advance(29)
            self.assertEqual(len(f.pool.selects), 1)
            f.reactor.advance(1)
            self.assertEqual(len(f.pool.selects), 2)
            self.assertEqual(f.pool.max_active, 1)
            self.assertEqual(f.pool.commits, 1)
            self.assert_pruned(f, 1)
            f.reactor.advance(30)
            self.assertEqual(len(f.pool.selects), 3)
            self.assertEqual(f.pool.max_active, 1)

    return unittest.TestSuite(NativeBoundaryTests(name) for name in CASES)


class SanitizedResult(unittest.TestResult):
    """Never invoke unittest's exception/traceback formatting methods."""
    def __init__(self):
        super().__init__()
        self.statuses = {}

    def case_name(self, test):
        name = getattr(test, "_testMethodName", "")
        return name if name in CASES else "case_bootstrap"

    def addSuccess(self, test):
        self.statuses[self.case_name(test)] = "PASS"

    def addFailure(self, test, err):
        self.statuses[self.case_name(test)] = "FAIL"
        self.failures.append((self.case_name(test), "FAIL"))

    def addError(self, test, err):
        self.statuses[self.case_name(test)] = "FAIL"
        self.errors.append((self.case_name(test), "FAIL"))

    def addSkip(self, test, reason):
        self.addError(test, None)  # skipped coverage must fail closed

    def addExpectedFailure(self, test, err):
        self.addError(test, None)

    def addUnexpectedSuccess(self, test):
        self.addError(test, None)

    def addSubTest(self, test, subtest, err):
        if err is not None:
            self.addError(test, None)


def main():
    result, bootstrap_failed = SanitizedResult(), False
    logging.disable(sys.maxsize)
    warnings.simplefilter("ignore")
    with open(os.devnull, "w", encoding="utf-8") as discard:
        with contextlib.redirect_stdout(discard), contextlib.redirect_stderr(discard):
            try:
                build_suite().run(result)
            except BaseException:
                bootstrap_failed = True
    for name in CASES:
        print(name + " " + result.statuses.get(name, "FAIL"))
    if bootstrap_failed:
        print("case_bootstrap FAIL")
    passed = sum(result.statuses.get(name) == "PASS" for name in CASES)
    failed = len(CASES) - passed + int(bootstrap_failed)
    print("cases=%d passed=%d failed=%d" % (len(CASES), passed, failed))
    return int(bootstrap_failed or failed != 0 or result.testsRun != len(CASES))


if __name__ == "__main__":
    raise SystemExit(main())
