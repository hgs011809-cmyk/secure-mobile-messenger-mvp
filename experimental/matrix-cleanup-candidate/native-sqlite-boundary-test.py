#!/usr/bin/env python3
"""HYBRID native SQLite persistence boundary, pinned candidate image only.

Execute with Python -B in the installed v1.162.0 candidate image. /tmp must
be writable (CI tmpfs). No network, server, installation or fallback DB.
DatabasePool(hs, DatabaseConnectionConfig, create_engine(config)) constructs
native make_pool/Twisted adbapi, Sqlite3Engine and BackgroundUpdater. A real
file-backed minimal schema is seeded BEFORE pool construction: :memory:
would make the engine prepare the full Synapse schema on each connection.

Installed decorated censor, execute, runInteraction, simple_update_one_txn
and Rust pruning are unchanged. CensorEventsStore.__init__ is skipped via
object.__new__. get_event returns synthetic native EventBase objects with
redacted metadata. Content is encrypted-shaped, NOT cryptographically
encrypted. NOT SDK/auth/cache/full-native-store, scheduling, rate-limit,
retention-policy, backup or disk-erasure coverage. SQL below only seeds and
asserts fixtures, creates the gate index, and injects an SQLite abort trigger.
No copied selection/transaction algorithm or edits/patches to native DB methods.
No censor scheduler or updater processing loop is started; constructor-owned
upsert safety work remains native and is drained during cleanup.
Real background runner consumes errors; assertions check persisted rollback.
Only fixed labels/statuses/counts escape the library-output discard boundary.
"""

import contextlib
import hashlib
import json
import logging
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
import warnings

OLD = "hs.get_clock().looping_call(self._censor_redactions, Duration(minutes=5))"
NEW = "hs.get_clock().looping_call_now(self._censor_redactions, Duration(seconds=30))"
HASHES = {
    "censor": "6e995c5ddcc078f9ae099af8924ee2a2e40d2f5bf5349d148a1cfc7ad2030f2f",
    "database": "856177ee1cc15591fe69eb24de6b71484bc402e7323b80d8a3feac45d6af6658",
    "background": "0bba7e1fa7ffddd7d2cfaefeea97bd8f5ef204289ac2eff47e84d63537c845d4",
    "config": "c4076d009ac0fcd062a1fa0b5155ca993f27499c656ec12eddd8bccae7001481",
    "sqlite": "a7e6bd376521c89f7f8d760531d95164213859a222b435b061cc5d5b55371fcb",
}
CASES = (
    "case_01_source_gates", "case_02_exactly_100",
    "case_03_101_oldest_100_then_1", "case_04_real_index_gate",
    "case_05_future_received_ts", "case_06_real_rollback_retry",
    "case_07_invalid_not_redacted", "case_08_sources_unchanged",
    "case_09_cleanup",
)
INDEX = "redactions_have_censored_ts_idx"


def require(condition):
    if not condition:  # Does not disappear under python -O.
        raise AssertionError("boundary_failure")


def imports():
    import synapse.storage.databases.main.censor_events as censor
    import synapse.storage.database as database
    import synapse.storage.background_updates as background
    import synapse.config.database as config
    import synapse.storage.engines.sqlite as engine_module
    from synapse.storage.engines import create_engine, Sqlite3Engine
    from synapse.api.room_versions import RoomVersions
    from synapse.events import EventBase, make_event_from_dict
    from synapse.metrics.background_process_metrics import run_as_background_process
    from synapse.util.clock import Clock
    from twisted.enterprise import adbapi
    from twisted.internet import defer, task
    return SimpleNamespace(**locals())


def source_gate(n):
    for key, module in (("censor", n.censor), ("database", n.database),
                        ("background", n.background), ("config", n.config),
                        ("sqlite", n.engine_module)):
        raw = Path(module.__file__).read_bytes()
        if key == "censor":
            require(raw.count(NEW.encode()) == 1)
            require(OLD.encode() not in raw)
            raw = raw.replace(NEW.encode(), OLD.encode())
        require(hashlib.sha256(raw).hexdigest() == HASHES[key])
    require(n.database.DatabasePool.__module__ == n.database.__name__)
    require(n.background.BackgroundUpdater.__module__ == n.background.__name__)
    require(n.Sqlite3Engine.__module__ == n.engine_module.__name__)


def synthetic_event(n, identifier, *, redaction=False, redacted=True, target=None):
    data = {
        "event_id": identifier, "room_id": "!fixture:sql.invalid",
        "sender": "@fixture:sql.invalid",
        "type": "m.room.redaction" if redaction else "m.room.encrypted",
        "content": {} if redaction else {
            "algorithm": "synthetic-only-not-encryption",
            "ciphertext": "synthetic-only-not-cryptographically-encrypted",
        },
        "origin": "sql.invalid", "origin_server_ts": 1, "depth": 1,
        "prev_events": [], "auth_events": [], "hashes": {}, "signatures": {},
    }
    if redaction:
        data["redacts"] = target
    event = n.make_event_from_dict(
        data, n.RoomVersions.V1, {"redacted": redacted and not redaction}
    )
    require(isinstance(event, n.EventBase))
    require(event.internal_metadata.is_redacted() == (redacted and not redaction))
    return event


class Fixture:
    def __init__(self, n, reactor):
        self.n, self.reactor = n, reactor
        self.directory = self.clock = self.pool = None
        self.background = []
        self.events, self.rows, self.lookups, self.raw = {}, [], [], {}
        self.cleaned = False
        self.phase = "fixture_init"

    def initialize(self, count, *, pending=False, future=False):
        self.directory = tempfile.TemporaryDirectory(prefix="native-sqlite-boundary-", dir="/tmp")
        self.filename = str(Path(self.directory.name) / "fixture.sqlite3")
        self.clock = self.n.Clock(self.reactor, "sql.invalid")
        cutoff = self.clock.time_msec()
        # Reverse insertion order and distinct timestamps prove oldest SQL order.
        for number in range(count):
            r, e = "$redaction%d:sql.invalid" % number, "$original%d:sql.invalid" % number
            ts = cutoff - 100000 + number
            if future and number == count - 1:
                ts = cutoff + 86400000
            self.rows.append((r, e, ts))
            self.events[r] = synthetic_event(self.n, r, redaction=True, target=e)
            self.events[e] = synthetic_event(self.n, e)
            self.raw[e] = json.dumps(self.events[e].get_pdu_json())
        with contextlib.closing(sqlite3.connect(self.filename)) as conn:
            with conn:
                conn.executescript("""
                    CREATE TABLE redactions (
                        event_id TEXT PRIMARY KEY, redacts TEXT NOT NULL,
                        received_ts BIGINT NOT NULL, have_censored INTEGER NOT NULL DEFAULT 0
                    );
                    CREATE TABLE events (event_id TEXT PRIMARY KEY);
                    CREATE TABLE event_json (event_id TEXT PRIMARY KEY, json TEXT NOT NULL);
                    CREATE TABLE background_updates (
                        update_name TEXT PRIMARY KEY, progress_json TEXT NOT NULL,
                        depends_on TEXT, ordering INTEGER NOT NULL DEFAULT 0
                    );
                """)
                for r, e, ts in reversed(self.rows):
                    conn.execute("INSERT INTO redactions VALUES (?, ?, ?, 0)", (r, e, ts))
                    conn.executemany("INSERT INTO events VALUES (?)", ((r,), (e,)))
                    conn.execute("INSERT INTO event_json VALUES (?, ?)", (e, self.raw[e]))
                if pending:
                    conn.execute("INSERT INTO background_updates VALUES (?, '{}', NULL, 0)", (INDEX,))
                else:
                    conn.execute("CREATE INDEX redactions_have_censored_ts_idx ON redactions (have_censored, received_ts)")
        self.phase = "native_pool_init"
        self.hs = SimpleNamespace(
            hostname="sql.invalid", get_clock=lambda: self.clock,
            get_reactor=lambda: self.reactor,
            config=SimpleNamespace(
                server=SimpleNamespace(redaction_retention_period=0),
                background_updates=SimpleNamespace(
                    min_batch_size=1, default_batch_size=100,
                    update_duration_ms=100, sleep_duration_ms=1000,
                    sleep_enabled=True,
                ),
            ),
        )

        def runner(desc, func, *args, **kwargs):
            deferred = self.n.run_as_background_process(
                desc, "sql.invalid", func, *args, bg_start_span=False, **kwargs
            )
            self.background.append(deferred)
            return deferred

        self.hs.run_as_background_process = runner
        config = self.n.config.DatabaseConnectionConfig(
            "fixture", {"name": "sqlite3", "args": {"database": self.filename}}
        )
        engine = self.n.create_engine(config.config)
        require(type(engine) is self.n.Sqlite3Engine)
        require(not engine._is_in_memory)
        # Retain the object before genuine ctor execution so partially-created
        # adbapi resources remain visible to finally cleanup on ctor failure.
        self.pool = object.__new__(self.n.database.DatabasePool)
        self.n.database.DatabasePool.__init__(self.pool, self.hs, config, engine)
        require(type(self.pool._db_pool) is self.n.adbapi.ConnectionPool)
        require(type(self.pool.updates) is self.n.background.BackgroundUpdater)
        self.store = object.__new__(self.n.censor.CensorEventsStore)
        self.store.hs, self.store.clock, self.store.db_pool = self.hs, self.clock, self.pool

        async def get_event(identifier, **kwargs):
            self.lookups.append((identifier, kwargs))
            return self.events.get(identifier)

        self.store.get_event = get_event
        self.phase = "native_case"

    def read(self, sql, parameters=()):
        with contextlib.closing(sqlite3.connect(self.filename)) as conn:
            return conn.execute(sql, parameters).fetchall()

    def ddl(self, sql, parameters=()):
        with contextlib.closing(sqlite3.connect(self.filename)) as conn:
            with conn:
                conn.execute(sql, parameters)

    async def invoke(self):
        d = self.store._censor_redactions()
        require(isinstance(d, self.n.defer.Deferred))
        await d  # Actual decorated runner consumes exceptions: never assert propagation.

    def marked(self):
        return {r for (r,) in self.read("SELECT event_id FROM redactions WHERE have_censored = 1")}

    def persisted(self, count):
        require(len(self.marked()) == count)
        rows = self.read("SELECT json FROM event_json")
        require(len(rows) == len(self.rows))
        pruned = [json.loads(raw) for (raw,) in rows if json.loads(raw)["content"] == {}]
        require(len(pruned) == count)
        require(all(event["type"] == "m.room.encrypted" for event in pruned))

    def untouched(self):
        require(self.marked() == set())
        require(dict(self.read("SELECT event_id, json FROM event_json")) == self.raw)

    def lookup_order(self, numbers):
        expected = []
        for number in numbers:
            r, e, _ = self.rows[number]
            expected.extend(((r, {"allow_none": True}),
                             (e, {"allow_rejected": True, "allow_none": True})))
        require(self.lookups == expected)

    async def cleanup(self):
        errors = []
        # Independent cleanup steps: one failure must not skip the remaining ones.
        if self.clock is not None:
            try:
                self.clock.shutdown()
            except BaseException:
                errors.append(True)
        if self.pool is not None:
            try:
                self.pool.stop_background_updates()
                require(not self.pool.updates.enabled)
            except BaseException:
                errors.append(True)
        for d in self.background:
            try:
                await d
            except BaseException:
                errors.append(True)
        # A constructor-owned safety query can schedule a call while draining.
        if self.clock is not None:
            try:
                self.clock.shutdown()
            except BaseException:
                errors.append(True)
        if self.pool is not None:
            try:
                self.pool._db_pool.close()
                require(not self.pool._db_pool.running)
                require(not self.pool._db_pool.connections)
                require(not self.pool.updates._running)
            except BaseException:
                errors.append(True)
        if self.directory is not None:
            directory_name = self.directory.name
            try:
                self.directory.cleanup()
                require(not Path(directory_name).exists())
                require(not any(Path(self.filename + suffix).exists() for suffix in ("", "-wal", "-shm", "-journal")))
            except BaseException:
                errors.append(True)
        self.cleaned = not errors
        require(self.cleaned)


async def run_cases(reactor, n, statuses, diagnostics):
    fixtures = []
    cleanup_ok = True
    try:
        try:
            source_gate(n)
            statuses[CASES[0]] = "PASS"
        except BaseException:
            return  # No persistence coverage against unpinned libraries.

        async def run_fixture(name, count, callback, **kwargs):
            nonlocal cleanup_ok
            f = Fixture(n, reactor)  # Independent actual updater/cache per case.
            fixtures.append(f)
            try:
                f.initialize(count, **kwargs)
                await callback(f)
                statuses[name] = "PASS"
            except BaseException as error:
                statuses[name] = "FAIL"
                allowed = {"AssertionError", "AttributeError", "TypeError", "RuntimeError", "StoreError", "OperationalError", "IntegrityError"}
                kind = type(error).__name__
                diagnostics[name] = (f.phase, kind if kind in allowed else "OTHER")
            finally:
                try:
                    await f.cleanup()
                except BaseException:
                    cleanup_ok = False
                    statuses[name] = "FAIL"

        async def exactly100(f):
            await f.invoke()
            f.persisted(100)
            f.lookup_order(range(100))

        async def batch101(f):
            await f.invoke()
            f.persisted(100)
            require(f.marked() == {r for r, _, _ in f.rows[:100]})
            require(f.read("SELECT json FROM event_json WHERE event_id = ?", (f.rows[100][1],))[0][0] == f.raw[f.rows[100][1]])
            f.lookup_order(range(100))
            await f.invoke()
            f.persisted(101)
            f.lookup_order(range(101))

        async def gate(f):
            require(f.read("SELECT update_name FROM background_updates") == [(INDEX,)])
            require(f.read("SELECT name FROM sqlite_master WHERE type='index' AND name=?", (INDEX,)) == [])
            require(not await f.pool.updates.has_completed_background_update(INDEX))
            await f.invoke()
            require(f.lookups == [])
            f.untouched()
            # The physical index is committed BEFORE pending marker deletion.
            f.ddl("CREATE INDEX redactions_have_censored_ts_idx ON redactions (have_censored, received_ts)")
            require(f.read("SELECT name FROM sqlite_master WHERE type='index' AND name=?", (INDEX,)) == [(INDEX,)])
            require(f.read("PRAGMA index_info(redactions_have_censored_ts_idx)") == [(0, 3, "have_censored"), (1, 2, "received_ts")])
            require(f.read("SELECT update_name FROM background_updates") == [(INDEX,)])
            f.ddl("DELETE FROM background_updates WHERE update_name=?", (INDEX,))
            require(await f.pool.updates.has_completed_background_update(INDEX))
            await f.invoke()
            f.persisted(1)
            f.lookup_order([0])

        async def future(f):
            await f.invoke()
            f.persisted(1)
            require(f.marked() == {f.rows[0][0]})
            require(f.read("SELECT json FROM event_json WHERE event_id=?", (f.rows[1][1],))[0][0] == f.raw[f.rows[1][1]])
            f.lookup_order([0])
            await f.invoke()
            f.persisted(1)
            f.lookup_order([0])

        async def rollback(f):
            # Abort SECOND marker only if its event_json was genuinely pruned
            # in this transaction. Also proves rollback of the first row writes.
            f.ddl("""CREATE TRIGGER fixture_marker_abort
                BEFORE UPDATE OF have_censored ON redactions
                WHEN NEW.have_censored = 1
                AND NEW.event_id = '$redaction1:sql.invalid'
                AND (SELECT json_extract(json, '$.content') FROM event_json
                     WHERE event_id = OLD.redacts) = '{}'
                BEGIN SELECT RAISE(ABORT, 'fixture_abort'); END""")
            await f.invoke()
            f.lookup_order([0, 1])
            f.untouched()  # Independently reopened persisted DB, not error status.
            require(f.read("SELECT name FROM sqlite_master WHERE type='trigger'") == [("fixture_marker_abort",)])
            f.ddl("DROP TRIGGER fixture_marker_abort")
            await f.invoke()
            f.persisted(2)
            f.lookup_order([0, 1, 0, 1])

        async def invalid(f):
            f.events[f.rows[0][1]] = synthetic_event(n, f.rows[0][1], redacted=False)
            del f.events[f.rows[1][0]]
            del f.events[f.rows[2][1]]
            await f.invoke()
            require(len(f.marked()) == 3)
            require(dict(f.read("SELECT event_id, json FROM event_json")) == f.raw)
            f.lookup_order(range(3))
            await f.invoke()
            f.lookup_order(range(3))

        await run_fixture(CASES[1], 100, exactly100)
        await run_fixture(CASES[2], 101, batch101)
        await run_fixture(CASES[3], 1, gate, pending=True)
        await run_fixture(CASES[4], 2, future, future=True)
        await run_fixture(CASES[5], 2, rollback)
        await run_fixture(CASES[6], 3, invalid)
        try:
            source_gate(n)
            statuses[CASES[7]] = "PASS"
        except BaseException:
            statuses[CASES[7]] = "FAIL"
    finally:
        for f in fixtures:
            if not f.cleaned:
                cleanup_ok = False
                try:
                    await f.cleanup()
                except BaseException:
                    pass
        statuses[CASES[8]] = "PASS" if cleanup_ok and fixtures and all(f.cleaned for f in fixtures) else "FAIL"


@contextlib.contextmanager
def discard_library_output():
    logging.disable(sys.maxsize)
    warnings.simplefilter("ignore")
    saved = []
    with open(os.devnull, "w", encoding="utf-8") as discard:
        try:
            sys.stdout.flush()
            sys.stderr.flush()
            for fd in (1, 2):
                saved.append((fd, os.dup(fd)))
                os.dup2(discard.fileno(), fd)
            # FD redirection also captures Rust/C and Twisted shutdown output.
            with contextlib.redirect_stdout(discard), contextlib.redirect_stderr(discard):
                yield
        finally:
            for fd, original in saved:
                os.dup2(original, fd)
                os.close(original)


def main():
    statuses = {}
    diagnostics = {}
    bootstrap_failed = False
    with discard_library_output():
        try:
            n = imports()

            def start(reactor):
                return n.defer.ensureDeferred(run_cases(reactor, n, statuses, diagnostics))

            # Real reactor starts native adbapi threadpool, no simulated reactor.
            try:
                n.task.react(start)
            except SystemExit as exc:
                if exc.code not in (None, 0):
                    bootstrap_failed = True
        except BaseException:
            bootstrap_failed = True
    print("HYBRID_NATIVE_SQLITE_SYNTHETIC_EVENTBASE")
    print("NOT_CRYPTOGRAPHICALLY_ENCRYPTED_NOT_SDK_AUTH_CACHE_FULL_NATIVE_STORE")
    for name in CASES:
        print(name + " " + statuses.get(name, "FAIL"))
        if name in diagnostics:
            phase, kind = diagnostics[name]
            print(name + " fixed_phase=" + phase + " fixed_error_kind=" + kind)
    if bootstrap_failed:
        print("case_bootstrap FAIL")
    passed = sum(statuses.get(name) == "PASS" for name in CASES)
    failed = len(CASES) - passed + int(bootstrap_failed)
    print("cases=%d passed=%d failed=%d" % (len(CASES), passed, failed))
    return int(failed != 0)


if __name__ == "__main__":
    raise SystemExit(main())
