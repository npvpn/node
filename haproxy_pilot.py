"""Durable, serialized commands for the node's single opt-in TCP route."""

import fcntl
import logging
import os
import sqlite3
from contextlib import closing, contextmanager, nullcontext
from pathlib import Path

from haproxy_runtime import (
    Command,
    ConfigCheckError,
    ConfigCheckTimeout,
    Policy,
    Route,
    Runtime,
    StartupPending,
)

logger = logging.getLogger(__name__)


class Conflict(ValueError):
    pass


class Rejected(ValueError):
    pass


class Pilot:
    def __init__(self, policy_path, directory):
        self.policy = Policy.model_validate_json(Path(policy_path).read_bytes())
        self.directory = Path(directory).resolve()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        stat = self.directory.stat()
        if stat.st_uid != os.geteuid() or stat.st_mode & 0o077:
            raise ValueError("HAProxy state directory must be private and owned by the node")
        self.runtime = Runtime(self.directory)
        with self._locked() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS confirmed (id INTEGER PRIMARY KEY CHECK(id=1), route TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS operations (
                    id TEXT PRIMARY KEY, command TEXT NOT NULL, candidate TEXT NOT NULL,
                    require_backend INTEGER NOT NULL, phase TEXT NOT NULL,
                    revision INTEGER NOT NULL, detail TEXT NOT NULL DEFAULT ''
                );
            """)
            initial = Route(
                revision=0,
                target=None,
                enabled=False,
                destination=None,
                listen_address=self.policy.listen_address,
                listen_port=self.policy.listen_port,
            )
            with db:
                db.execute("INSERT OR IGNORE INTO confirmed VALUES (1,?)", (initial.model_dump_json(),))
            previous = self._current(db)
            if (previous.listen_address, previous.listen_port) != (
                initial.listen_address,
                initial.listen_port,
            ):
                raise ValueError("Persisted pilot owns a different listener than the policy")
            self._recover(db)
            self._observe_confirmed(db, self._current(db))

    def _observe_confirmed(self, db, route):
        marker, listener = self.runtime.observe(route)
        # A legacy initial rejection may have left our worker running at revision zero.
        needs_worker = route.revision or (marker is not None and listener == "up")
        expected_listener = "up" if route.enabled else "down"
        if (
            not needs_worker
            or listener in ("unknown", "external")
            or (marker == route.marker and listener == expected_listener)
            or not self._allowed(route)
            or self._pending(db) is not None
        ):
            return marker, listener
        try:
            self.runtime.activate(route)
        except (RuntimeError, OSError) as error:
            logger.error("Cannot restore confirmed HAProxy revision %d: %s", route.revision, error)
        return self.runtime.observe(route)

    @contextmanager
    def _locked(self, admission=nullcontext):
        with (self.directory / "route.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            with admission():
                connection = sqlite3.connect(self.directory / "journal.sqlite3")
            with closing(connection) as db:
                db.row_factory = sqlite3.Row
                db.execute("PRAGMA synchronous=FULL")
                yield db

    @staticmethod
    def _current(db):
        return Route.model_validate_json(db.execute("SELECT route FROM confirmed WHERE id=1").fetchone()[0])

    @staticmethod
    def _pending(db):
        return db.execute(
            "SELECT * FROM operations WHERE phase IN ('prepared','pending','rollback')"
        ).fetchone()

    @staticmethod
    def _row(db, operation_id):
        return db.execute("SELECT * FROM operations WHERE id=?", (str(operation_id),)).fetchone()

    @staticmethod
    def _result(row):
        if row is None:
            return None
        phase = row["phase"]
        return {
            "operation_id": row["id"],
            "outcome": "pending" if phase in ("prepared", "rollback") else phase,
            "revision": row["revision"],
            "detail": row["detail"],
        }

    def _finish(self, db, row, route, outcome, detail):
        with db:
            if outcome == "applied":
                db.execute("UPDATE confirmed SET route=? WHERE id=1", (route.model_dump_json(),))
            db.execute(
                "UPDATE operations SET phase=?,revision=?,detail=? WHERE id=?",
                (outcome, route.revision, detail, row["id"]),
            )
        return self._result(self._row(db, row["id"]))

    def _allowed(self, route):
        return not route.enabled or self.policy.targets.get(route.target) == route.destination

    def _rollback(self, db, row, previous, reason):
        with db:
            db.execute("UPDATE operations SET phase='rollback',detail=? WHERE id=?", (reason, row["id"]))
        try:
            # Always restore the startup file as well as the worker, even if the old worker survived.
            if not self._allowed(previous):
                raise RuntimeError("The previous destination is no longer in the local policy")
            marker, listener = self.runtime.observe(previous)
            if listener == "unknown":
                return self._result(self._row(db, row["id"]))
            if previous.revision or marker is not None:
                self.runtime.activate(previous)
            else:
                # Initial launch failed before creating a worker.
                (self.directory / "active.cfg").unlink(missing_ok=True)
        except (StartupPending, ConfigCheckTimeout):
            # Keep the rollback phase until we can check and restore the old worker.
            return self._result(self._row(db, row["id"]))
        except (OSError, RuntimeError) as error:
            if self.runtime.observe(previous)[1] == "unknown":
                return self._result(self._row(db, row["id"]))
            return self._finish(
                db,
                row,
                previous,
                "rollback_failed",
                f"{reason}; could not restore revision {previous.revision}: {error}",
            )
        if previous.enabled and previous.backend_health() == "down":
            reason += "; previous backend is unreachable"
        return self._finish(db, row, previous, "rejected", reason)

    def _recover(self, db):
        pending = self._pending(db)
        if pending is None:
            return
        previous = self._current(db)
        if pending["phase"] == "prepared":
            self._finish(db, pending, previous, "rejected", "Interrupted before reload")
            return
        candidate = Route.model_validate_json(pending["candidate"])
        if self.runtime.observe(candidate)[1] == "unknown":
            return  # The same ID can be reconciled when the master becomes observable.
        if pending["phase"] == "pending" and self._allowed(candidate):
            if self.runtime.matches(candidate) and (
                not pending["require_backend"] or candidate.backend_health() == "up"
            ):
                self._finish(db, pending, candidate, "applied", "Worker confirmed after recovery")
                return
        self._rollback(
            db, pending, previous, pending["detail"] or "Interrupted application was not confirmed"
        )

    def status(self, admission=nullcontext):
        with self._locked(admission) as db:
            self._recover(db)
            route = self._current(db)
            marker, listener = self._observe_confirmed(db, route)
            if listener == "up" and marker != route.marker:
                listener = "unknown"
            return dict(
                self.policy.model_dump(),
                revision=route.revision,
                target=route.target,
                enabled=route.enabled,
                listener=listener,
                backend=route.backend_health(),
                confirmed_destination=route.destination.model_dump() if route.destination else None,
            )

    def result(self, operation_id, admission=nullcontext):
        with self._locked(admission) as db:
            self._recover(db)
            return self._result(self._row(db, operation_id))

    def _prepare(self, db, command):
        row = self._row(db, command.operation_id)
        if row is not None and row["command"] != command.model_dump_json():
            raise Conflict("Operation ID was already used with different content")
        previous = self._current(db)
        if row is None and command.expected_revision != previous.revision:
            raise Conflict(f"Current revision is {previous.revision}")
        if row is None and self._pending(db) is not None:
            raise Conflict("Another operation is waiting for runtime observation")
        if row:
            return previous, Route.model_validate_json(row["candidate"]), row
        candidate = Route(
            revision=previous.revision + 1,
            enabled=command.enabled,
            target=command.target,
            destination=command.expected_destination,
            listen_address=self.policy.listen_address,
            listen_port=self.policy.listen_port,
        )
        return previous, candidate, row

    def _check_destination(self, previous, candidate):
        if (
            not candidate.enabled
            and previous.enabled
            and candidate.target == previous.target
            and candidate.destination == previous.destination
        ):
            return
        if self.policy.targets.get(candidate.target) != candidate.destination:
            raise Rejected("Requested destination does not match the local policy")

    def _preflight(self, previous, candidate, require_backend):
        marker, listener = self.runtime.observe(previous)
        if listener in ("external", "unknown") or (listener == "up" and marker != previous.marker):
            raise Rejected(f"Pilot listener is {listener} or belongs to a different worker")
        if require_backend and candidate.backend_health() != "up":
            raise Rejected("Proposed backend is unreachable")

    @staticmethod
    def _require_backend(previous, candidate):
        return candidate.enabled and (
            not previous.enabled
            or previous.destination != candidate.destination
            or previous.backend_health() == "up"
        )

    def validate(self, payload, admission=nullcontext):
        command = Command.model_validate(payload)
        with self._locked(admission) as db:
            previous, candidate, row = self._prepare(db, command)
            if row is None:
                self._check_destination(previous, candidate)
                try:
                    self._preflight(previous, candidate, self._require_backend(previous, candidate))
                    self.runtime.validate(candidate)
                except (RuntimeError, OSError) as error:
                    raise Rejected(str(error)) from error
            return {"valid": True, "revision": previous.revision}

    def apply(self, payload, admission=nullcontext):
        command = Command.model_validate(payload)
        with self._locked(admission) as db:
            self._recover(db)
            # Ownership can change during reconciliation. Reserve the command under the
            # same short lock as REST connect/disconnect; HAProxy I/O follows the commit.
            with admission():
                previous, candidate, row = self._prepare(db, command)
                if row is not None:
                    return self._result(row)
                with db:
                    db.execute(
                        "INSERT INTO operations (id,command,candidate,require_backend,phase,revision) "
                        "VALUES (?,?,?,?,?,?)",
                        (
                            str(command.operation_id),
                            command.model_dump_json(),
                            candidate.model_dump_json(),
                            False,
                            "prepared",
                            previous.revision,
                        ),
                    )
            row = self._row(db, command.operation_id)
            try:
                self._check_destination(previous, candidate)
                require_backend = self._require_backend(previous, candidate)
                self._preflight(previous, candidate, require_backend)
            except (Rejected, RuntimeError, OSError) as error:
                return self._finish(db, row, previous, "rejected", str(error))
            with db:
                db.execute(
                    "UPDATE operations SET phase='pending',require_backend=? WHERE id=?",
                    (require_backend, row["id"]),
                )
            try:
                self.runtime.activate(candidate)
                if require_backend and candidate.backend_health() != "up":
                    raise RuntimeError("Backend became unreachable after reload")
            except ConfigCheckError as error:
                # Syntax checks finish before replacing the file or contacting the master.
                return self._finish(db, row, previous, "rejected", str(error))
            except StartupPending:
                return self._result(self._row(db, row["id"]))
            except (RuntimeError, OSError) as error:
                if self.runtime.observe(candidate)[1] == "unknown":
                    return self._result(row)
                return self._rollback(db, row, previous, str(error))
            return self._finish(db, row, candidate, "applied", "Worker and listener confirmed")
