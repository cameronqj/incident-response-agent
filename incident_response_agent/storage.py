from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from .security import safe_metadata


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class StoreConflict(Exception):
    pass


class StoreNotFound(Exception):
    pass


class IdempotencyConflict(StoreConflict):
    pass


class SQLiteStore:
    def __init__(self, database_path: str):
        self.database_path = database_path
        if database_path != ":memory:":
            Path(database_path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(database_path, check_same_thread=False, isolation_level=None, timeout=5.0)
        self.connection.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA busy_timeout = 5000")
        if database_path != ":memory:":
            self.connection.execute("PRAGMA journal_mode = WAL")
        self._initialize_schema()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self.lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                yield self.connection
            except Exception:
                self.connection.rollback()
                raise
            else:
                self.connection.commit()

    def _initialize_schema(self) -> None:
        with self._transaction() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    payload_hash TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    trace_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS proposals (
                    proposal_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL REFERENCES runs(run_id),
                    revision INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    scenario TEXT NOT NULL DEFAULT 'disk-exhaustion',
                    scenario_kind TEXT NOT NULL DEFAULT 'synthetic_marker',
                    assessment_json TEXT NOT NULL,
                    option_json TEXT NOT NULL,
                    action_hash TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    approved_action_hash TEXT,
                    UNIQUE(run_id, revision)
                );
                CREATE TABLE IF NOT EXISTS audit (
                    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    trace_id TEXT NOT NULL,
                    run_id TEXT NOT NULL REFERENCES runs(run_id),
                    proposal_id TEXT,
                    event_type TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    occurred_at TEXT NOT NULL
                );
                """
            )
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(proposals)").fetchall()}
            if "scenario" not in columns:
                connection.execute("ALTER TABLE proposals ADD COLUMN scenario TEXT NOT NULL DEFAULT 'disk-exhaustion'")
            if "scenario_kind" not in columns:
                connection.execute("ALTER TABLE proposals ADD COLUMN scenario_kind TEXT NOT NULL DEFAULT 'synthetic_marker'")
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version < 2:
                self._migrate_legacy_records(connection)
                connection.execute("PRAGMA user_version = 2")

    def _migrate_legacy_records(self, connection: sqlite3.Connection) -> None:
        scenario_aliases = {
            "failed-log-rotation-disk-exhaustion": "disk-exhaustion",
            "disk": "disk-exhaustion",
            "oom": "memory-oom",
        }
        runs = connection.execute("SELECT * FROM runs").fetchall()
        for run in runs:
            try:
                legacy = json.loads(run["event_json"])
            except (TypeError, json.JSONDecodeError):
                legacy = {}
            payload = legacy.get("payload") if isinstance(legacy, dict) else {}
            payload = payload if isinstance(payload, dict) else {}
            scenario = scenario_aliases.get(str(payload.get("scenario", "disk-exhaustion")), str(payload.get("scenario", "disk-exhaustion")))
            if scenario not in {"disk-exhaustion", "runaway-cpu", "memory-oom", "restarting-service", "log-storm"}:
                scenario = "disk-exhaustion"
            normalized = {
                "idempotency_key": run["idempotency_key"],
                "source": "local_simulation",
                "observed_at": run["created_at"],
                "event_type": "incident.detected",
                "payload": {
                    "scenario": scenario,
                    "summary": "legacy event content removed during security migration",
                    "log_lines": [],
                    "context": [],
                },
                "trace_id": run["trace_id"],
            }
            canonical = {key: normalized[key] for key in ("source", "observed_at", "event_type", "payload")}
            payload_hash = hashlib.sha256(_json(canonical).encode("utf-8")).hexdigest()
            connection.execute(
                "UPDATE runs SET event_json = ?, payload_hash = ? WHERE run_id = ?",
                (_json(normalized), payload_hash, run["run_id"]),
            )

        audit_rows = connection.execute("SELECT audit_id, metadata_json FROM audit").fetchall()
        for audit_row in audit_rows:
            try:
                metadata = json.loads(audit_row["metadata_json"])
            except (TypeError, json.JSONDecodeError):
                metadata = {"migration_note": "invalid legacy audit metadata removed"}
            connection.execute(
                "UPDATE audit SET metadata_json = ? WHERE audit_id = ?",
                (_json(safe_metadata(metadata if isinstance(metadata, dict) else {"migration_note": "non-object legacy audit metadata removed"})), audit_row["audit_id"]),
            )

        legacy_active = connection.execute(
            "SELECT p.proposal_id, p.run_id, p.revision, r.trace_id FROM proposals p JOIN runs r ON r.run_id = p.run_id WHERE p.status IN ('proposed', 'approved', 'executing')"
        ).fetchall()
        for proposal in legacy_active:
            connection.execute("UPDATE proposals SET status = 'expired' WHERE proposal_id = ?", (proposal["proposal_id"],))
            connection.execute("UPDATE runs SET state = 'expired' WHERE run_id = ?", (proposal["run_id"],))
            self._insert_audit(
                connection,
                {
                    "trace_id": proposal["trace_id"],
                    "run_id": proposal["run_id"],
                    "proposal_id": proposal["proposal_id"],
                    "event_type": "proposal_expired",
                    "metadata": {"revision": proposal["revision"], "reason": "security_schema_migration", "actor": "system-migration"},
                    "occurred_at": connection.execute("SELECT updated_at FROM runs WHERE run_id = ?", (proposal["run_id"],)).fetchone()[0],
                },
            )

    @staticmethod
    def _one(connection: sqlite3.Connection, query: str, args: tuple = ()) -> Optional[Dict[str, Any]]:
        row = connection.execute(query, args).fetchone()
        return dict(row) if row else None

    @staticmethod
    def _insert_audit(connection: sqlite3.Connection, row: Dict[str, Any]) -> None:
        connection.execute(
            "INSERT INTO audit(trace_id, run_id, proposal_id, event_type, metadata_json, occurred_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                row["trace_id"],
                row["run_id"],
                row.get("proposal_id"),
                row["event_type"],
                _json(safe_metadata(row["metadata"])),
                row["occurred_at"],
            ),
        )

    def create_or_get_run(self, row: Dict[str, Any], audit: Dict[str, Any]) -> tuple[Dict[str, Any], bool]:
        with self._transaction() as connection:
            try:
                connection.execute(
                    "INSERT INTO runs(run_id, idempotency_key, payload_hash, event_json, trace_id, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        row["run_id"],
                        row["idempotency_key"],
                        row["payload_hash"],
                        _json(row["event"]),
                        row["trace_id"],
                        row["state"],
                        row["created_at"],
                        row["updated_at"],
                    ),
                )
            except sqlite3.IntegrityError:
                existing = self._one(connection, "SELECT * FROM runs WHERE idempotency_key = ?", (row["idempotency_key"],))
                if existing is None:
                    raise
                if existing["payload_hash"] != row["payload_hash"]:
                    raise IdempotencyConflict("idempotency key belongs to a different normalized event")
                return existing, False
            self._insert_audit(connection, audit)
            return row, True

    def transition_run(self, run_id: str, expected: str, new_state: str, now: str, trace_id: str, reason: str, actor: str, proposal_id: str | None = None) -> None:
        with self._transaction() as connection:
            updated = connection.execute(
                "UPDATE runs SET state = ?, updated_at = ? WHERE run_id = ? AND state = ?",
                (new_state, now, run_id, expected),
            ).rowcount
            if updated != 1:
                raise StoreConflict(f"run is not in expected state {expected}")
            self._insert_audit(
                connection,
                {
                    "trace_id": trace_id,
                    "run_id": run_id,
                    "proposal_id": proposal_id,
                    "event_type": "state_transition",
                    "metadata": {"from": expected, "to": new_state, "reason": reason, "actor": actor},
                    "occurred_at": now,
                },
            )

    def create_proposal_and_transition(self, row: Dict[str, Any], now: str, trace_id: str, actor: str, event_to_proposal_ms: int) -> None:
        with self._transaction() as connection:
            connection.execute(
                "INSERT INTO proposals(proposal_id, run_id, revision, status, scenario, scenario_kind, assessment_json, option_json, action_hash, expires_at, created_at, approved_action_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                (
                    row["proposal_id"],
                    row["run_id"],
                    row["revision"],
                    row["status"],
                    row["scenario"],
                    row["scenario_kind"],
                    _json(row["assessment"]),
                    _json(row["option"]),
                    row["action_hash"],
                    row["expires_at"],
                    row["created_at"],
                ),
            )
            updated = connection.execute(
                "UPDATE runs SET state = 'proposed', updated_at = ? WHERE run_id = ? AND state = 'assessed'",
                (now, row["run_id"]),
            ).rowcount
            if updated != 1:
                raise StoreConflict("run is not assessed")
            self._insert_audit(connection, {"trace_id": trace_id, "run_id": row["run_id"], "proposal_id": row["proposal_id"], "event_type": "state_transition", "metadata": {"from": "assessed", "to": "proposed", "reason": "remediation proposal created", "actor": actor}, "occurred_at": now})
            self._insert_audit(connection, {"trace_id": trace_id, "run_id": row["run_id"], "proposal_id": row["proposal_id"], "event_type": "proposal_created", "metadata": {"revision": row["revision"], "scenario": row["scenario"], "scenario_kind": row["scenario_kind"], "action_id": row["option"]["action_id"], "action_hash": row["action_hash"], "expires_at": row["expires_at"], "event_to_proposal_latency_ms": event_to_proposal_ms, "actor": actor}, "occurred_at": now})

    def decide_proposal(self, proposal_id: str, revision: int, digest: str, decision: str, now: str, actor: str, approval_wait_seconds: float, new_proposal: Dict[str, Any] | None = None) -> tuple[str, str]:
        with self._transaction() as connection:
            proposal = self._one(connection, "SELECT * FROM proposals WHERE proposal_id = ?", (proposal_id,))
            if proposal is None:
                raise StoreNotFound("proposal not found")
            run = self._one(connection, "SELECT * FROM runs WHERE run_id = ?", (proposal["run_id"],))
            assert run is not None
            if proposal["revision"] != revision or proposal["action_hash"] != digest:
                raise StoreConflict("decision does not bind to the current revision and action hash")
            if proposal["status"] != "proposed" or run["state"] != "proposed":
                raise StoreConflict(f"proposal is {proposal['status']}, not proposed")
            if now >= proposal["expires_at"]:
                self._expire_locked(connection, proposal, run, now, actor, "approval_ttl_elapsed")
                return proposal["run_id"], "expired"

            if decision == "revise":
                if new_proposal is None:
                    raise ValueError("revision requires a replacement proposal")
                updated = connection.execute("UPDATE proposals SET status = 'superseded' WHERE proposal_id = ? AND status = 'proposed'", (proposal_id,)).rowcount
                if updated != 1:
                    raise StoreConflict("proposal revision lost a concurrent decision")
                connection.execute(
                    "INSERT INTO proposals(proposal_id, run_id, revision, status, scenario, scenario_kind, assessment_json, option_json, action_hash, expires_at, created_at, approved_action_hash) VALUES (?, ?, ?, 'proposed', ?, ?, ?, ?, ?, ?, ?, NULL)",
                    (new_proposal["proposal_id"], proposal["run_id"], new_proposal["revision"], new_proposal["scenario"], new_proposal["scenario_kind"], _json(new_proposal["assessment"]), _json(new_proposal["option"]), new_proposal["action_hash"], new_proposal["expires_at"], new_proposal["created_at"]),
                )
                connection.execute("UPDATE runs SET updated_at = ? WHERE run_id = ? AND state = 'proposed'", (now, proposal["run_id"]))
                self._insert_audit(connection, {"trace_id": run["trace_id"], "run_id": proposal["run_id"], "proposal_id": new_proposal["proposal_id"], "event_type": "proposal_revised", "metadata": {"from_revision": revision, "to_revision": new_proposal["revision"], "action_hash": new_proposal["action_hash"], "actor": actor}, "occurred_at": now})
                return proposal["run_id"], "revised"

            proposal_state = "approved" if decision == "approve" else "rejected"
            approved_hash = digest if decision == "approve" else None
            updated = connection.execute(
                "UPDATE proposals SET status = ?, approved_action_hash = ? WHERE proposal_id = ? AND status = 'proposed'",
                (proposal_state, approved_hash, proposal_id),
            ).rowcount
            if updated != 1:
                raise StoreConflict("proposal decision lost a concurrent update")
            run_updated = connection.execute(
                "UPDATE runs SET state = ?, updated_at = ? WHERE run_id = ? AND state = 'proposed'",
                (proposal_state, now, proposal["run_id"]),
            ).rowcount
            if run_updated != 1:
                raise StoreConflict("run decision lost a concurrent update")
            self._insert_audit(connection, {"trace_id": run["trace_id"], "run_id": proposal["run_id"], "proposal_id": proposal_id, "event_type": "state_transition", "metadata": {"from": "proposed", "to": proposal_state, "reason": f"human decision: {decision}", "actor": actor}, "occurred_at": now})
            self._insert_audit(connection, {"trace_id": run["trace_id"], "run_id": proposal["run_id"], "proposal_id": proposal_id, "event_type": "approval_decision", "metadata": {"decision": decision, "revision": revision, "action_hash": digest, "approval_wait_seconds": approval_wait_seconds, "actor": actor}, "occurred_at": now})
            return proposal["run_id"], proposal_state

    def claim_execution(self, proposal_id: str, expected_digest: str, now: str, actor: str) -> tuple[str, Optional[Dict[str, Any]]]:
        with self._transaction() as connection:
            proposal = self._one(connection, "SELECT * FROM proposals WHERE proposal_id = ?", (proposal_id,))
            if proposal is None:
                raise StoreNotFound("proposal not found")
            run = self._one(connection, "SELECT * FROM runs WHERE run_id = ?", (proposal["run_id"],))
            assert run is not None
            if proposal["status"] != "approved" or run["state"] != "approved":
                raise StoreConflict("only an approved proposal can enter execution")
            if proposal["action_hash"] != expected_digest or proposal["approved_action_hash"] != expected_digest:
                raise StoreConflict("approved action hash does not match the proposal")
            if now >= proposal["expires_at"]:
                self._expire_locked(connection, proposal, run, now, actor, "expired_before_execution")
                return "expired", None
            proposal_updated = connection.execute("UPDATE proposals SET status = 'executing' WHERE proposal_id = ? AND status = 'approved'", (proposal_id,)).rowcount
            run_updated = connection.execute("UPDATE runs SET state = 'executing', updated_at = ? WHERE run_id = ? AND state = 'approved'", (now, proposal["run_id"])).rowcount
            if proposal_updated != 1 or run_updated != 1:
                raise StoreConflict("proposal execution claim lost a concurrent update")
            self._insert_audit(connection, {"trace_id": run["trace_id"], "run_id": proposal["run_id"], "proposal_id": proposal_id, "event_type": "state_transition", "metadata": {"from": "approved", "to": "executing", "reason": "execution atomically claimed", "actor": actor}, "occurred_at": now})
            return "claimed", self._decode_proposal(proposal)

    def finalize_execution(self, proposal_id: str, success: bool, now: str, actor: str, result_metadata: Dict[str, Any]) -> str:
        final_state = "succeeded" if success else "failed"
        with self._transaction() as connection:
            proposal = self._one(connection, "SELECT * FROM proposals WHERE proposal_id = ?", (proposal_id,))
            if proposal is None:
                raise StoreNotFound("proposal not found")
            run = self._one(connection, "SELECT * FROM runs WHERE run_id = ?", (proposal["run_id"],))
            assert run is not None
            proposal_updated = connection.execute("UPDATE proposals SET status = ? WHERE proposal_id = ? AND status = 'executing'", (final_state, proposal_id)).rowcount
            run_updated = connection.execute("UPDATE runs SET state = ?, updated_at = ? WHERE run_id = ? AND state = 'executing'", (final_state, now, proposal["run_id"])).rowcount
            if proposal_updated != 1 or run_updated != 1:
                raise StoreConflict("execution finalization lost its claim")
            self._insert_audit(connection, {"trace_id": run["trace_id"], "run_id": proposal["run_id"], "proposal_id": proposal_id, "event_type": "state_transition", "metadata": {"from": "executing", "to": final_state, "reason": "remediation completed" if success else "remediation failed", "actor": actor}, "occurred_at": now})
            metadata = dict(result_metadata)
            metadata["actor"] = actor
            self._insert_audit(connection, {"trace_id": run["trace_id"], "run_id": proposal["run_id"], "proposal_id": proposal_id, "event_type": "execution_result", "metadata": metadata, "occurred_at": now})
            return proposal["run_id"]

    def _expire_locked(self, connection: sqlite3.Connection, proposal: Dict[str, Any], run: Dict[str, Any], now: str, actor: str, reason: str) -> None:
        if proposal["status"] not in {"proposed", "approved"}:
            raise StoreConflict("proposal cannot expire from its current state")
        proposal_updated = connection.execute(
            "UPDATE proposals SET status = 'expired' WHERE proposal_id = ? AND status = ?",
            (proposal["proposal_id"], proposal["status"]),
        ).rowcount
        run_updated = connection.execute(
            "UPDATE runs SET state = 'expired', updated_at = ? WHERE run_id = ? AND state = ?",
            (now, run["run_id"], run["state"]),
        ).rowcount
        if proposal_updated != 1 or run_updated != 1:
            raise StoreConflict("proposal expiration lost a concurrent update")
        self._insert_audit(connection, {"trace_id": run["trace_id"], "run_id": run["run_id"], "proposal_id": proposal["proposal_id"], "event_type": "state_transition", "metadata": {"from": run["state"], "to": "expired", "reason": reason, "actor": actor}, "occurred_at": now})
        self._insert_audit(connection, {"trace_id": run["trace_id"], "run_id": run["run_id"], "proposal_id": proposal["proposal_id"], "event_type": "proposal_expired", "metadata": {"revision": proposal["revision"], "reason": reason, "retained": True, "actor": actor}, "occurred_at": now})

    def expire_due(self, now: str, actor: str) -> int:
        with self._transaction() as connection:
            proposals = connection.execute(
                "SELECT * FROM proposals WHERE status IN ('proposed', 'approved') AND expires_at <= ? ORDER BY created_at",
                (now,),
            ).fetchall()
            count = 0
            for row in proposals:
                proposal = dict(row)
                run = self._one(connection, "SELECT * FROM runs WHERE run_id = ?", (proposal["run_id"],))
                if run is None or run["state"] not in {"proposed", "approved"}:
                    continue
                self._expire_locked(connection, proposal, run, now, actor, "ttl_elapsed")
                count += 1
            return count

    def fail_run(self, run_id: str, now: str, actor: str, reason_code: str) -> None:
        with self._transaction() as connection:
            run = self._one(connection, "SELECT * FROM runs WHERE run_id = ?", (run_id,))
            if run is None or run["state"] in {"succeeded", "failed", "rejected", "expired"}:
                return
            connection.execute("UPDATE runs SET state = 'failed', updated_at = ? WHERE run_id = ? AND state = ?", (now, run_id, run["state"]))
            self._insert_audit(connection, {"trace_id": run["trace_id"], "run_id": run_id, "event_type": "state_transition", "metadata": {"from": run["state"], "to": "failed", "reason": "workflow exception", "actor": actor}, "occurred_at": now})
            self._insert_audit(connection, {"trace_id": run["trace_id"], "run_id": run_id, "event_type": "run_failed", "metadata": {"failure_reason_code": reason_code, "actor": actor}, "occurred_at": now})

    def create_audit(self, row: Dict[str, Any]) -> None:
        with self._transaction() as connection:
            self._insert_audit(connection, row)

    def find_by_idempotency(self, key: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            return self._one(self.connection, "SELECT * FROM runs WHERE idempotency_key = ?", (key,))

    def get_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            return self._one(self.connection, "SELECT * FROM runs WHERE run_id = ?", (run_id,))

    def get_proposal(self, proposal_id: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            return self._decode_proposal(self._one(self.connection, "SELECT * FROM proposals WHERE proposal_id = ?", (proposal_id,)))

    def latest_proposal(self, run_id: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            return self._decode_proposal(self._one(self.connection, "SELECT * FROM proposals WHERE run_id = ? ORDER BY revision DESC LIMIT 1", (run_id,)))

    @staticmethod
    def _decode_proposal(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not row:
            return None
        decoded = dict(row)
        decoded["assessment"] = json.loads(decoded.pop("assessment_json"))
        decoded["option"] = json.loads(decoded.pop("option_json"))
        return decoded

    def list_audit(self, run_id: str) -> List[Dict[str, Any]]:
        with self.lock:
            rows = self.connection.execute("SELECT * FROM audit WHERE run_id = ? ORDER BY audit_id", (run_id,)).fetchall()
            result = []
            for row in rows:
                item = dict(row)
                item["metadata"] = json.loads(item.pop("metadata_json"))
                result.append(item)
            return result

    def close(self) -> None:
        with self.lock:
            self.connection.close()
