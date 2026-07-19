from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class SQLiteStore:
    def __init__(self, database_path: str):
        if database_path != ":memory:":
            Path(database_path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(database_path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.executescript(
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
        self.connection.commit()

    def _one(self, query: str, args: tuple = ()) -> Optional[Dict[str, Any]]:
        row = self.connection.execute(query, args).fetchone()
        return dict(row) if row else None

    def find_by_idempotency(self, key: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            return self._one("SELECT * FROM runs WHERE idempotency_key = ?", (key,))

    def create_run(self, row: Dict[str, Any]) -> None:
        with self.lock:
            self.connection.execute(
                "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (row["run_id"], row["idempotency_key"], row["payload_hash"], _json(row["event"]), row["trace_id"], row["state"], row["created_at"], row["updated_at"]),
            )
            self.connection.commit()

    def update_run_state(self, run_id: str, state: str, updated_at: str) -> None:
        with self.lock:
            self.connection.execute("UPDATE runs SET state = ?, updated_at = ? WHERE run_id = ?", (state, updated_at, run_id))
            self.connection.commit()

    def get_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            return self._one("SELECT * FROM runs WHERE run_id = ?", (run_id,))

    def create_proposal(self, row: Dict[str, Any]) -> None:
        with self.lock:
            self.connection.execute(
                "INSERT INTO proposals VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (row["proposal_id"], row["run_id"], row["revision"], row["status"], _json(row["assessment"]), _json(row["option"]), row["action_hash"], row["expires_at"], row["created_at"], None),
            )
            self.connection.commit()

    def get_proposal(self, proposal_id: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            row = self._one("SELECT * FROM proposals WHERE proposal_id = ?", (proposal_id,))
            return self._decode_proposal(row)

    def latest_proposal(self, run_id: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            row = self._one("SELECT * FROM proposals WHERE run_id = ? ORDER BY revision DESC LIMIT 1", (run_id,))
            return self._decode_proposal(row)

    def active_proposals(self) -> List[Dict[str, Any]]:
        with self.lock:
            rows = self.connection.execute("SELECT * FROM proposals WHERE status = 'proposed'").fetchall()
            return [self._decode_proposal(dict(row)) for row in rows]

    @staticmethod
    def _decode_proposal(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not row:
            return None
        row["assessment"] = json.loads(row.pop("assessment_json"))
        row["option"] = json.loads(row.pop("option_json"))
        return row

    def update_proposal(self, proposal_id: str, status: str, approved_action_hash: Optional[str] = None) -> None:
        with self.lock:
            self.connection.execute(
                "UPDATE proposals SET status = ?, approved_action_hash = COALESCE(?, approved_action_hash) WHERE proposal_id = ?",
                (status, approved_action_hash, proposal_id),
            )
            self.connection.commit()

    def create_audit(self, row: Dict[str, Any]) -> None:
        with self.lock:
            self.connection.execute(
                "INSERT INTO audit(trace_id, run_id, proposal_id, event_type, metadata_json, occurred_at) VALUES (?, ?, ?, ?, ?, ?)",
                (row["trace_id"], row["run_id"], row.get("proposal_id"), row["event_type"], _json(row["metadata"]), row["occurred_at"]),
            )
            self.connection.commit()

    def list_audit(self, run_id: str) -> List[Dict[str, Any]]:
        with self.lock:
            rows = self.connection.execute("SELECT * FROM audit WHERE run_id = ? ORDER BY audit_id", (run_id,)).fetchall()
            result = []
            for row in rows:
                item = dict(row)
                item["metadata"] = json.loads(item.pop("metadata_json"))
                result.append(item)
            return result
