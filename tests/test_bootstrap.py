from __future__ import annotations

from incident_response_agent.cli import initialize_database
from incident_response_agent.storage import SQLiteStore


def test_database_initializer_creates_current_schema_and_is_repeatable(tmp_path):
    path = tmp_path / "nested" / "incident.sqlite3"

    first = initialize_database(str(path))
    second = initialize_database(str(path))

    assert first == second == {"database_path": str(path), "schema_version": 2, "status": "ready"}
    store = SQLiteStore(str(path))
    try:
        tables = {
            row[0]
            for row in store.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    finally:
        store.close()
    assert {"runs", "proposals", "audit"} <= tables
