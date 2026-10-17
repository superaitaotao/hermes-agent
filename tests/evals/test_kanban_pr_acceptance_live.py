"""The acceptance probe executes only against verified source and isolated state."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.platforms("linux")
@pytest.mark.parametrize("mode", ["isolated", "read-only", "runtime-ready"])
def test_probe_refuses_source_drift_before_state_access(tmp_path, mode):
    root = Path(__file__).resolve().parents[2]
    board = tmp_path / "live.db"
    board.write_bytes(b"live-state-sentinel")
    output = tmp_path / "report.json"
    env = {**os.environ, "HERMES_KANBAN_DB": str(board),
           "HERMES_DELEGATED_CHILD_CONTEXT": str(tmp_path), "PYTHONDONTWRITEBYTECODE": "1"}
    before = {path.relative_to(tmp_path) for path in tmp_path.rglob("*")}
    result = subprocess.run([sys.executable, str(root / "evals/kanban_pr_acceptance_live.py"), str(root),
                             "--mode", mode, "--expected-sha", "0" * 40, "--output", str(output)],
                            env=env, capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 1
    assert json.loads(output.read_text()) == {
        "schema_version": 1, "mode": mode, "source_sha": "0" * 40, "ok": False,
        "detail": "Probe refused source, isolation, acceptance or readiness evidence.",
    }
    assert board.read_bytes() == b"live-state-sentinel"
    assert {path.relative_to(tmp_path) for path in tmp_path.rglob("*")} - before == {Path("report.json")}


@pytest.mark.platforms("linux")
def test_probe_refuses_fenced_db_and_pending_runtime_without_writes(tmp_path, monkeypatch):
    from evals.kanban_pr_acceptance_live import _pending, _safe_db

    fenced = tmp_path / "board"
    fenced.mkdir()
    db = fenced / "kanban.db"
    db.write_bytes(b"board-sentinel")
    monkeypatch.setenv("HERMES_DELEGATED_CHILD_CONTEXT", str(fenced))
    monkeypatch.setenv("HERMES_KANBAN_DB", str(db))
    with pytest.raises(ValueError, match="pinned board"):
        _safe_db(db, tmp_path)
    with pytest.raises(ValueError, match="inherited board fence"):
        _safe_db(fenced / "other.db", tmp_path)
    with pytest.raises(ValueError, match="outside"):
        _safe_db(tmp_path.parent / "other.db", tmp_path)
    safe = tmp_path / "isolated/kanban.db"
    assert _safe_db(safe, tmp_path) == safe
    assert safe.exists() is False
    source = tmp_path / "source"
    source.mkdir()
    marker = source / ".lazy-refresh-incomplete"
    marker.write_text("owed")
    with pytest.raises(ValueError, match="Pending runtime obligation"):
        _pending(source)
    assert marker.read_text() == "owed"
    assert db.read_bytes() == b"board-sentinel"
    assert os.environ["HERMES_DELEGATED_CHILD_CONTEXT"] == str(fenced)
