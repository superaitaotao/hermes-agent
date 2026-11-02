"""Registry file transport uses one bounded, guarded regular-file read."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

import pytest


@pytest.fixture
def board(tmp_path, monkeypatch):
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect_closing

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(home / ".hermes"))
    monkeypatch.delenv("HERMES_KANBAN_DB", raising=False)
    monkeypatch.setenv("HERMES_KANBAN_BOARD", "path-contract")
    monkeypatch.setenv("HERMES_PROFILE", "probe")
    kb.create_board("path-contract")
    with connect_closing(board="path-contract") as conn:
        tid = kb.create_task(conn, title="file transport", assignee="probe")
        other = kb.create_task(conn, title="other owner", assignee="peer")
        owner = kb.claim_task(conn, tid)
    monkeypatch.setenv("HERMES_KANBAN_TASK", tid)
    monkeypatch.setenv("HERMES_KANBAN_RUN_ID", str(owner.current_run_id))
    return tid, other, home


def dispatch(args):
    from tools import kanban_tools
    from tools.registry import registry

    return json.loads(registry.dispatch("kanban_attach", args))


def snapshot():
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect_closing

    with connect_closing(board="path-contract") as conn:
        rows = [dict(row) for row in conn.execute("SELECT * FROM task_attachments ORDER BY id")]
        root = kb.attachments_root(board="path-contract")
        files = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    return rows, files


@pytest.mark.parametrize("source", ["path", "base64", "override"])
def test_registry_stores_literal_binary_and_sanitizes_name(board, tmp_path, source):
    payload = bytes(range(256)) * 1000 + b"\x00\xff\xfeEND"
    path = tmp_path / "evidence.bin"
    path.write_bytes(payload)
    args = {"path": str(path)}
    expected_name = "evidence.bin"
    if source == "base64":
        args = {"content_base64": base64.b64encode(payload).decode(), "filename": "evidence.bin"}
    elif source == "override":
        args["filename"] = "../../renamed.bin"
        expected_name = "renamed.bin"
    result = dispatch(args)
    assert result.get("ok") is True, result
    rows, files = snapshot()
    row = next(row for row in rows if row["id"] == result["attachment_id"])
    stored = Path(row["stored_path"]).read_bytes()
    assert row["filename"] == expected_name
    assert result["size"] == len(payload) == len(stored)
    assert stored == payload
    assert hashlib.sha256(stored).digest() == hashlib.sha256(payload).digest()
    assert list(files.values()) == [payload]


@pytest.mark.parametrize("case,error", [
    ("both", "exactly one"), ("neither", "exactly one"), ("blank", "exactly one"),
    ("base64-no-name", "filename"), ("bad-base64", "valid base64"),
    ("relative", "absolute"), ("tilde", "absolute"), ("missing", "file"),
    ("directory", "regular file"), ("oversize", "limit"),
    ("protected", "denied"), ("other-worker", "scoped to task"),
    ("namespace", "namespace"),
])
def test_registry_refusal_leaves_storage_unchanged(board, tmp_path, case, error):
    from hermes_cli import kanban_db as kb

    path = tmp_path / "input.bin"
    path.write_bytes(b"ordinary bytes")
    assert dispatch({"path": str(path)})["ok"] is True
    args = {"path": str(path)}
    protected = board[2] / ".hermes" / "auth.json"
    protected.write_text('{"synthetic":true}', encoding="utf-8")
    (board[2] / "input.bin").write_bytes(b"must require absolute input")
    if case == "oversize":
        with path.open("wb") as stream:
            stream.truncate(kb.KANBAN_ATTACHMENT_MAX_BYTES + 1)
    variants = {
        "both": {**args, "content_base64": "aGk=", "filename": "x.bin"},
        "neither": {}, "blank": {"path": "  ", "content_base64": " "},
        "base64-no-name": {"content_base64": "aGk="},
        "bad-base64": {"content_base64": "!", "filename": "x.bin"},
        "relative": {"path": "relative.bin"}, "tilde": {"path": "~/input.bin"},
        "missing": {"path": str(tmp_path / "absent.bin")},
        "directory": {"path": str(tmp_path)}, "oversize": args,
        "protected": {"path": str(protected)}, "other-worker": {**args, "task_id": board[1]},
        "namespace": {"path": r"\\?\UNC\example.invalid\share\input.bin"},
    }
    args = variants[case]
    before = snapshot()
    result = dispatch(args)
    assert error in result.get("error", ""), result
    assert snapshot() == before


@pytest.mark.platforms("posix")
def test_symlink_target_uses_shared_guard_and_fifo_refuses(board, tmp_path):
    safe = tmp_path / "safe.bin"
    safe.write_bytes(b"permitted\x00binary")
    link = tmp_path / "link.bin"
    link.symlink_to(safe)
    result = dispatch({"path": str(link)})
    assert result.get("ok") is True, result
    assert list(snapshot()[1].values()) == [b"permitted\x00binary"]
    secret = board[2] / ".hermes" / "auth.json"
    secret.write_text('{"synthetic":true}')
    link.unlink()
    link.symlink_to(secret)
    before = snapshot()
    assert "denied" in dispatch({"path": str(link)})["error"]
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    assert "regular file" in dispatch({"path": str(fifo)})["error"]
    assert snapshot() == before


def test_growing_file_is_rejected_after_bounded_read(board, tmp_path, monkeypatch):
    from hermes_cli import kanban_db as kb

    path = tmp_path / "growing.bin"
    path.write_bytes(b"small")
    before = snapshot()
    original = os.fstat
    visits = []

    def grow_on_stat(fd):
        stat = original(fd)
        if stat.st_ino == path.stat().st_ino and not visits:
            visits.append(fd)
            with path.open("ab") as stream:
                stream.truncate(kb.KANBAN_ATTACHMENT_MAX_BYTES + 1)
        return stat

    monkeypatch.setattr(os, "fstat", grow_on_stat)
    result = dispatch({"path": str(path)})
    assert "limit" in result.get("error", ""), result
    assert snapshot() == before
    assert visits, "the opened file must be checked, not a pre-open Path stat"


def test_namespace_is_refused_before_any_resolution(board, monkeypatch):
    original = Path.resolve

    def no_namespace_resolution(self, *args, **kwargs):
        if "UNC" in str(self):
            raise AssertionError("namespace touched before the raw guard")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", no_namespace_resolution)
    before = snapshot()
    result = dispatch({"path": r"\\?\UNC\example.invalid\share\input.bin"})
    assert "namespace" in result.get("error", ""), result
    assert snapshot() == before
