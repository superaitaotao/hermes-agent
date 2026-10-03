"""``hermes approvals protected-write`` — real CLI wiring for the D1 boundary.

The subcommand is the only unprivileged surface of the protected-write mechanism:
it previews one request deterministically and reads broker status. It must never
register, issue, extend or bypass confirmation, and its exit codes are a contract
the root admin launcher and the (D2) file tools both read.

Test-audit authoring gate:

* Behaviour protected: the CLI's own contract — the flags that exist (no
  ``--yes``/``--always``/issuance), the exit codes (0 preview ok, 2 malformed
  request, 3 refused context or unavailable authority), the full untruncated
  untrusted diff with its descriptor digest, terminal-control escaping, and the
  fail-closed status answer when no broker is listening.
* Credible regression: someone adds a confirmation-skipping flag, a refusal
  silently degrades into an unprotected fallback, a preview truncates the diff
  (so the human confirms bytes they never saw), raw control characters reach the
  terminal, or an unreachable broker is reported as "unregistered".
* Why existing coverage misses it: no existing test drives this subcommand; the
  module-level suites exercise the preparer and store directly and cannot catch a
  parser/dispatch regression.
* No production seam: every case parses real argv through the real
  ``build_approvals_parser`` and calls the real ``hermes_cli.main.cmd_approvals``
  dispatcher against a real temp git worktree.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

from hermes_cli.subcommands.approvals import build_approvals_parser
from hermes_cli.main import cmd_approvals
from tools import protected_write_protocol as proto
from tools.protected_write_broker import ADMIN_SOCKET_NAME, CONSUME_SOCKET_NAME, BrokerServer, serve_forever
from tools.protected_write_preparer import UNTRUSTED_DIFF_HEADER

GIT_ENV = {
    "GIT_AUTHOR_NAME": "tester",
    "GIT_AUTHOR_EMAIL": "tester@example.invalid",
    "GIT_COMMITTER_NAME": "tester",
    "GIT_COMMITTER_EMAIL": "tester@example.invalid",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_TERMINAL_PROMPT": "0",
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
}


@pytest.fixture
def worktree(tmp_path: Path) -> Path:
    """A real git worktree: the runtime context reads HEAD, so it must exist."""
    root = tmp_path / "wt"
    root.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(root)], check=True, timeout=60,
                   env={**GIT_ENV})
    (root / "notes.txt").write_bytes(b"alpha\nbeta\ngamma\n")
    (root / "bom_crlf.txt").write_bytes(b"\xef\xbb\xbffirst\r\nsecond\r\n")
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True, timeout=60, env=GIT_ENV)
    subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", "init"], check=True,
                   timeout=60, env=GIT_ENV)
    return root


def _parser() -> argparse.ArgumentParser:
    """The real ``hermes approvals`` parser, wired to the real dispatcher."""
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    build_approvals_parser(subparsers, cmd_approvals=cmd_approvals)
    return parser


def _run(argv: list[str], capsys) -> tuple[int, str, str]:
    """Parse real argv, dispatch through the real handler, capture streams."""
    args = _parser().parse_args(argv)
    code = 0
    try:
        args.func(args)
    except SystemExit as exc:  # cmd_approvals exits with the handler's status
        code = int(exc.code or 0)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _write_request(path: Path, tool: str, arguments: dict) -> Path:
    path.write_text(json.dumps({"tool": tool, "arguments": arguments}), encoding="utf-8")
    return path


def _contextless(argv_extra: list[str], worktree: Path) -> list[str]:
    return ["approvals", "protected-write", *argv_extra, "--root", str(worktree)]


# ── parser contract ───────────────────────────────────────────────────────
def test_parser_exposes_preview_and_status_and_no_bypass_flag():
    parser = _parser()
    preview = parser.parse_args(["approvals", "protected-write", "preview", "--request", "-"])
    assert preview.protected_write_command == "preview"
    assert preview.request == "-"
    assert preview.json is False

    status = parser.parse_args(["approvals", "protected-write", "status"])
    assert status.protected_write_command == "status"
    assert status.socket_dir == "/run/hermes-protected-writes"

    # There is deliberately no confirmation-skipping or issuance flag: a bypass
    # flag would turn a human decision into a one-line agent command.
    for flag in ("--yes", "--always", "--grant", "--issue", "--session", "--force"):
        with pytest.raises(SystemExit):
            parser.parse_args(["approvals", "protected-write", "preview", flag])
        with pytest.raises(SystemExit):
            parser.parse_args(["approvals", "protected-write", "status", flag])


def test_no_subcommand_prints_usage_and_fails(capsys):
    code, out, err = _run(["approvals", "protected-write"], capsys)
    assert code == 1
    assert out.strip() == ""
    assert "usage: hermes approvals protected-write preview" in err


# ── preview ───────────────────────────────────────────────────────────────
def test_preview_prints_full_untrusted_diff_and_descriptor_digest(worktree, tmp_path, capsys):
    before = (worktree / "notes.txt").read_bytes()
    request = _write_request(
        tmp_path / "req.json", "patch_replace",
        {"path": "notes.txt", "old_string": "beta", "new_string": "BETA",
         "replace_all": False, "cross_profile": False})

    code, out, err = _run(_contextless(["preview", "--request", str(request)], worktree), capsys)

    assert code == 0, err
    # The banner is the first line of the rendered diff, so the human always sees
    # the "this is request data" label before any request byte.
    assert UNTRUSTED_DIFF_HEADER in out
    assert out.index(UNTRUSTED_DIFF_HEADER) < out.index("-beta")
    assert "-beta" in out and "+BETA" in out
    # The diff is complete, not elided: the untouched line that follows the hunk
    # is present, so the human sees every changed and unchanged byte of the file.
    assert " gamma" in out

    # The printed digest must bind the descriptor the preview showed. Recompute it
    # from the plan the CLI itself produced and compare with the printed value.
    from tools import protected_write as pw
    context = pw.runtime_context(worktree=worktree)
    plan = pw.prepare("patch_replace",
                      {"path": "notes.txt", "old_string": "beta", "new_string": "BETA",
                       "replace_all": False, "cross_profile": False},
                      context, worktree_root=worktree)
    assert f"descriptor_sha256:  {plan.descriptor_sha256}" in out
    assert plan.descriptor_sha256 == proto.sha256_hex(
        proto.canonical_json_bytes(plan.descriptor))
    # A preview creates nothing.
    assert (worktree / "notes.txt").read_bytes() == before


def test_preview_escapes_terminal_control_characters(worktree, tmp_path, capsys):
    request = _write_request(
        tmp_path / "req.json", "patch_replace",
        {"path": "notes.txt", "old_string": "gamma",
         "new_string": "\x1b[31mRED\x1b[0m\x07", "replace_all": False, "cross_profile": False})

    code, out, err = _run(_contextless(["preview", "--request", str(request)], worktree), capsys)

    assert code == 0, err
    assert "\x1b" not in out, "raw escape reached the terminal"
    assert "\x07" not in out, "raw bell reached the terminal"
    assert "\\x1b[31mRED\\x1b[0m\\x07" in out


def test_preview_json_output_carries_the_same_digest(worktree, tmp_path, capsys):
    request = _write_request(
        tmp_path / "req.json", "write_file",
        {"path": "new.txt", "content": "created\n", "cross_profile": False})

    code, out, err = _run(
        _contextless(["preview", "--request", str(request), "--json"], worktree), capsys)

    assert code == 0, err
    payload = json.loads(out)
    assert payload["schema_version"] == proto.SCHEMA_VERSION
    assert payload["tool"] == "write_file"
    assert payload["confirmation"] == payload["descriptor_sha256"]
    assert payload["paths"][0]["action"] == "create"
    assert payload["paths"][0]["before_sha256"] is None
    assert payload["paths"][0]["after_sha256"] == proto.sha256_hex(b"created\n")
    assert not (worktree / "new.txt").exists()


def test_preview_refuses_malformed_and_unknown_requests(worktree, tmp_path, capsys):
    cases = {
        "unknown field": {"tool": "write_file", "arguments": {"path": "a", "content": "b",
                                                             "cross_profile": False}, "extra": 1},
        "missing arguments": {"tool": "write_file"},
        "cross_profile true": {"tool": "write_file",
                               "arguments": {"path": "a", "content": "b", "cross_profile": True}},
        "unsupported tool": {"tool": "shell_exec",
                             "arguments": {"path": "a", "content": "b", "cross_profile": False}},
    }
    for label, payload in cases.items():
        request = tmp_path / f"{label.replace(' ', '_')}.json"
        request.write_text(json.dumps(payload), encoding="utf-8")
        code, out, err = _run(_contextless(["preview", "--request", str(request)], worktree), capsys)
        assert code == 2, f"{label}: expected refusal, got {code} {out!r} {err!r}"
        assert out.strip() == ""

    missing = tmp_path / "absent.json"
    code, _out, err = _run(_contextless(["preview", "--request", str(missing)], worktree), capsys)
    assert code == 2
    assert "does not exist" in err
    assert not (worktree / "a").exists()


def test_preview_refuses_a_delegated_or_cron_execution_context(worktree, tmp_path, capsys, monkeypatch):
    """A delegate/cron run inherits the worker's identity but is not the worker."""
    from agent.delegation_context import non_dispatcher_owned_context

    request = _write_request(
        tmp_path / "req.json", "write_file",
        {"path": "new.txt", "content": "created\n", "cross_profile": False})
    argv = _contextless(["preview", "--request", str(request)], worktree)

    # Cron / in-process run: the real ContextVar the gateway sets.
    with non_dispatcher_owned_context():
        code, out, err = _run(argv, capsys)
    assert code == 3, (out, err)
    assert "non-dispatcher-owned" in err

    # A subprocess of a delegate child: the real environment marker.
    monkeypatch.setenv("HERMES_DELEGATED_CHILD_CONTEXT", "1")
    code, out, err = _run(argv, capsys)
    assert code == 3, (out, err)
    assert "delegated child context" in err
    assert not (worktree / "new.txt").exists()


# ── status ────────────────────────────────────────────────────────────────
def test_status_fails_closed_when_no_broker_is_listening(worktree, tmp_path, capsys):
    empty = tmp_path / "empty-sockets"
    empty.mkdir()
    code, out, err = _run(
        _contextless(["status", "--socket-dir", str(empty), "--json"], worktree), capsys)
    assert code == 3
    payload = json.loads(out)
    # An unreachable authority is NOT "unregistered": reporting the weaker answer
    # would invite the caller to fall back to an unprotected write.
    assert payload["status"] == "unavailable"
    assert payload["error"]
    assert "unregistered" not in out


def test_status_reads_unregistered_from_a_live_broker(worktree, tmp_path, capsys):
    socket_dir = Path(tempfile.mkdtemp(prefix="hermes-pwcli-"))
    server = BrokerServer(socket_dir=socket_dir, db_path=tmp_path / "authority.sqlite3",
                          board_check=lambda _ctx: None, trust_local_admin=True)
    failures: list[str] = []

    def _serve() -> None:
        try:
            server.start()
            serve_forever(server)
        except BaseException as exc:  # surfaced instead of lost in the thread
            failures.append(f"{type(exc).__name__}: {exc}")

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not (socket_dir / CONSUME_SOCKET_NAME).exists():
            assert not failures, failures
            assert time.monotonic() < deadline, "broker sockets never appeared"
            time.sleep(0.01)
        code, out, err = _run(
            _contextless(["status", "--socket-dir", str(socket_dir), "--json"], worktree), capsys)
        assert code == 0, err
        payload = json.loads(out)
        assert payload["status"] == "unregistered"
        assert payload["generation"] is None
        assert payload["correlations"] == []
        assert payload["identity_key"]

        human_code, human_out, human_err = _run(
            _contextless(["status", "--socket-dir", str(socket_dir)], worktree), capsys)
        assert human_code == 0, human_err
        assert "status:      unregistered" in human_out
    finally:
        server.request_stop()
        thread.join(timeout=5)
        assert not thread.is_alive(), "the broker thread did not stop"
        assert not failures, failures
        shutil.rmtree(socket_dir, ignore_errors=True)


def test_status_human_output_is_not_json(worktree, tmp_path, capsys):
    empty = tmp_path / "no-sockets"
    empty.mkdir()
    code, out, err = _run(
        _contextless(["status", "--socket-dir", str(empty)], worktree), capsys)
    assert code == 3
    assert out.strip() == ""
    assert "unavailable" in err
    assert not (empty / ADMIN_SOCKET_NAME).exists()
