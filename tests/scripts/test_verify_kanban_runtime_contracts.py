"""Verification refuses unsafe homes and stale Git targets before mutation."""
from pathlib import Path
import subprocess
import sys
import json

import pytest

from scripts import verify_kanban_runtime_contracts as probe


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


@pytest.mark.parametrize("key", ["HOME", "HERMES_HOME", "HERMES_RUNTIME_DIR", "XDG_STATE_HOME",
                                     "HERMES_GATEWAY_LOCK_DIR"])
def test_escaping_home_refuses_before_board_or_update(tmp_path, key):
    env = probe.trial_environment()
    env[key] = str(tmp_path)
    before = list(tmp_path.iterdir())
    with pytest.raises(ValueError, match="outside /trial"):
        probe.validate_trial_homes(env)
    assert list(tmp_path.iterdir()) == before
    assert probe.validate_trial_homes(probe.trial_environment())["HOME"] == "/trial/home"


def test_target_must_advertise_exact_candidate_and_advance_as_descendant(tmp_path):
    writer = tmp_path / "writer"
    writer.mkdir()
    git(writer, "init", "-b", "main")
    git(writer, "config", "user.name", "Fixture")
    git(writer, "config", "user.email", "fixture@example.invalid")
    git(writer, "config", "commit.gpgsign", "false")
    (writer / "unrelated.txt").write_text("old")
    git(writer, "add", ".")
    git(writer, "commit", "-m", "old")
    old = git(writer, "rev-parse", "HEAD")
    (writer / "unrelated.txt").write_text("candidate")
    git(writer, "commit", "-am", "candidate")
    candidate = git(writer, "rev-parse", "HEAD")
    bare = tmp_path / "origin.git"
    git(writer, "clone", "--bare", "--no-local", str(writer), str(bare))
    assert probe.verify_target(writer, str(bare), candidate)["advertised_sha"] == candidate
    with pytest.raises(ValueError, match="advertised"):
        probe.verify_target(writer, str(bare), old)
    child = probe.advance_fixture(writer, bare, candidate)
    assert child != candidate
    assert probe.verify_target(writer, str(bare), child, ancestor=candidate)["descendant"] is True
    git(bare, "update-ref", "refs/heads/main", candidate)
    with pytest.raises(ValueError, match="descendant"):
        probe.verify_target(writer, str(bare), candidate, ancestor=child)


def test_runtime_child_refuses_pending_completion_without_repair(tmp_path):
    root = Path(__file__).resolve().parents[2]
    marker = tmp_path / ".lazy-refresh-incomplete"
    marker.write_text("owed")
    before = sorted(p.name for p in tmp_path.iterdir())
    code = ("import os; from pathlib import Path; "
            "from scripts.verify_kanban_runtime_contracts import runtime_ready; "
            "os.environ['HERMES_DISABLE_LAZY_INSTALLS']='1'; "
            f"runtime_ready(Path({str(tmp_path)!r}), {'0' * 40!r})")
    result = subprocess.run([sys.executable, "-B", "-c", code], cwd=root,
                            capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode != 0
    assert "Pending runtime obligation" in result.stderr
    assert marker.read_text(encoding="utf-8") == "owed"
    assert sorted(p.name for p in tmp_path.iterdir()) == before


@pytest.mark.platforms("posix")
def test_settlement_stops_on_real_owed_restart_before_readiness(tmp_path, monkeypatch):
    from scripts import kanban_update_rehearsal as rehearsal
    from hermes_cli.update_host_obligation import host_obligation_path, write_host_obligation

    root = Path(__file__).resolve().parents[2]
    home = tmp_path / "home"
    profile = home / ".hermes/profiles/probe"
    profile.mkdir(parents=True)
    (profile / "config.yaml").write_text("model: harmless-probe\n")
    (profile / "gateway_state.json").write_text(json.dumps({"gateway_state": "running", "pid": 4194297}))
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(home / ".hermes"))
    monkeypatch.setenv("HERMES_GATEWAY_LOCK_DIR", str(tmp_path / "locks"))
    sha = git(root, "rev-parse", "HEAD")
    assert write_host_obligation(expected_sha=sha)
    marker = host_obligation_path()
    original = marker.read_bytes()
    (tmp_path / "evidence").mkdir()
    trial = rehearsal.Trial(tmp_path, root)
    monkeypatch.setattr(trial, "preflight", lambda **kw: {})
    monkeypatch.setattr(trial, "python", lambda: [sys.executable])

    def local_argv(_trial, _runner, command):
        command = [str(arg).replace("/runner/", str(root) + "/").replace("/trial/checkout", str(root)) for arg in command]
        launcher = str(root / ".hermes/bin/hermes")
        if launcher in command:
            index = command.index(launcher)
            command[index:index + 1] = [sys.executable, "-B", "-m", "hermes_cli.main"]
        return ["env", "-u", "HERMES_KANBAN_TASK", "-u", "HERMES_KANBAN_DB", *command]

    monkeypatch.setattr(rehearsal, "sandbox_argv", local_argv)
    real_run = trial.run

    def run(label, argv, **kwargs):
        if label == "actual-update":
            return tmp_path / "evidence/unneeded-update.log"
        return real_run(label, argv, **kwargs)

    monkeypatch.setattr(trial, "run", run)

    def forbidden_readback(*args):
        pytest.fail("Readiness must not run with an owed restart")

    monkeypatch.setattr(trial, "readback", forbidden_readback)
    with pytest.raises(ValueError, match="Settlement left runtime obligations"):
        trial.update(sha)
    assert marker.read_bytes() == original
    settlement = next(phase["settlement"] for phase in trial.phases if phase["phase"] == "settlement")
    assert settlement["exit_code"] == 0, next(Path(phase["log"]).read_text() for phase in trial.phases if phase["phase"] == "settlement")
    assert settlement["after"][0]["exists"] is True
    assert settlement["before"][0]["sha256"] == settlement["after"][0]["sha256"]
