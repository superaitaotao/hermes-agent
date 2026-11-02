"""Verification refuses unsafe homes and stale Git targets before mutation."""
from pathlib import Path
import subprocess
import sys

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
