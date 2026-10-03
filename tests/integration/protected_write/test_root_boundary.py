"""Root broker / unprivileged consumer boundary — real root, real sockets.

This is the only proof of the D1 authority boundary that a mocked test cannot give:
the broker runs as ROOT from the immutable bundle, the consumer is the
unprivileged runner, and the kernel — not a payload — reports who is on the other
end of each socket.

Lane: the repository's ``integration`` lane (``tests/integration/`` is excluded
from the default pytest lane, exactly like ``tests/e2e/``) and it is run by the
dedicated privileged CI job. The suite FAILS rather than skips when that job's
capability is missing, so a green run cannot mean "the boundary was never tested".

Test-audit authoring gate:

* Behaviour protected: SO_PEERCRED uid==0 authenticates the admin, the admin
  socket is unreachable to a non-root process, admin methods are unreachable from
  the consume socket, and a granted consent can only be claimed by the exact
  registered worker PID even when another process presents the same uid.
* Credible regression: an admin method reachable from the consume socket, a
  permission change that lets any local user talk to admin.sock, or an
  identity check that accepts a different process with the same uid.
* Why existing coverage misses it: the store/socket suites run the broker in the
  test process, so nothing there can prove what a *real* root broker does with a
  *real* unprivileged peer.
* No production seam: the launcher, bundle, broker and client are the real ones;
  ``trust_local_admin`` is never used here.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from tools import protected_write as pw
from tools import protected_write_protocol as proto
from tools.protected_write_broker import (
    ADMIN_SOCKET_NAME, CONSUME_SOCKET_NAME, EXIT_UNAVAILABLE,
)
from tools.protected_write_client import ClientError, admin_request, claim, finalize, worktree_status

pytestmark = pytest.mark.platforms("linux")

REPO_ROOT = Path(__file__).resolve().parents[3]
LANE_ENV = "HERMES_PROTECTED_WRITE_PRIVILEGED"
CARD = "t_privileged_e2e"
RUN = "4242"

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


def _sudo(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(["sudo", "-n", *args], capture_output=True, text=True, timeout=300,
                          **kwargs)


@pytest.fixture(scope="module")
def root_capability():
    """The privileged lane's capability, or a FAILURE — never a silent skip."""
    if os.environ.get(LANE_ENV) != "1":
        pytest.fail(
            f"{LANE_ENV}=1 is required: this suite proves the root-broker / "
            "unprivileged-consumer boundary and must run in the privileged CI job")
    if os.geteuid() == 0:
        pytest.fail("this suite must run as the UNPRIVILEGED consumer, never as root")
    probe = _sudo(["true"])
    if probe.returncode != 0:
        pytest.fail(f"the privileged lane has no passwordless sudo: {probe.stderr.strip()}")
    return True


class RootInstall:
    """One installed bundle + a root broker serving it, owned by a temp prefix."""

    def __init__(self, root: Path, launcher: Path, bundle_dir: Path, socket_dir: Path,
                 db_path: Path, board_db: Path):
        self.root = root
        self.launcher = launcher
        self.bundle_dir = bundle_dir
        self.socket_dir = socket_dir
        self.db_path = db_path
        self.board_db = board_db
        self.process: subprocess.Popen | None = None

    def admin(self, method: str, params: dict) -> dict:
        """Send one admin request through the real launcher, as root, from stdin."""
        request = json.dumps({"method": method, "params": params})
        result = _sudo(
            ["env", f"HERMES_KANBAN_DB={self.board_db}", str(self.launcher),
             "--bundle", str(self.bundle_dir), "--socket-dir", str(self.socket_dir),
             "--request", "-"],
            input=request)
        assert result.returncode == 0, f"admin {method} failed: {result.stderr}"
        return json.loads(result.stdout)

    def start(self) -> None:
        self.process = subprocess.Popen(
            ["sudo", "-n", "env", f"HERMES_KANBAN_DB={self.board_db}", str(self.launcher),
             "--bundle", str(self.bundle_dir), "--socket-dir", str(self.socket_dir),
             "--db", str(self.db_path), "--foreground"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def wait_ready(self, timeout: float = 30) -> None:
        deadline = time.monotonic() + timeout
        while not (self.socket_dir / CONSUME_SOCKET_NAME).exists():
            assert self.process is not None
            if self.process.poll() is not None:
                _out, err = self.process.communicate(timeout=5)
                raise AssertionError(f"the root broker exited: {err}")
            assert time.monotonic() < deadline, "the root broker never opened its sockets"
            time.sleep(0.05)

    def stop(self) -> None:
        if self.process is None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _sudo(["pkill", "-f", str(self.socket_dir)])
            self.process.wait(timeout=10)
        # sudo may have left the root child running; the sockets are the witness.
        _sudo(["pkill", "-f", str(self.socket_dir)])
        for _ in range(100):
            if not (self.socket_dir / CONSUME_SOCKET_NAME).exists():
                break
            time.sleep(0.05)
        self.process = None


@pytest.fixture(scope="module")
def install(root_capability, tmp_path_factory) -> RootInstall:
    """Build, chown and serve the real bundle from a root-owned prefix."""
    from scripts import protected_write_bundle as bundle

    root = Path(tempfile.mkdtemp(prefix="pwpriv-", dir="/tmp"))
    prefix = root / "prefix"
    bundle_root = prefix / bundle.BUNDLE_ROOT_REL
    launcher = prefix / bundle.LAUNCHER_REL
    target = bundle.build(REPO_ROOT, bundle_root)
    bundle.install_launcher(bundle_root, launcher)
    (bundle_root / bundle.CURRENT_POINTER).write_text(target.name, encoding="utf-8")

    socket_dir = root / "run"
    socket_dir.mkdir()
    board_db = root / "board.db"
    _write_board(board_db)

    # The install shape: root owns every byte and no other user may write any of it.
    assert _sudo(["chown", "-R", "root:root", str(root)]).returncode == 0
    assert _sudo(["chmod", "0755", str(root)]).returncode == 0
    assert _sudo(["chmod", "0755", str(socket_dir)]).returncode == 0
    assert _sudo(["chmod", "0644", str(board_db)]).returncode == 0
    assert _sudo(["chmod", "-R", "go-w", str(prefix)]).returncode == 0

    install = RootInstall(root=root, launcher=launcher, bundle_dir=target,
                          socket_dir=socket_dir, db_path=root / "authority.sqlite3",
                          board_db=board_db)
    install.start()
    try:
        install.wait_ready()
        yield install
    finally:
        install.stop()
        _sudo(["rm", "-rf", str(root)])


def _write_board(path: Path) -> None:
    """A real (if minimal) board database: the adapter reads it read-only."""
    conn = sqlite3.connect(path)
    try:
        conn.execute("CREATE TABLE tasks (id TEXT PRIMARY KEY, status TEXT, assignee TEXT, "
                     "current_run_id INTEGER, workspace_path TEXT)")
        conn.execute("INSERT INTO tasks VALUES (?, 'running', 'twohomes-coder', ?, '')",
                     (CARD, int(RUN)))
        conn.commit()
    finally:
        conn.close()


@pytest.fixture(scope="module")
def worktree(tmp_path_factory) -> Path:
    """A real git worktree owned by the unprivileged runner."""
    root = tmp_path_factory.mktemp("wt") / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(root)], check=True, timeout=120,
                   env=GIT_ENV)
    (root / "notes.txt").write_bytes(b"alpha\nbeta\n")
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True, timeout=120, env=GIT_ENV)
    subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", "init"], check=True,
                   timeout=120, env=GIT_ENV)
    return root


def _context(worktree: Path) -> dict:
    return pw.runtime_context(
        worktree=worktree, board="two-homes", card=CARD, profile="twohomes-coder",
        home=str(Path(worktree).parent), run=RUN, session="sess-privileged")


# ── the installed bundle is root-owned and self-verifying ─────────────────
def test_installed_bundle_is_root_owned_and_not_writable_by_others(install):
    for path in (install.bundle_dir, install.bundle_dir / "manifest.json",
                 install.bundle_dir / "tools" / "protected_write_broker.py", install.launcher):
        st = os.lstat(path)
        assert st.st_uid == 0, f"{path} is not root-owned"
        assert stat.S_IMODE(st.st_mode) & 0o022 == 0, f"{path} is writable by group or other"
    assert stat.S_IMODE(os.lstat(install.launcher).st_mode) == 0o755
    assert install.bundle_dir.name == json.loads(
        (install.bundle_dir / "manifest.json").read_text(encoding="utf-8"))["artifact_sha256"]


def test_launcher_refuses_a_tampered_bundle_before_serving(install):
    victim = install.bundle_dir / "tools" / "protected_write_protocol.py"
    assert _sudo(["cp", "-a", str(victim), str(victim) + ".orig"]).returncode == 0
    try:
        assert _sudo(["bash", "-c", f"printf '\\n# tampered\\n' >> {victim}"]).returncode == 0
        result = _sudo([str(install.launcher), "--bundle", str(install.bundle_dir),
                        "--socket-dir", str(install.socket_dir), "--db", str(install.db_path),
                        "--foreground"])
        assert result.returncode == EXIT_UNAVAILABLE, result.stdout
        assert "content hash mismatch" in result.stderr
    finally:
        assert _sudo(["cp", "-a", str(victim) + ".orig", str(victim)]).returncode == 0
        _sudo(["rm", "-f", str(victim) + ".orig"])


# ── kernel credential checks ─────────────────────────────────────────────
def test_unprivileged_process_cannot_reach_the_admin_socket(install):
    with pytest.raises(ClientError) as excinfo:
        admin_request("active_holds", {}, socket_dir=install.socket_dir)
    # Two independent gates: the 0600 socket, and (behind it) SO_PEERCRED uid==0.
    assert "Permission denied" in str(excinfo.value)


def test_admin_methods_are_unreachable_from_the_consume_socket(install):
    from tools.protected_write_client import request as client_request

    consume = install.socket_dir / CONSUME_SOCKET_NAME
    for method in ("register", "issue", "revoke"):
        with pytest.raises(ClientError) as excinfo:
            client_request(consume, method, {})
        assert "admin" in str(excinfo.value).lower()


def test_unprivileged_worker_reads_status_without_authority(install, worktree):
    context = _context(worktree)
    status = worktree_status(context, socket_dir=install.socket_dir)
    assert status["status"] == "unregistered"
    assert status["generation"] is None
    assert status["identity_key"]


# ── the whole grant lifecycle across the privilege boundary ──────────────
def test_only_the_exact_registered_pid_can_claim_a_root_issued_grant(install, worktree):
    context = _context(worktree)
    registered = install.admin("register", {
        "context": context, "dispatcher_pid": os.getpid()})
    assert registered["generation"] >= 1

    context = _context(worktree) | {"registration_generation": registered["generation"]}
    plan = pw.prepare("write_file",
                      {"path": "notes.txt", "content": "alpha\nBETA\n", "cross_profile": False},
                      context, worktree_root=worktree)
    issued = install.admin("issue", {
        "envelope": plan.envelope(), "descriptor": plan.descriptor, "ttl_seconds": 900,
        "confirmation": plan.descriptor_sha256})
    assert issued["descriptor_sha256"] == plan.descriptor_sha256

    journal_digest = proto.sha256_hex(b"journal")
    claimed = claim(issued["grant_id"], plan.descriptor, "txn-e2e", journal_digest, context,
                    socket_dir=install.socket_dir)
    assert claimed["receipt"]["state"] == "spent_pending"
    assert claimed["claim_id"]

    # Readback over the REAL after-image, then the durable terminal receipt.
    readback = {record["normalized"]: plan.descriptor["paths"][0]["after_sha256"]
                for record in plan.descriptor["paths"]}
    done = finalize(claimed["claim_id"], "txn-e2e", "completed", readback, context,
                    socket_dir=install.socket_dir)
    assert done["receipt"]["state"] == "completed"

    # A second process with the SAME uid but a different PID must never spend consent.
    second = install.admin("issue", {
        "envelope": plan.envelope(), "descriptor": plan.descriptor, "ttl_seconds": 900,
        "confirmation": plan.descriptor_sha256})
    script = (
        "import json, sys\n"
        "from tools.protected_write_client import claim, ConsentDenied\n"
        "from tools.protected_write_context import current_identity\n"
        "payload = json.loads(sys.stdin.read())\n"
        "mine = current_identity()\n"
        "ctx = dict(payload['context'])\n"
        "ctx.update(uid=mine.uid, pid=mine.pid, boot_id=mine.boot_id,\n"
        "           start_ticks=mine.start_ticks)\n"
        "assert mine.pid != payload['parent_pid']\n"
        "try:\n"
        "    claim(payload['grant_id'], payload['descriptor'], 'txn-child',\n"
        "          payload['journal_digest'], ctx, socket_dir=payload['socket_dir'])\n"
        "except ConsentDenied as exc:\n"
        "    print(f'DENIED {exc}')\n"
        "    raise SystemExit(0)\n"
        "print('ALLOWED')\n")
    child = subprocess.run(
        [sys.executable, "-c", script],
        input=json.dumps({"grant_id": second["grant_id"], "descriptor": plan.descriptor,
                          "journal_digest": journal_digest, "context": context,
                          "parent_pid": os.getpid(), "socket_dir": str(install.socket_dir)}),
        capture_output=True, text=True, timeout=180,
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT)}, check=False)
    assert child.returncode == 0, child.stderr
    assert child.stdout.startswith("DENIED"), child.stdout
    assert "PID must EQUAL" in child.stdout or "identity does not match" in child.stdout
