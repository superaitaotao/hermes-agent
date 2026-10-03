"""Protected-write broker, sockets and immutable bundle — real processes only.

Linux-only: the whole contract rests on ``SO_PEERCRED``, ``/proc`` identity and
AF_UNIX socket permissions, so these tests run on the host that has them and
never fake a platform.

Test-audit authoring gate:

* Behaviour protected: the kernel-attested peer rules on a real Unix socket
  (exact PID, uid==0 for admin), the socket permission contract, the restart
  rule, and root-owned bundle verification. Mocks cannot prove any of it.
* Credible regression: an admin method reachable from the consume socket, a
  foreign process claiming with a copied context, an unverified bundle accepted,
  or a restarted broker letting an unresolved claim execute.
* Why existing coverage misses it: the store-level suite drives the API directly
  and cannot reach socket permissions, ``SO_PEERCRED`` or the launcher.
* No production seam: the DI used here (a no-op board check, an in-process broker
  with the root requirement relaxed) is the same constructor surface the launcher
  uses, and the launcher itself exposes no switch that relaxes admin auth.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

from tools import protected_write_authority as authority
from tools import protected_write_broker as broker_mod
from tools import protected_write_preparer as preparer
from tools import protected_write_protocol as proto
from tools.protected_write_broker import (
    ADMIN_SOCKET_NAME, CONSUME_SOCKET_NAME, BrokerServer, serve_forever,
)
from tools.protected_write_client import ConsentDenied, admin_request, claim, finalize, lookup
from tools.protected_write_client import request as client_request
from tools.protected_write_context import current_identity

pytestmark = pytest.mark.platforms("linux")

REPO_ROOT = Path(__file__).resolve().parents[2]
IDENTITY = current_identity()
BASELINE = "e9d7a18dc5515d50a9d9ecd5beca188028cda004"


def _context(worktree: Path, **overrides) -> dict:
    ctx = {
        "board": "two-homes",
        "card": "t_broker",
        "profile": "twohomes-coder",
        "home": str(worktree / "home"),
        "run": "700",
        "session": "sess-broker",
        "registration_generation": 0,
        "uid": IDENTITY.uid,
        "pid": IDENTITY.pid,
        "boot_id": IDENTITY.boot_id,
        "start_ticks": IDENTITY.start_ticks,
        "worktree": str(worktree),
        "git_dir": str(worktree / ".git"),
        "common_dir": str(worktree / ".git"),
        "baseline": BASELINE,
    }
    ctx.update(overrides)
    return ctx


@pytest.fixture
def short_socket_dir():
    """A private socket directory with a path short enough for ``sun_path``.

    ``tmp_path`` sits under a deep runner prefix whose socket path would exceed the
    108-byte AF_UNIX limit, so the sockets live in a short private directory.
    """
    directory = Path(tempfile.mkdtemp(prefix="hermes-pw-"))
    try:
        yield directory
    finally:
        shutil.rmtree(directory, ignore_errors=True)


class Harness:
    """A broker served on its own thread, owned by the thread that opened it.

    The store is a SQLite connection: it must be created, used and closed on one
    thread, exactly as the production launcher does. The harness reproduces that
    shape and surfaces any startup failure to the test instead of losing it in a
    dead thread.
    """

    def __init__(self, server: BrokerServer, socket_dir: Path):
        self.server = server
        self.failures: list[str] = []
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        try:
            self.server.start()
            serve_forever(self.server)  # its own finally closes the store on this thread
        except BaseException as exc:  # surfaced to the waiting test, never swallowed
            self.failures.append(f"{type(exc).__name__}: {exc}")

    def __enter__(self) -> "Harness":
        self.thread.start()
        for name in (ADMIN_SOCKET_NAME, CONSUME_SOCKET_NAME):
            deadline = time.monotonic() + 10
            while not (self.server.socket_dir / name).exists():
                if self.failures:
                    raise AssertionError(f"broker failed to start: {self.failures[0]}")
                assert time.monotonic() < deadline, f"{name} never appeared"
                time.sleep(0.01)
        return self

    def __exit__(self, *_exc) -> None:
        # Closing the listeners ends accept(); the serving thread then closes the
        # store it opened, so no SQLite connection crosses a thread boundary.
        self.server.request_stop()
        self.thread.join(timeout=5)
        assert not self.thread.is_alive(), "the broker thread did not stop"
        assert self.server.store is None, "the serving thread did not close the store"
        assert not self.failures, self.failures


@pytest.fixture
def running_broker(tmp_path: Path, short_socket_dir: Path):
    """A real broker over real sockets. ``require_root_peer=False`` is the test DI.

    The launcher itself always uses the production default, so nothing a user can
    run relaxes admin authentication.
    """
    server = BrokerServer(
        socket_dir=short_socket_dir, db_path=tmp_path / "authority.sqlite3",
        board_check=lambda _ctx: None,  # the real adapter reads a live board database
        trust_local_admin=True)  # this runner is not root; the launcher never sets this
    with Harness(server, short_socket_dir):
        yield server


@pytest.fixture
def worktree(tmp_path: Path) -> Path:
    root = tmp_path / "wt"
    root.mkdir()
    (root / "plain.txt").write_bytes(b"alpha\nbeta\n")
    (root.parent / "home").mkdir(exist_ok=True)
    return root


# ── socket contract ───────────────────────────────────────────────────────
def test_socket_and_directory_permissions_are_restrictive(running_broker, short_socket_dir):
    socket_dir = short_socket_dir
    # Traversable (the worker must reach consume.sock) but NOT writable by group or
    # other, so no unprivileged process can replace, unlink or shadow a socket here.
    assert stat.S_IMODE(socket_dir.stat().st_mode) == 0o755
    assert stat.S_IMODE(socket_dir.stat().st_mode) & 0o022 == 0
    # The admin socket stays root-only; connect permission is the first of two gates.
    assert stat.S_IMODE((socket_dir / ADMIN_SOCKET_NAME).stat().st_mode) == 0o600
    # Any uid may connect to consume.sock: the kernel credential check, not the file
    # mode, is the authority, so the mode must not be what denies the real worker.
    assert stat.S_IMODE((socket_dir / CONSUME_SOCKET_NAME).stat().st_mode) == 0o666
    assert stat.S_ISSOCK((socket_dir / CONSUME_SOCKET_NAME).stat().st_mode)


def test_admin_entry_reads_stdin_only_and_refuses_a_non_root_shell(short_socket_dir, tmp_path, capsys):
    """The launcher's admin path never opens a request file and never runs unprivileged."""
    request_file = tmp_path / "request.json"
    request_file.write_text('{"method": "register", "params": {}}', encoding="utf-8")
    assert broker_mod.admin_request_main(["--request", str(request_file)]) == broker_mod.EXIT_USAGE
    assert "stdin only" in capsys.readouterr().err

    assert os.geteuid() != 0, "this runner must be the unprivileged consumer"
    assert broker_mod.admin_request_main(["--request", "-"]) == broker_mod.EXIT_UNAVAILABLE
    assert "requires root" in capsys.readouterr().err


def test_board_resolution_is_self_contained_and_denies_when_unresolvable(monkeypatch, tmp_path):
    """The bundled broker cannot import the worker checkout, so it resolves the board itself."""
    monkeypatch.delenv("HERMES_KANBAN_DB", raising=False)
    monkeypatch.delenv("HERMES_KANBAN_HOME", raising=False)
    with pytest.raises(authority.ConsentError, match="HERMES_KANBAN_DB or HERMES_KANBAN_HOME"):
        broker_mod.resolve_board_db("two-homes")

    pinned = tmp_path / "pinned.db"
    monkeypatch.setenv("HERMES_KANBAN_DB", str(pinned))
    assert broker_mod.resolve_board_db("two-homes") == pinned

    monkeypatch.delenv("HERMES_KANBAN_DB")
    monkeypatch.setenv("HERMES_KANBAN_HOME", str(tmp_path))
    assert broker_mod.resolve_board_db("default") == tmp_path / "kanban.db"
    assert broker_mod.resolve_board_db("two-homes") == (
        tmp_path / "kanban" / "boards" / "two-homes" / "kanban.db")
    with pytest.raises(authority.ConsentError, match="invalid board slug"):
        broker_mod.resolve_board_db("../escape")


def test_admin_request_reader_refuses_unknown_fields_and_non_admin_methods():
    """Everything the root process is asked to send is bounded and typed first."""
    good = broker_mod.read_admin_request(io.StringIO('{"method": "register", "params": {}}'))
    assert good == {"method": "register", "params": {}}

    for payload in (
        '{"method": "worktree_status"}',            # read-only, not an admin method
        '{"method": "register", "extra": 1}',       # unknown field
        '{"method": "register", "params": []}',     # wrong type
        "[]",                                        # not an object
        '{"method": "register", "params": {"ttl": NaN}}',  # non-finite number
    ):
        with pytest.raises((broker_mod.BrokerError, proto.ProtocolError)):
            broker_mod.read_admin_request(io.StringIO(payload))


def test_bind_refuses_to_replace_a_symlink(short_socket_dir, tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("keep", encoding="utf-8")
    (short_socket_dir / ADMIN_SOCKET_NAME).symlink_to(victim)
    server = BrokerServer(socket_dir=short_socket_dir, db_path=tmp_path / "a.sqlite3")
    with pytest.raises(broker_mod.BrokerError, match="symlink"):
        server.start()
    assert victim.read_text(encoding="utf-8") == "keep"


def test_bind_refuses_a_socket_path_past_the_sun_path_limit(short_socket_dir, tmp_path):
    """A long path must fail loudly at bind time, never hang in the accept thread."""
    deep = short_socket_dir / ("d" * 100)
    with pytest.raises(broker_mod.BrokerError, match="AF_UNIX limit"):
        BrokerServer(socket_dir=deep, db_path=tmp_path / "a.sqlite3").start()


def test_serve_forever_requires_a_started_server(short_socket_dir, tmp_path):
    server = BrokerServer(socket_dir=short_socket_dir, db_path=tmp_path / "a.sqlite3")
    with pytest.raises(broker_mod.BrokerError, match="requires a started server"):
        serve_forever(server)


# ── end-to-end consent over the sockets ───────────────────────────────────
def _register_and_issue(server, worktree, socket_dir):
    ctx = _context(worktree)
    registered = admin_request("register", {
        "context": ctx, "dispatcher_pid": os.getpid()}, socket_dir=socket_dir)
    ctx = _context(worktree, registration_generation=registered["generation"])
    plan = preparer.prepare(
        "write_file", {"path": "plain.txt", "content": "alpha\nBETA\n", "cross_profile": False},
        ctx, worktree_root=worktree)
    issued = admin_request("issue", {
        "envelope": plan.envelope(), "descriptor": plan.descriptor, "ttl_seconds": 900,
        "confirmation": plan.descriptor_sha256}, socket_dir=socket_dir)
    return ctx, plan, issued


def test_register_issue_claim_finalize_round_trip(running_broker, worktree, short_socket_dir):
    socket_dir = short_socket_dir
    ctx, plan, issued = _register_and_issue(running_broker, worktree, short_socket_dir)

    found = lookup(plan.descriptor, ctx, socket_dir=socket_dir)
    assert found["status"] == "issued" and found["grant_id"] == issued["grant_id"]

    claimed = claim(issued["grant_id"], plan.descriptor, "txn-1", "d" * 64, ctx,
                    socket_dir=socket_dir)
    claim_id = claimed["receipt"]["claim_id"]
    assert claimed["receipt"]["state"] == "spent_pending"

    digest = plan.descriptor["paths"][0]["after_sha256"]
    settled = finalize(claim_id, "txn-1", "completed", {"plain.txt": digest}, ctx,
                       socket_dir=socket_dir)
    assert settled["receipt"]["outcome"] == "completed"
    assert lookup(plan.descriptor, ctx, socket_dir=socket_dir)["status"] == "terminal"


def test_duplicate_claim_over_the_socket_only_reads_the_receipt(running_broker, worktree,
                                                                short_socket_dir):
    socket_dir = short_socket_dir
    ctx, plan, issued = _register_and_issue(running_broker, worktree, short_socket_dir)
    first = claim(issued["grant_id"], plan.descriptor, "txn-1", "d" * 64, ctx,
                  socket_dir=socket_dir)
    replay = claim(issued["grant_id"], plan.descriptor, "txn-1", "d" * 64, ctx,
                   socket_dir=socket_dir)
    assert replay["replayed"] is True
    assert replay["receipt"]["claim_id"] == first["receipt"]["claim_id"]
    with pytest.raises(ConsentDenied, match="never re-execute"):
        claim(issued["grant_id"], plan.descriptor, "txn-2", "d" * 64, ctx,
              socket_dir=socket_dir)


def test_status_is_read_only_and_reports_unregistered(running_broker, worktree,
                                                      short_socket_dir):
    from tools.protected_write_client import worktree_status

    ctx = _context(worktree)
    status = worktree_status(ctx, socket_dir=short_socket_dir)
    assert status["status"] == "unregistered"
    assert status["correlations"] == []


# ── method/authority routing ──────────────────────────────────────────────
def test_admin_method_is_refused_on_the_consume_socket(running_broker, short_socket_dir):
    with pytest.raises(ConsentDenied, match="served only on the admin socket"):
        client_request(short_socket_dir / CONSUME_SOCKET_NAME, "issue", {})


def test_consume_method_is_refused_on_the_admin_socket(running_broker, short_socket_dir):
    with pytest.raises(ConsentDenied, match="served only on the consume socket"):
        admin_request("lookup", {}, socket_dir=short_socket_dir)


def test_unknown_method_and_malformed_frame_get_an_error_response(running_broker, short_socket_dir):
    with pytest.raises(ConsentDenied, match="unknown request method"):
        admin_request("grant_everything", {}, socket_dir=short_socket_dir)

    import socket as socket_module
    import struct

    with socket_module.socket(socket_module.AF_UNIX, socket_module.SOCK_STREAM) as raw:
        raw.settimeout(10)
        raw.connect(str(short_socket_dir / CONSUME_SOCKET_NAME))
        raw.sendall(struct.pack(">I", proto.MAX_MESSAGE_BYTES + 1))
        header = raw.recv(proto.FRAME_HEADER_BYTES)
        length = proto.decode_header(header)
        payload = raw.recv(length)
    response = proto.decode_payload(payload)
    assert response["ok"] is False
    assert "exceeds" in response["error"]


def test_unprivileged_peer_cannot_reach_an_admin_method(tmp_path, short_socket_dir):
    """The production default: SO_PEERCRED uid must be 0 for an admin method."""
    socket_dir = short_socket_dir
    server = BrokerServer(
        socket_dir=socket_dir, db_path=tmp_path / "authority.sqlite3",
        board_check=lambda _ctx: None)
    # The production default every other broker is built with.
    assert server.trust_local_admin is False
    with Harness(server, socket_dir):
        assert os.geteuid() != 0, "this test needs an unprivileged runner"
        with pytest.raises(ConsentDenied, match="uid == 0"):
            admin_request("active_holds", {}, socket_dir=socket_dir)


def test_launcher_exposes_no_switch_that_relaxes_admin_auth(short_socket_dir, tmp_path):
    """No command line turns a non-root peer into an admin peer."""
    with pytest.raises(SystemExit) as exit_info:
        broker_mod.main(["--socket-dir", str(short_socket_dir),
                         "--db", str(tmp_path / "a.sqlite3"),
                         "--foreground", "--no-root-required"])
    assert exit_info.value.code == 2
    with pytest.raises(SystemExit) as exit_info:
        broker_mod.main(["--trust-local-admin"])
    assert exit_info.value.code == 2


def test_foreign_process_cannot_claim_with_a_copied_context(running_broker, worktree,
                                                           short_socket_dir):
    socket_dir = short_socket_dir
    ctx, plan, issued = _register_and_issue(running_broker, worktree, short_socket_dir)
    # The child is a real second process with the SAME uid. It self-reports its own
    # kernel identity, so the socket-level context check passes and the store's
    # exact-PID rule is the guard that refuses it. A copied environment cannot help.
    script = (
        "import json, sys\n"
        "from tools.protected_write_client import claim, ConsentDenied\n"
        "from tools.protected_write_context import current_identity\n"
        "payload = json.loads(sys.stdin.read())\n"
        "mine = current_identity()\n"
        "ctx = dict(payload['context'])\n"
        "ctx.update(pid=mine.pid, start_ticks=mine.start_ticks, boot_id=mine.boot_id,\n"
        "           uid=mine.uid)\n"
        "assert mine.pid != payload['parent_pid'], 'the child must be a different pid'\n"
        "try:\n"
        "    claim(payload['grant_id'], payload['descriptor'], 'txn-x', 'd' * 64,\n"
        "          ctx, socket_dir=payload['socket_dir'])\n"
        "except ConsentDenied as exc:\n"
        "    print(f'DENIED {exc}')\n"
        "    raise SystemExit(0)\n"
        "print('ALLOWED')\n")
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}
    env.pop("JEST_WORKER_ID", None)
    result = subprocess.run(
        [sys.executable, "-c", script],
        input=json.dumps({"grant_id": issued["grant_id"], "descriptor": plan.descriptor,
                          "context": ctx, "socket_dir": str(socket_dir),
                          "parent_pid": ctx["pid"]}),
        capture_output=True, text=True, timeout=120, env=env, check=False)
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("DENIED"), result.stdout
    # The refusal lands on the strictest identity check that runs first; either
    # wording is the exact-identity rule, and "ALLOWED" would be the regression.
    assert "identity does not match" in result.stdout or "PID must EQUAL" in result.stdout


def test_restart_marks_an_unresolved_claim_recovery_only(tmp_path, worktree, short_socket_dir):
    """A restarted broker never lets a claim whose outcome was never settled execute."""
    socket_dir = short_socket_dir
    db_path = tmp_path / "authority.sqlite3"

    def _boot(name: str) -> Harness:
        # A restart reuses the authority database; a stale socket path from the
        # previous boot must not be mistaken for a live listener.
        return Harness(BrokerServer(
            socket_dir=socket_dir / name, db_path=db_path, board_check=lambda _ctx: None,
            trust_local_admin=True), socket_dir / name)

    with _boot("boot1") as first:
        ctx, plan, issued = _register_and_issue(first.server, worktree, socket_dir / "boot1")
        claimed = claim(issued["grant_id"], plan.descriptor, "txn-1", "d" * 64, ctx,
                        socket_dir=socket_dir / "boot1")

    with _boot("boot2") as restarted:
        holds = admin_request("active_holds", {}, socket_dir=socket_dir / "boot2")["holds"]
        assert [hold["claim_id"] for hold in holds] == [claimed["receipt"]["claim_id"]]
        # The same transaction only READS the receipt the dead broker left behind:
        # no fresh claim id, and the unresolved spend stays visible.
        replay = claim(issued["grant_id"], plan.descriptor, "txn-1", "d" * 64, ctx,
                       socket_dir=socket_dir / "boot2")
        assert replay["replayed"] is True
        assert replay["receipt"]["claim_id"] == claimed["receipt"]["claim_id"]
        assert replay["receipt"]["state"] == "spent_pending"
        # A different transaction can never obtain execution from that grant.
        with pytest.raises(ConsentDenied, match="never re-execute"):
            claim(issued["grant_id"], plan.descriptor, "txn-2", "d" * 64, ctx,
                  socket_dir=socket_dir / "boot2")


# ── immutable bundle ──────────────────────────────────────────────────────
def _safe_boundary(path: Path) -> Path:
    """The deepest non-writable ancestor of ``path``, so the walk can stop there.

    A test prefix lives under a shared temp root that no test may claim, so the
    ancestor check is rooted at the private part of the runner's tree instead.
    """
    current = path
    while True:
        writable = stat.S_IMODE(os.lstat(current).st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
        if not writable or current.parent == current:
            return current
        current = current.parent


def test_bundle_build_verify_and_tamper_detection(tmp_path):
    from scripts import protected_write_bundle as bundle

    prefix = tmp_path / "prefix"
    prefix.mkdir(mode=0o755)
    target = bundle.build(REPO_ROOT, prefix / bundle.BUNDLE_ROOT_REL)
    manifest = bundle.verify_bundle(target, boundary=_safe_boundary(prefix))
    assert manifest["artifact_sha256"] == target.name
    assert set(manifest["files"]) >= {
        "tools/protected_write_broker.py", "tools/protected_write_authority.py",
        bundle.BOOTSTRAP_NAME}
    listed = (target / bundle.MANIFEST_NAME).read_bytes()
    assert listed == bundle.canonical_manifest_bytes(manifest) + b"\n"

    # Same length, different bytes: the content hash check must catch it, not the size.
    victim = target / "tools/protected_write_broker.py"
    original = victim.read_bytes()
    victim.write_bytes(b"#" * len(original))
    with pytest.raises(bundle.BundleError, match="content hash mismatch"):
        bundle.verify_bundle(target, boundary=_safe_boundary(prefix))
    # A size change is caught by the size rule.
    victim.write_bytes(original + b"#")
    with pytest.raises(bundle.BundleError, match="size changed"):
        bundle.verify_bundle(target, boundary=_safe_boundary(prefix))


def test_bundle_rejects_a_writable_ancestor_and_a_symlinked_artifact(tmp_path):
    from scripts import protected_write_bundle as bundle

    prefix = tmp_path / "prefix"
    middle = prefix / "middle"
    middle.mkdir(parents=True, mode=0o755)
    os.chmod(prefix, 0o755)
    bundle_root = middle / bundle.BUNDLE_ROOT_REL
    target = bundle.build(REPO_ROOT, bundle_root)
    assert bundle.verify_bundle(target, boundary=_safe_boundary(prefix))

    os.chmod(middle, 0o777)
    with pytest.raises(bundle.BundleError, match="writable by group or other"):
        bundle.verify_bundle(target, boundary=_safe_boundary(prefix))
    os.chmod(middle, 0o755)

    # A symlinked artifact directory is refused even when its bytes verify.
    evil = bundle_root / "evil"
    evil.symlink_to(target)
    with pytest.raises(bundle.BundleError):
        bundle.verify_bundle(evil, boundary=_safe_boundary(prefix))


def test_bundle_missing_source_is_refused(tmp_path):
    from scripts import protected_write_bundle as bundle

    source = tmp_path / "src"
    source.mkdir()
    with pytest.raises(bundle.BundleError, match="is missing"):
        bundle.build(source, tmp_path / "bundle")


def test_bundle_cli_refuses_an_unsafe_prefix_by_default(tmp_path):
    """The CLI default walks to ``/``, so a world-writable temp prefix is rejected."""
    from scripts import protected_write_bundle as bundle

    prefix = tmp_path / "prefix"
    prefix.mkdir(mode=0o755)
    bundle.main(["--prefix", str(prefix), "build", "--source", str(REPO_ROOT)])
    command = (
        f"import sys; sys.path.insert(0, {str(REPO_ROOT)!r});"
        " from scripts import protected_write_bundle as b;"
        f" raise SystemExit(b.main(['--prefix', {str(prefix)!r}, 'verify']))")
    result = subprocess.run([sys.executable, "-c", command], capture_output=True,
                            text=True, timeout=120, check=False)
    assert result.returncode == 1
    assert "writable by group or other" in result.stderr


def test_bundle_cli_builds_verifies_and_reports_the_active_artifact(tmp_path):
    from scripts import protected_write_bundle as bundle

    prefix = tmp_path / "prefix"
    prefix.mkdir(mode=0o755)
    assert bundle.main(["--prefix", str(prefix), "build", "--source", str(REPO_ROOT)]) == 0
    built = json.loads(subprocess.run(
        [sys.executable, "-c",
         f"import sys; sys.path.insert(0, {str(REPO_ROOT)!r});"
         " from scripts import protected_write_bundle as b;"
         f" raise SystemExit(b.main(['--prefix', {str(prefix)!r}, 'verify',"
         f" '--boundary', {str(_safe_boundary(prefix))!r}]))"],
        capture_output=True, text=True, timeout=120, check=False).stdout or "{}")
    assert built.get("verified") is True
    assert bundle.main(["--prefix", str(prefix), "artifact-id"]) == 0


def test_install_launcher_is_executable_and_points_at_the_bundle(tmp_path):
    from scripts import protected_write_bundle as bundle

    bundle_root = tmp_path / "opt" / "hermes-protected-writes"
    target = bundle.build(REPO_ROOT, bundle_root)
    launcher = tmp_path / "usr" / "local" / "libexec" / "hermes-protected-write-admin"
    bundle.install_launcher(bundle_root, launcher)
    assert stat.S_IMODE(launcher.stat().st_mode) == 0o755
    text = launcher.read_text(encoding="utf-8")
    assert str(bundle_root) in text and bundle.BOOTSTRAP_NAME in text
    (bundle_root / bundle.CURRENT_POINTER).write_text(target.name, encoding="utf-8")
    assert bundle.main(["--prefix", str(tmp_path), "artifact-id"]) == 0


def test_main_build_verifies_only_what_it_created(tmp_path):
    """A build verifies its own artifact tree; the installer's ancestor walk stays the CLI default."""
    from scripts import protected_write_bundle as bundle

    prefix = tmp_path / "prefix"
    assert bundle.main(["--prefix", str(prefix), "build", "--source", str(REPO_ROOT)]) == 0
    assert (prefix / bundle.BUNDLE_ROOT_REL / bundle.CURRENT_POINTER).is_file()


def test_bundled_broker_verifies_its_own_hash_pin_before_doing_anything(tmp_path):
    """The pin is real only if the running process checks the bytes it is running."""
    from scripts import protected_write_bundle as bundle

    prefix = tmp_path / "prefix"
    target = bundle.build(REPO_ROOT, prefix / bundle.BUNDLE_ROOT_REL)
    bootstrap = target / bundle.BOOTSTRAP_NAME

    # Intact bundle: the pin verifies, and the launcher then refuses only because
    # this runner is not root. Any bundle complaint here would appear instead.
    def _run() -> subprocess.CompletedProcess:
        # Exactly how the launcher invokes it: isolated interpreter, no site, no
        # .pth, no PYTHONPATH — only the bundle and the standard library.
        return subprocess.run(
            [sys.executable, "-I", "-S", str(bootstrap), "--bundle", str(target),
             "--request", "-"],
            input="{}", capture_output=True, text=True, timeout=120, check=False)

    ok = _run()
    assert ok.returncode == broker_mod.EXIT_UNAVAILABLE, ok.stderr
    assert "requires root" in ok.stderr

    # A swapped module of the SAME length is caught by hash before a request is sent.
    victim = target / "tools" / "protected_write_protocol.py"
    victim.write_bytes(victim.read_bytes().replace(b"MAX_PATHS = 32", b"MAX_PATHS = 64"))
    tampered = _run()
    assert tampered.returncode == broker_mod.EXIT_UNAVAILABLE, tampered.stdout
    assert "content hash mismatch" in tampered.stderr