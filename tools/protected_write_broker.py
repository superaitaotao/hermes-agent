"""Root broker over Unix domain sockets for protected-write consent.

Two sockets under ``/run/hermes-protected-writes``:

* ``admin.sock``  — root-only. SO_PEERCRED ``uid == 0`` authenticates the admin;
  the JSON body never does. A root-registered cancel-only dispatcher peer may also
  connect and call exactly one method.
* ``consume.sock`` — the worker. The peer PID must EQUAL the registered worker PID
  with matching uid, boot id and start ticks: there is no descendant allowance, and
  a copied environment is rejected because the kernel, not the payload, reports the
  peer.

One request per connection: a single length-prefixed v1 message, then one response.
The broker never reads a request-supplied path on the worker's behalf for privilege
reasons; the deterministic preparer runs as the worker (see ``protected_write_preparer``).

D1 scope: the broker and its contract. Nothing integrates it into a write path;
D2 owns that.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import socket
import stat
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from tools import protected_write_protocol as proto
from tools.protected_write_authority import (
    AuthorityStore, ConsentError, DEFAULT_DB_PATH, StoreUnavailable,
    dispatcher_fingerprint_for,
)
from tools.protected_write_context import (
    ExecutionIdentity, IdentityError, process_identity,
)

#: The bundle manifest schema this broker can verify itself against.
BUNDLE_MANIFEST_SCHEMA = "protected-write-bundle-v1"
DEFAULT_SOCKET_DIR = "/run/hermes-protected-writes"
ADMIN_SOCKET_NAME = "admin.sock"
CONSUME_SOCKET_NAME = "consume.sock"
#: ``sockaddr_un.sun_path`` is 108 bytes on Linux including the terminating NUL.
MAX_SOCKET_PATH_BYTES = 108

#: Exit codes the launcher reports so an operator can distinguish failure modes.
EXIT_OK = 0
EXIT_USAGE = 2
EXIT_UNAVAILABLE = 3

_SO_PEERCRED = getattr(socket, "SO_PEERCRED", None)


class BrokerError(RuntimeError):
    """The request cannot be served. Every ambiguous state is refused."""


# ── request schemas ───────────────────────────────────────────────────────
_CONTEXT = ("object:context", True)
_DESCRIPTOR = ("object:descriptor", True)
_DIGEST = ("digest", True)
_SHORT = ("short_str", True)

REQUEST_SCHEMAS: dict[str, dict[str, tuple[str, bool]]] = {
    "register": {
        "context": _CONTEXT,  # carries the board the run belongs to
        "dispatcher_pid": ("non_negative_int", True),
    },
    "register_cancel_peer": {
        "generation": ("non_negative_int", True),
        "peer_pid": ("non_negative_int", True),
    },
    "issue": {
        "envelope": ("object:envelope", True),
        "descriptor": _DESCRIPTOR,
        "ttl_seconds": ("ttl", True),
        "confirmation": ("reason", True),
    },
    "revoke": {"grant_id": _SHORT, "reason": ("reason", True)},
    "cancel_generation": {"generation": ("non_negative_int", True), "reason": ("reason", True)},
    "recovery_status": {"claim_id": _SHORT},
    "recover": {
        "claim_id": _SHORT,
        "verified": ("action", False),  # re-checked below against the recovery set
        "readback": ("object:readback", False),
        "reason": ("reason", True),
    },
    "clear_hold": {"hold_id": _SHORT, "reason": ("reason", True)},
    "active_holds": {},
    "lookup": {"context": _CONTEXT, "descriptor": _DESCRIPTOR},
    "claim": {
        "context": _CONTEXT,
        "descriptor": _DESCRIPTOR,
        "grant_id": _SHORT,
        "transaction_id": _SHORT,
        "journal_digest": _DIGEST,
    },
    "finalize": {
        "context": _CONTEXT,
        "claim_id": _SHORT,
        "transaction_id": _SHORT,
        "outcome": ("short_str", True),
        "readback": ("object:readback", True),
    },
    "worktree_status": {"identity": _CONTEXT},
}

#: Methods served on the root-only admin socket (SO_PEERCRED uid == 0).
ADMIN_METHODS = frozenset({
    "register", "register_cancel_peer", "issue", "revoke", "cancel_generation",
    "recovery_status", "recover", "clear_hold", "active_holds",
})
#: Methods served on the consume socket to the identity-matched worker.
CONSUME_METHODS = frozenset({"lookup", "claim", "finalize", "worktree_status"})
#: The one method a root-registered cancel-only dispatcher peer may call.
CANCEL_ONLY_METHODS = frozenset({"cancel_generation"})
#: Read-only, authority-free: reachable from either socket without a registration.
READ_ONLY_METHODS = frozenset({"worktree_status", "active_holds"})


@dataclass
class PeerContext:
    identity: ExecutionIdentity
    is_root: bool
    fingerprint: str


# ── default read-only board adapter ───────────────────────────────────────
def resolve_board_db(board: str) -> Path:
    """The board database path, resolved WITHOUT importing the worker checkout.

    The broker runs from the immutable bundle, so it must never import
    ``hermes_cli`` (a worker-writable checkout is not an authority). This mirrors
    ``hermes_cli.kanban_db.kanban_db_path`` for the documented overrides:
    ``HERMES_KANBAN_DB`` pins the file, otherwise ``HERMES_KANBAN_HOME`` locates
    the board. Anything unresolvable DENIES; there is no default-allow path.
    """
    import re

    override = os.environ.get("HERMES_KANBAN_DB", "").strip()
    if override:
        return Path(override).expanduser()
    home = os.environ.get("HERMES_KANBAN_HOME", "").strip()
    if not home:
        raise ConsentError(
            "the broker needs HERMES_KANBAN_DB or HERMES_KANBAN_HOME to read a board")
    root = Path(home).expanduser()
    slug = str(board).strip().lower()
    if slug in ("", "default"):
        return root / "kanban.db"
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", slug):
        raise ConsentError(f"invalid board slug {board!r}")
    return root / "kanban" / "boards" / slug / "kanban.db"


def default_board_check(context: Mapping[str, Any]) -> None:
    """Cooperative evidence only: the card is running and owns the stated run.

    The board is editable by the same uid, so this proves the caller consulted it,
    never that the run is authentic. A missing or unreadable board DENIES.
    """
    import sqlite3

    db_path = resolve_board_db(str(context["board"]))
    if not db_path.exists():
        raise ConsentError(f"board database {db_path} does not exist")
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "SELECT status, assignee, current_run_id, workspace_path FROM tasks WHERE id = ?",
                (str(context["card"]),)).fetchone()
        finally:
            conn.close()
    except sqlite3.Error as exc:
        raise ConsentError(f"cannot read the board database read-only: {exc}") from exc
    if row is None:
        raise ConsentError(f"card {context['card']} is not on board {context['board']}")
    if row["status"] != "running":
        raise ConsentError(f"card {context['card']} is {row['status']}, not running")
    run = str(context["run"])
    stored_run = row["current_run_id"]
    if stored_run is not None and run.isdigit() and int(run) != int(stored_run):
        raise ConsentError(
            f"card {context['card']} current run is {stored_run}, not the presented run {run}")


# ── server ────────────────────────────────────────────────────────────────
class BrokerServer:
    """One process, two sockets, no per-connection state."""

    def __init__(
        self,
        *,
        socket_dir: os.PathLike[str] | str = DEFAULT_SOCKET_DIR,
        db_path: os.PathLike[str] | str = DEFAULT_DB_PATH,
        board_check: Callable[[Mapping[str, Any]], None] | None = None,
        trust_local_admin: bool = False,
    ):
        self.socket_dir = Path(socket_dir)
        self.db_path = Path(db_path)
        self.board_check = board_check or default_board_check
        # Trusted-local mode exists for an in-process broker owned by one user (the
        # test harness). It is not reachable from the launcher and never widens the
        # kernel's answer; it only supplies the missing uid==0 peer there is none of.
        self.trust_local_admin = trust_local_admin
        self.store: AuthorityStore | None = None
        self._listeners: list[socket.socket] = []
        self._closing = False
        self._wakeup: tuple[int, int] | None = None

    # -- lifecycle ------------------------------------------------------
    def start(self) -> None:
        if self.store is None:
            self.store = AuthorityStore(self.db_path)
            try:
                self.store.open()
            except StoreUnavailable as exc:
                raise BrokerError(f"authority store unavailable: {exc}") from exc
            # Every unresolved claim is recovery-only BEFORE the consume socket opens.
            unresolved = self.store.mark_restart_recovery()
            if unresolved:
                print(
                    f"broker: {unresolved} unresolved claim(s) are recovery-only until an "
                    "admin settles them", file=sys.stderr, flush=True)
        self.socket_dir.mkdir(parents=True, exist_ok=True)
        # Root-owned and NOT writable by group or other: no unprivileged process can
        # replace, unlink or shadow a socket in here. It stays traversable (0755)
        # because the worker must reach consume.sock; traversal alone grants nothing,
        # since the admin socket is 0600 and the broker authenticates every peer by
        # kernel credentials rather than by file permission.
        os.chmod(self.socket_dir, 0o755)
        # A self-pipe wakes the accept loop at shutdown: closing a listener does not
        # wake an epoll_wait on Linux, so a bare close would leave the loop blocked.
        if self._wakeup is None:
            read_fd, write_fd = os.pipe()
            os.set_blocking(read_fd, False)
            os.set_blocking(write_fd, False)
            self._wakeup = (read_fd, write_fd)
        # Bind here, not in the accept loop: a bind failure must reach the operator.
        self.open_admin_socket()
        self.open_consume_socket()

    @property
    def closing(self) -> bool:
        """True once :meth:`stop` asked the accept loop to end; a stop is not a failure."""
        return self._closing

    def request_stop(self) -> None:
        """End the accept loop. Safe from another thread: it never touches the store."""
        self._closing = True
        if self._wakeup is not None:
            try:
                os.write(self._wakeup[1], b"x")
            except OSError:
                pass
        for listener in self._listeners:
            try:
                listener.close()
            except OSError:
                pass
        self._listeners = []

    def stop(self) -> None:
        """Close the listeners, the wakeup pipe and the store; same thread as start()."""
        self.request_stop()
        if self._wakeup is not None:
            for fd in self._wakeup:
                try:
                    os.close(fd)
                except OSError:
                    pass
            self._wakeup = None
        if self.store is not None:
            self.store.close()
            self.store = None

    # -- socket helpers -------------------------------------------------
    @staticmethod
    def _bind(path: Path, mode: int) -> socket.socket:
        # sun_path is a fixed 108-byte field: a longer path truncates or fails, so
        # refuse it here where the operator sees a clear reason.
        if len(os.fsencode(path)) >= MAX_SOCKET_PATH_BYTES:
            raise BrokerError(
                f"socket path {path} exceeds the {MAX_SOCKET_PATH_BYTES - 1}-byte AF_UNIX "
                "limit; use a shorter --socket-dir")
        if path.exists() or path.is_symlink():
            if path.is_symlink():
                raise BrokerError(f"refusing to replace a symlink at {path}")
            path.unlink()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(path))
        os.chmod(path, mode)
        listener.listen(64)
        return listener

    def open_admin_socket(self) -> socket.socket:
        listener = self._bind(self.socket_dir / ADMIN_SOCKET_NAME, 0o600)
        self._listeners.append(listener)
        return listener

    def open_consume_socket(self) -> socket.socket:
        # Any uid may connect; the broker authenticates the peer by SO_PEERCRED
        # (exact PID + uid) against the registration, so the file mode is not the
        # authority and must not be the thing that breaks the worker's access.
        listener = self._bind(self.socket_dir / CONSUME_SOCKET_NAME, 0o666)
        self._listeners.append(listener)
        return listener

    # -- peer identity --------------------------------------------------
    @staticmethod
    def _peer_credentials(conn: socket.socket) -> tuple[int, int]:
        if _SO_PEERCRED is None:
            raise BrokerError("SO_PEERCRED is unavailable on this platform; refusing")
        raw = conn.getsockopt(socket.SOL_SOCKET, _SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", raw)
        return _pid, uid

    def peer_context(self, conn: socket.socket) -> PeerContext:
        pid, uid = self._peer_credentials(conn)
        try:
            identity = process_identity(pid, exotic_uid=uid)
        except IdentityError as exc:
            raise BrokerError(f"cannot read the peer's kernel identity: {exc}") from exc
        return PeerContext(
            identity=identity, is_root=(uid == 0),
            fingerprint=dispatcher_fingerprint_for(identity))

    # -- framing --------------------------------------------------------
    @staticmethod
    def _read_message(conn: socket.socket) -> dict:
        header = _recv_exactly(conn, proto.FRAME_HEADER_BYTES)
        length = proto.decode_header(header)
        payload = _recv_exactly(conn, length)
        message = proto.decode_payload(payload)
        if not isinstance(message, dict):
            raise proto.ProtocolError("message must be a JSON object")
        return message

    @staticmethod
    def _write_message(conn: socket.socket, message: Mapping[str, Any]) -> None:
        conn.sendall(proto.encode_frame(dict(message)))

    # -- dispatch -------------------------------------------------------
    def handle(self, conn: socket.socket, *, socket_kind: str) -> dict:
        peer = self.peer_context(conn)
        try:
            message = self._read_message(conn)
        except proto.ProtocolError as exc:
            return {"schema_version": proto.SCHEMA_VERSION, "ok": False, "error": str(exc)}
        try:
            return self._dispatch(message, peer, socket_kind=socket_kind)
        except (ConsentError, BrokerError, proto.ProtocolError) as exc:
            return {"schema_version": proto.SCHEMA_VERSION, "ok": False, "error": str(exc)}
        except Exception as exc:  # never leak a traceback into a security decision
            return {"schema_version": proto.SCHEMA_VERSION, "ok": False,
                    "error": f"internal broker error: {type(exc).__name__}"}

    def _dispatch(self, message: Mapping[str, Any], peer: PeerContext, *,
                  socket_kind: str) -> dict:
        method = message.get("method")
        if not isinstance(method, str) or method not in REQUEST_SCHEMAS:
            raise BrokerError(f"unknown request method {method!r}")
        if method in ADMIN_METHODS and socket_kind != "admin":
            raise BrokerError(f"{method} is served only on the admin socket")
        if method in CONSUME_METHODS and socket_kind != "consume":
            raise BrokerError(f"{method} is served only on the consume socket")
        if method in ADMIN_METHODS and not self.is_admin_peer(peer):
            # The kernel's SO_PEERCRED uid is the only admin authority in production.
            raise BrokerError("admin requests require SO_PEERCRED uid == 0")

        params = proto.validate_fields(
            message.get("params", {}), REQUEST_SCHEMAS[method], where=f"{method}.params")
        handler = _HANDLERS[method]
        return handler(self, params, peer)

    # -- handlers -------------------------------------------------------
    def is_admin_peer(self, peer: PeerContext) -> bool:
        """The one admin answer: the kernel says uid 0, or this broker is trusted-local."""
        return peer.is_root or self.trust_local_admin

    def _require_store(self) -> AuthorityStore:
        if self.store is None:
            raise StoreUnavailable("authority store is not open; refusing")
        return self.store

    def h_register(self, params: dict, peer: PeerContext) -> dict:
        ctx = proto.validate_context(params["context"])
        dispatcher_pid = int(params["dispatcher_pid"])
        try:
            dispatcher = process_identity(dispatcher_pid)
        except IdentityError as exc:
            raise BrokerError(f"dispatcher pid {dispatcher_pid} is not readable: {exc}") from exc
        if dispatcher.uid != ctx["uid"]:
            raise BrokerError("dispatcher uid does not match the worker uid")
        result = self._require_store().register(
            ctx, dispatcher_fingerprint_for(dispatcher), dispatcher=dispatcher,
            board_check=self.board_check)
        return {"ok": True, **result}

    def h_register_cancel_peer(self, params: dict, peer: PeerContext) -> dict:
        target = process_identity(int(params["peer_pid"]))
        result = self._require_store().register_cancel_peer(
            target, int(params["generation"]), admin=self.is_admin_peer(peer))
        return {"ok": True, **result}

    def h_issue(self, params: dict, peer: PeerContext) -> dict:
        result = self._require_store().issue(
            params["envelope"], params["descriptor"], int(params["ttl_seconds"]),
            params["confirmation"], peer.identity, admin=self.is_admin_peer(peer))
        return {"ok": True, **result}

    def h_revoke(self, params: dict, peer: PeerContext) -> dict:
        return {"ok": True, **self._require_store().revoke(
            params["grant_id"], params["reason"], admin=self.is_admin_peer(peer))}

    def h_cancel_generation(self, params: dict, peer: PeerContext) -> dict:
        admin = self.is_admin_peer(peer)
        return {"ok": True, **self._require_store().cancel_generation(
            int(params["generation"]), params["reason"],
            admin=admin, cancel_peer=None if admin else peer.identity)}

    def h_recovery_status(self, params: dict, peer: PeerContext) -> dict:
        return {"ok": True, **self._require_store().recovery_status(params["claim_id"])}

    def h_recover(self, params: dict, peer: PeerContext) -> dict:
        verified = params.get("verified")
        if verified not in ("after", "before", "conflict"):
            raise BrokerError("recover.verified must be one of after, before, conflict")
        return {"ok": True, **self._require_store().recover(
            params["claim_id"], verified, params.get("readback") or {}, params["reason"],
            admin=self.is_admin_peer(peer))}

    def h_clear_hold(self, params: dict, peer: PeerContext) -> dict:
        return {"ok": True, **self._require_store().clear_hold(
            params["hold_id"], params["reason"], admin=self.is_admin_peer(peer))}

    def h_active_holds(self, params: dict, peer: PeerContext) -> dict:
        return {"ok": True, "holds": self._require_store().active_holds()}

    def h_lookup(self, params: dict, peer: PeerContext) -> dict:
        ctx = self._bind_worker_context(params["context"], peer)
        return {"ok": True, **self._require_store().lookup(params["descriptor"], ctx, peer.identity)}

    def h_claim(self, params: dict, peer: PeerContext) -> dict:
        ctx = self._bind_worker_context(params["context"], peer)
        return {"ok": True, **self._require_store().claim(
            params["grant_id"], params["descriptor"], params["transaction_id"],
            params["journal_digest"], ctx, peer.identity)}

    def h_finalize(self, params: dict, peer: PeerContext) -> dict:
        ctx = self._bind_worker_context(params["context"], peer)
        return {"ok": True, **self._require_store().finalize(
            params["claim_id"], params["transaction_id"], params["outcome"],
            params["readback"], ctx, peer.identity)}

    def h_worktree_status(self, params: dict, peer: PeerContext) -> dict:
        identity = params["identity"]
        ctx = proto.validate_context(identity)
        # The kernel's answer wins over the payload for the identity fields.
        live = dict(ctx, uid=peer.identity.uid, pid=peer.identity.pid,
                    boot_id=peer.identity.boot_id, start_ticks=peer.identity.start_ticks)
        return {"ok": True, **self._require_store().worktree_status(live)}

    @staticmethod
    def _bind_worker_context(context: Mapping[str, Any], peer: PeerContext) -> dict:
        ctx = proto.validate_context(dict(context))
        live = peer.identity
        for field, value in (
            ("uid", live.uid), ("pid", live.pid),
            ("boot_id", live.boot_id), ("start_ticks", live.start_ticks),
        ):
            if ctx[field] != value:
                raise BrokerError(
                    f"context.{field} does not match the kernel-reported peer identity")
        return ctx


_HANDLERS: dict[str, Callable[[BrokerServer, dict, PeerContext], dict]] = {
    "register": BrokerServer.h_register,
    "register_cancel_peer": BrokerServer.h_register_cancel_peer,
    "issue": BrokerServer.h_issue,
    "revoke": BrokerServer.h_revoke,
    "cancel_generation": BrokerServer.h_cancel_generation,
    "recovery_status": BrokerServer.h_recovery_status,
    "recover": BrokerServer.h_recover,
    "clear_hold": BrokerServer.h_clear_hold,
    "active_holds": BrokerServer.h_active_holds,
    "lookup": BrokerServer.h_lookup,
    "claim": BrokerServer.h_claim,
    "finalize": BrokerServer.h_finalize,
    "worktree_status": BrokerServer.h_worktree_status,
}


def _recv_exactly(conn: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining > 0:
        chunk = conn.recv(remaining)
        if not chunk:
            raise proto.ProtocolError("connection closed mid-frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def serve_one_request(server: BrokerServer, conn: socket.socket, *, socket_kind: str) -> None:
    with conn:
        try:
            response = server.handle(conn, socket_kind=socket_kind)
        except BrokerError as exc:
            response = {"schema_version": proto.SCHEMA_VERSION, "ok": False, "error": str(exc)}
        try:
            server._write_message(conn, response)
        except OSError:
            pass


def serve_forever(server: BrokerServer) -> int:
    """Accept on both bound sockets until interrupted. Returns an exit code."""
    if not server._listeners:  # noqa: SLF001 - start() binds them; a bare call fails closed
        raise BrokerError("serve_forever requires a started server (call start() first)")
    admin, consume = server._listeners[0], server._listeners[1]  # noqa: SLF001
    import selectors

    selector = selectors.DefaultSelector()
    selector.register(admin, selectors.EVENT_READ, "admin")
    selector.register(consume, selectors.EVENT_READ, "consume")
    if server._wakeup is not None:  # noqa: SLF001 - the shutdown wakeup pipe
        selector.register(server._wakeup[0], selectors.EVENT_READ, "stop")  # noqa: SLF001
    print(f"broker: admin={server.socket_dir / ADMIN_SOCKET_NAME} "
          f"consume={server.socket_dir / CONSUME_SOCKET_NAME}", file=sys.stderr, flush=True)
    try:
        while True:
            for key, _events in selector.select():
                if key.data == "stop":
                    return EXIT_OK
                listener = key.fileobj
                assert isinstance(listener, socket.socket)
                try:
                    conn, _addr = listener.accept()
                except OSError as exc:
                    if server.closing:
                        return EXIT_OK
                    if exc.errno in (errno.EINTR, errno.EAGAIN):
                        continue
                    raise
                serve_one_request(server, conn, socket_kind=key.data)
    except KeyboardInterrupt:
        return EXIT_OK
    finally:
        selector.close()
        server.stop()


def verify_running_bundle(bundle_dir: os.PathLike[str] | str) -> dict:
    """Refuse to serve unless THIS process is the hash-pinned bundle on disk.

    The launcher passes ``--bundle``; verifying it at startup is what makes the
    pin real. A worker-writable copy of the same code is not the authority, and a
    swapped module is caught before the sockets open.
    """
    import hashlib

    root = Path(bundle_dir).resolve()
    here = Path(__file__).resolve().parent
    if here.parent != root:
        raise BrokerError(f"running code {here.parent} is not the bundle {root}")
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        raise BrokerError(f"{manifest_path} is missing")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BrokerError(f"cannot read {manifest_path}: {exc}") from exc
    if manifest.get("schema_version") != BUNDLE_MANIFEST_SCHEMA:
        raise BrokerError(f"unknown bundle manifest schema {manifest.get('schema_version')!r}")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise BrokerError("bundle manifest carries no files")
    for rel, entry in sorted(files.items()):
        path = root / rel
        if not path.is_file() or path.is_symlink():
            raise BrokerError(f"{rel} is missing or is a symlink")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != entry.get("sha256"):
            raise BrokerError(f"{rel} content hash mismatch")
    return manifest


def read_admin_request(stream: Any) -> dict:
    """Read exactly one bounded admin request from a stream (stdin, never a path).

    The launcher never opens a request-supplied FILE: a root process must not be
    talked into reading an arbitrary path. Unknown or duplicate fields, a bad type
    and an oversized body are all refused before anything is sent.
    """
    raw = stream.read(proto.MAX_MESSAGE_BYTES + 1)
    if len(raw) > proto.MAX_MESSAGE_BYTES:
        raise BrokerError(f"request exceeds the {proto.MAX_MESSAGE_BYTES}-byte bound")
    value = proto.parse_json_strict(raw)
    if not isinstance(value, dict):
        raise BrokerError("request must be a JSON object")
    unknown = sorted(set(value) - {"method", "params"})
    if unknown:
        raise BrokerError(f"request has unknown field(s): {', '.join(unknown)}")
    method = value.get("method")
    if not isinstance(method, str) or method not in ADMIN_METHODS:
        raise BrokerError(f"not an admin method: {method!r}")
    params = value.get("params", {})
    if not isinstance(params, dict):
        raise BrokerError("'params' must be a JSON object")
    return {"method": method, "params": params}


def admin_request_main(argv: list[str]) -> int:
    """One root admin request from stdin; prints the sanitized receipt as JSON."""
    parser = argparse.ArgumentParser(
        prog="hermes-protected-write-admin --request",
        description="Send exactly one admin request (read from stdin) to the broker.")
    parser.add_argument("--socket-dir", default=DEFAULT_SOCKET_DIR)
    parser.add_argument("--bundle", default=None,
                        help="verify this immutable bundle before sending anything")
    parser.add_argument("--request", default="-", metavar="-",
                        help="read the bounded request JSON from stdin (only '-' is accepted)")
    args = parser.parse_args(argv)
    if args.bundle is not None:
        try:
            verify_running_bundle(args.bundle)
        except BrokerError as exc:
            print(f"protected-write: {exc}", file=sys.stderr)
            return EXIT_UNAVAILABLE
    if args.request != "-":
        print("protected-write: the admin request is read from stdin only "
              "(pass --request -); no request-file path is accepted", file=sys.stderr)
        return EXIT_USAGE
    # The peer credential is the authority; this guard only makes the failure
    # legible instead of letting a non-root shell read a socket-level refusal.
    if os.geteuid() != 0:
        print("protected-write: the admin request path requires root", file=sys.stderr)
        return EXIT_UNAVAILABLE
    try:
        payload = read_admin_request(sys.stdin)
    except (BrokerError, proto.ProtocolError) as exc:
        print(f"protected-write: {exc}", file=sys.stderr)
        return EXIT_USAGE
    from tools.protected_write_client import ClientError, admin_request as send_admin_request

    try:
        response = send_admin_request(payload["method"], payload["params"],
                                     socket_dir=args.socket_dir)
    except ClientError as exc:
        print(f"protected-write: refused: {exc}", file=sys.stderr)
        return EXIT_UNAVAILABLE
    # Receipts are sanitized (descriptors, digests, states) and never carry request
    # content, so there is no untrusted text to render here.
    print(json.dumps(response, indent=2, sort_keys=True))
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    """Entry point used by the immutable admin launcher (root) and by tests."""
    raw = list(sys.argv[1:] if argv is None else argv)
    if "--request" in raw:
        return admin_request_main(raw)
    parser = argparse.ArgumentParser(
        prog="hermes-protected-write-admin",
        description="Root broker for protected-write consent (D1: mechanism only).")
    parser.add_argument("--socket-dir", default=DEFAULT_SOCKET_DIR)
    parser.add_argument("--db", default=DEFAULT_DB_PATH)
    parser.add_argument("--bundle", default=None,
                        help="verify this immutable bundle before opening a socket")
    parser.add_argument("--foreground", action="store_true",
                        help="serve until interrupted (the only supported mode)")
    args = parser.parse_args(raw)
    if args.bundle is not None:
        try:
            verify_running_bundle(args.bundle)
        except BrokerError as exc:
            print(f"protected-write: {exc}", file=sys.stderr)
            return EXIT_UNAVAILABLE

    # The launcher has no switch that relaxes admin authentication: a non-root peer
    # can never reach an admin method through this entry point.
    server = BrokerServer(socket_dir=args.socket_dir, db_path=args.db)
    try:
        server.start()
    except BrokerError as exc:
        print(f"broker: {exc}", file=sys.stderr)
        return EXIT_UNAVAILABLE
    if not args.foreground:
        print("broker: only --foreground is supported (nothing runs in the background)",
              file=sys.stderr)
        return EXIT_USAGE
    return serve_forever(server)


if __name__ == "__main__":  # pragma: no cover - exercised through the launcher
    raise SystemExit(main())
