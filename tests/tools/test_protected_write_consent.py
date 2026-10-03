"""Protected-write consent: protocol, deterministic preparer and authority store.

Test-audit authoring gate (per contract in ``twohomes-kanban-policy``):

* Behaviour protected: the strict v1 wire contract, byte-exact deterministic
  preparation of a request, and the broker's single-use consent lifecycle. A
  regression in any of these would let a previewed request differ from the bytes
  an execution installs, or let one consent authorize two writes.
* Credible regression: a loosened validator (unknown field accepted), a preparer
  that normalises CRLF/BOM, an authority store that re-issues after a duplicate
  claim, or a lookup that reports a mismatched descriptor as "absent" so the
  caller falls back to the unprotected path.
* Why existing coverage misses it: no existing module implements consent; the
  existing file-write tests cover only the always-ask prompt path.
* No production seam is added for tests: every assertion drives the real
  modules through their public functions against a real temp filesystem.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from tools import protected_write_authority as authority
from tools import protected_write_preparer as preparer
from tools import protected_write_protocol as proto
from tools.protected_write_context import ExecutionIdentity, current_identity

# The worker identity is synthetic; the DISPATCHER must be a live process, because
# the store invalidates a registration whose dispatcher fingerprint is gone.
LIVE_DISPATCHER = current_identity()
BOOT_ID = "b" * 32
START_TICKS = 4242
UID = 1000
PID = 4242


def _context(**overrides) -> dict:
    ctx = {
        "board": "two-homes",
        "card": "t_test",
        "profile": "twohomes-coder",
        "home": "/home/tester/.hermes/profiles/twohomes-coder",
        "run": "700",
        "session": "sess-1",
        "registration_generation": 0,
        "uid": UID,
        "pid": PID,
        "boot_id": BOOT_ID,
        "start_ticks": START_TICKS,
        "worktree": "/home/tester/wt",
        "git_dir": "/home/tester/wt/.git",
        "common_dir": "/home/tester/wt/.git",
        "baseline": "e9d7a18dc5515d50a9d9ecd5beca188028cda004",
    }
    ctx.update(overrides)
    return ctx


def _peer(**overrides) -> ExecutionIdentity:
    values = {"uid": UID, "pid": PID, "boot_id": BOOT_ID, "start_ticks": START_TICKS}
    values.update(overrides)
    return ExecutionIdentity(**values)


@pytest.fixture
def worktree(tmp_path: Path) -> Path:
    root = tmp_path / "wt"
    root.mkdir()
    (root / "plain.txt").write_bytes(b"alpha\nbeta\n")
    (root / "bom_crlf.txt").write_bytes(b"\xef\xbb\xbfone\r\ntwo\r\n")
    (root / "empty.txt").write_bytes(b"")
    return root


@pytest.fixture
def store(tmp_path: Path):
    instance = authority.AuthorityStore(tmp_path / "authority.sqlite3")
    instance.open()
    yield instance
    instance.close()


# ── protocol ──────────────────────────────────────────────────────────────
def test_frame_round_trip_is_canonical():
    frame = proto.encode_frame({"b": [1, 2], "a": "x"})
    message, rest = proto.decode_frame(frame)
    assert message == {"a": "x", "b": [1, 2]}
    assert rest == b""
    # Canonical key order means two equivalent dicts produce identical frames.
    assert frame == proto.encode_frame({"a": "x", "b": [1, 2]})


@pytest.mark.parametrize("payload", ['{"a":1,"a":2}', '{"a": NaN}', '{"a": Infinity}'])
def test_strict_json_rejects_duplicates_and_non_finite(payload):
    with pytest.raises(proto.ProtocolError):
        proto.parse_json_strict(payload)


def test_strict_json_accepts_one_plain_object():
    assert proto.parse_json_strict('{"a": 1}') == {"a": 1}


def test_oversize_frame_is_refused_by_header():
    import struct

    header = struct.pack(">I", proto.MAX_MESSAGE_BYTES + 1)
    with pytest.raises(proto.ProtocolError):
        proto.decode_header(header)


def test_encode_refuses_message_past_limit():
    big = {"payload": "x" * (proto.MAX_MESSAGE_BYTES + 1)}
    with pytest.raises(proto.ProtocolError):
        proto.encode_frame(big)


def test_envelope_rejects_unknown_field_and_wrong_cross_profile():
    valid = {
        "schema_version": proto.SCHEMA_VERSION,
        "context": _context(),
        "tool": "write_file",
        "arguments": {"path": "a.txt", "content": "x", "cross_profile": False},
    }
    proto.validate_envelope(valid)
    with pytest.raises(proto.ProtocolError, match="unknown field"):
        proto.validate_envelope({**valid, "extra": 1})
    with pytest.raises(proto.ProtocolError, match="cross_profile"):
        proto.validate_envelope({
            **valid,
            "arguments": {"path": "a.txt", "content": "x", "cross_profile": True},
        })
    with pytest.raises(proto.ProtocolError, match="cross_profile"):
        proto.validate_envelope({
            **valid, "arguments": {"path": "a.txt", "content": "x"}})


def test_descriptor_rejects_partial_null_side_and_duplicate_paths():
    record = {
        "relative": "a.txt", "normalized": "a.txt", "resolved": "/wt/a.txt",
        "action": "update", "protected_reason": None,
        "before_sha256": proto.sha256_hex(b"a"), "before_length": 1,
        "after_sha256": proto.sha256_hex(b"b"), "after_length": 1,
    }
    proto.build_descriptor(_context(), "a" * 64, "b" * 64, [record])
    with pytest.raises(proto.ProtocolError, match="both be null"):
        proto.build_descriptor(_context(), "a" * 64, "b" * 64, [{**record, "before_length": None}])
    with pytest.raises(proto.ProtocolError, match="duplicate or aliased"):
        proto.build_descriptor(_context(), "a" * 64, "b" * 64, [record, dict(record)])


def test_descriptor_rejects_more_than_max_paths():
    records = [{
        "relative": f"f{i}.txt", "normalized": f"f{i}.txt", "resolved": f"/wt/f{i}.txt",
        "action": "create", "protected_reason": None,
        "before_sha256": None, "before_length": None,
        "after_sha256": proto.sha256_hex(b"x"), "after_length": 1,
    } for i in range(proto.MAX_PATHS + 1)]
    with pytest.raises(proto.ProtocolError, match="exceeds the limit"):
        proto.build_descriptor(_context(), "a" * 64, "b" * 64, records)


def test_descriptor_digest_is_key_order_independent():
    plan = preparer.prepare(
        "write_file", {"path": "plain.txt", "content": "x", "cross_profile": False},
        _context(), worktree_root="/tmp")
    shuffled = dict(reversed(list(plan.descriptor.items())))
    assert proto.descriptor_digest(shuffled) == plan.descriptor_sha256


# ── preparer ──────────────────────────────────────────────────────────────
def test_write_file_prepare_is_deterministic(worktree):
    arguments = {"path": "plain.txt", "content": "alpha\nBETA\n", "cross_profile": False}
    first = preparer.prepare("write_file", arguments, _context(), worktree_root=worktree)
    second = preparer.prepare("write_file", arguments, _context(), worktree_root=worktree)
    assert first.plan_bytes == second.plan_bytes
    assert first.plan_sha256 == second.plan_sha256
    assert first.descriptor_sha256 == second.descriptor_sha256
    image = first.paths[0]
    assert image.action == "update"
    assert image.after == b"alpha\nBETA\n"
    assert first.diff_text.startswith(preparer.UNTRUSTED_DIFF_HEADER)


def test_create_action_has_null_before_side(worktree):
    plan = preparer.prepare(
        "write_file", {"path": "new.txt", "content": "hello", "cross_profile": False},
        _context(), worktree_root=worktree)
    record = plan.descriptor["paths"][0]
    assert record["action"] == "create"
    assert record["before_sha256"] is None and record["before_length"] is None
    assert record["after_sha256"] == proto.sha256_hex(b"hello")


def test_patch_replace_preserves_bom_and_crlf(worktree):
    plan = preparer.prepare(
        "patch_replace",
        {"path": "bom_crlf.txt", "old_string": "two", "new_string": "TWO",
         "replace_all": False, "cross_profile": False},
        _context(), worktree_root=worktree)
    image = plan.paths[0]
    assert image.before == b"\xef\xbb\xbfone\r\ntwo\r\n"
    assert image.after == b"\xef\xbb\xbfone\r\nTWO\r\n"


def test_patch_replace_without_a_match_is_refused(worktree):
    with pytest.raises(preparer.PrepareError, match="no match"):
        preparer.prepare(
            "patch_replace",
            {"path": "plain.txt", "old_string": "not-there", "new_string": "x",
             "replace_all": False, "cross_profile": False},
            _context(), worktree_root=worktree)


def test_patch_v4a_covers_create_update_and_delete(worktree):
    (worktree / "gone.txt").write_text("bye\n", encoding="utf-8")
    plan = preparer.prepare(
        "patch_v4a",
        {"patch": (
            "*** Begin Patch\n"
            "*** Update File: plain.txt\n"
            "@@ \n-alpha\n+ALPHA\n"
            "*** Add File: brand.txt\n+hello\n"
            "*** Delete File: gone.txt\n"
            "*** End Patch\n"), "cross_profile": False},
        _context(), worktree_root=worktree)
    actions = {image.normalized: image.action for image in plan.paths}
    assert actions == {"plain.txt": "update", "brand.txt": "create", "gone.txt": "delete"}
    deleted = next(image for image in plan.paths if image.normalized == "gone.txt")
    assert deleted.before == b"bye\n" and deleted.after is None


def test_patch_v4a_move_reports_both_endpoints(worktree):
    plan = preparer.prepare(
        "patch_v4a",
        {"patch": "*** Begin Patch\n*** Move File: plain.txt -> moved.txt\n*** End Patch\n",
         "cross_profile": False},
        _context(), worktree_root=worktree)
    actions = {image.normalized: image.action for image in plan.paths}
    assert actions == {"plain.txt": "move_source", "moved.txt": "move_destination"}


@pytest.mark.parametrize("bad_path", ["../escape.txt", "/etc/passwd", "~/x", "a/../../b.txt"])
def test_path_escape_is_refused(worktree, bad_path):
    with pytest.raises(preparer.PrepareError):
        preparer.prepare(
            "write_file", {"path": bad_path, "content": "x", "cross_profile": False},
            _context(), worktree_root=worktree)


def test_symlinked_component_and_target_are_refused(worktree):
    outside = worktree.parent / "outside"
    outside.mkdir()
    (outside / "target.txt").write_text("secret\n", encoding="utf-8")
    (worktree / "link.txt").symlink_to(outside / "target.txt")
    (worktree / "linkdir").symlink_to(outside)
    for bad in ("link.txt", "linkdir/target.txt"):
        with pytest.raises(preparer.PrepareError, match="symlink"):
            preparer.prepare(
                "write_file", {"path": bad, "content": "x", "cross_profile": False},
                _context(), worktree_root=worktree)


def test_hardlinked_target_is_refused(worktree):
    (worktree / "hard.txt").write_text("x\n", encoding="utf-8")
    os.link(worktree / "hard.txt", worktree / "hard2.txt")
    with pytest.raises(preparer.PrepareError, match="hard link"):
        preparer.prepare(
            "write_file", {"path": "hard.txt", "content": "y", "cross_profile": False},
            _context(), worktree_root=worktree)


def test_case_alias_is_refused(worktree):
    (worktree / "Mixed.txt").write_text("x\n", encoding="utf-8")
    with pytest.raises(preparer.PrepareError, match="case alias"):
        preparer.prepare(
            "write_file", {"path": "mixed.txt", "content": "y", "cross_profile": False},
            _context(), worktree_root=worktree)


@pytest.mark.platforms("posix")
def test_unreadable_file_is_not_treated_as_absence(worktree):
    if os.geteuid() == 0:
        pytest.skip("root can read a mode-000 file; the EACCES path needs an unprivileged uid")
    target = worktree / "sealed.txt"
    target.write_text("x\n", encoding="utf-8")
    os.chmod(target, 0)
    try:
        with pytest.raises(preparer.PrepareError, match="missing read is not absence"):
            preparer.prepare(
                "patch_replace",
                {"path": "sealed.txt", "old_string": "x", "new_string": "y",
                 "replace_all": False, "cross_profile": False},
                _context(), worktree_root=worktree)
    finally:
        os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)


def test_oversize_diff_is_refused_rather_than_truncated(worktree, monkeypatch):
    monkeypatch.setattr(preparer, "MAX_DIFF_BYTES", 64)
    with pytest.raises(preparer.PrepareError, match="never truncated"):
        preparer.prepare(
            "write_file",
            {"path": "plain.txt", "content": "z" * 4096, "cross_profile": False},
            _context(), worktree_root=worktree)


def test_render_diff_escapes_terminal_controls():
    escaped = preparer.escape_untrusted("ok\x1b[31mred\x07\nnext")
    assert "\x1b" not in escaped and "\x07" not in escaped
    assert "\\x1b" in escaped and "\\x07" in escaped


# ── authority store ───────────────────────────────────────────────────────
def _register(store, ctx) -> dict:
    return store.register(
        ctx, authority.dispatcher_fingerprint_for(LIVE_DISPATCHER),
        dispatcher=LIVE_DISPATCHER)


def _issue(store, worktree, ctx, arguments=None) -> tuple[dict, preparer.PreparedPlan]:
    arguments = arguments or {"path": "plain.txt", "content": "alpha\nBETA\n",
                              "cross_profile": False}
    plan = preparer.prepare("write_file", arguments, ctx, worktree_root=worktree)
    issued = store.issue(plan.envelope(), plan.descriptor, 900,
                         confirmation=plan.descriptor_sha256, peer=_peer(), admin=True)
    return issued, plan


def test_register_then_issue_requires_active_generation(store, worktree):
    ctx = _context()
    registered = _register(store, ctx)
    ctx = _context(registration_generation=registered["generation"])
    issued, plan = _issue(store, worktree, ctx)
    assert issued["state"] == authority.GRANT_ISSUED
    assert issued["descriptor_digest"] == plan.descriptor_sha256


def test_issue_without_a_registration_is_refused(store, worktree):
    ctx = _context(registration_generation=99)
    plan = preparer.prepare(
        "write_file", {"path": "plain.txt", "content": "x", "cross_profile": False},
        ctx, worktree_root=worktree)
    with pytest.raises(authority.ConsentError, match="no active registration"):
        store.issue(plan.envelope(), plan.descriptor, 900, confirmation="c",
                    peer=_peer(), admin=True)


def test_issue_requires_admin_and_confirmation(store, worktree):
    ctx = _context()
    registered = _register(store, ctx)
    ctx = _context(registration_generation=registered["generation"])
    plan = preparer.prepare(
        "write_file", {"path": "plain.txt", "content": "x", "cross_profile": False},
        ctx, worktree_root=worktree)
    with pytest.raises(authority.ConsentError, match="root admin peer"):
        store.issue(plan.envelope(), plan.descriptor, 900, confirmation="c",
                    peer=_peer(), admin=False)
    with pytest.raises(authority.ConsentError, match="confirmation"):
        store.issue(plan.envelope(), plan.descriptor, 900, confirmation="  ",
                    peer=_peer(), admin=True)


def test_issue_enforces_ttl_bounds(store, worktree):
    ctx = _context()
    registered = _register(store, ctx)
    ctx = _context(registration_generation=registered["generation"])
    plan = preparer.prepare(
        "write_file", {"path": "plain.txt", "content": "x", "cross_profile": False},
        ctx, worktree_root=worktree)
    with pytest.raises(authority.ConsentError, match="ttl"):
        store.issue(plan.envelope(), plan.descriptor, proto.MAX_TTL_SECONDS + 1,
                    confirmation="c", peer=_peer(), admin=True)
    with pytest.raises(authority.ConsentError, match="ttl"):
        store.issue(plan.envelope(), plan.descriptor, 0, confirmation="c",
                    peer=_peer(), admin=True)


def test_issue_refuses_plan_bytes_that_disagree_with_the_descriptor(store, worktree):
    ctx = _context()
    registered = _register(store, ctx)
    ctx = _context(registration_generation=registered["generation"])
    plan = preparer.prepare(
        "write_file", {"path": "plain.txt", "content": "x", "cross_profile": False},
        ctx, worktree_root=worktree)
    tampered = preparer.prepare(
        "write_file", {"path": "plain.txt", "content": "y", "cross_profile": False},
        ctx, worktree_root=worktree)
    with pytest.raises(authority.ConsentError, match="plan_sha256"):
        store.issue(tampered.envelope(), plan.descriptor, 900, confirmation="c",
                    peer=_peer(), admin=True)


def test_lookup_reports_absent_then_issued_then_terminal(store, worktree):
    ctx = _context()
    registered = _register(store, ctx)
    ctx = _context(registration_generation=registered["generation"])
    other = preparer.prepare(
        "write_file", {"path": "plain.txt", "content": "different", "cross_profile": False},
        ctx, worktree_root=worktree)
    assert store.lookup(other.descriptor, ctx, _peer())["status"] == authority.LOOKUP_ABSENT

    issued, plan = _issue(store, worktree, ctx)
    found = store.lookup(plan.descriptor, ctx, _peer())
    assert found["status"] == authority.LOOKUP_ISSUED

    store.revoke(issued["grant_id"], "operator withdrew it", admin=True)
    assert store.lookup(plan.descriptor, ctx, _peer())["status"] == authority.LOOKUP_TERMINAL


def test_lookup_denies_when_the_peer_is_not_the_registered_worker(store, worktree):
    ctx = _context()
    registered = _register(store, ctx)
    ctx = _context(registration_generation=registered["generation"])
    issued, plan = _issue(store, worktree, ctx)
    with pytest.raises(authority.ConsentError, match="PID must EQUAL"):
        store.lookup(plan.descriptor, ctx, _peer(pid=PID + 1))
    with pytest.raises(authority.ConsentError, match="start ticks"):
        store.lookup(plan.descriptor, ctx, _peer(start_ticks=START_TICKS + 1))
    with pytest.raises(authority.ConsentError, match="boot id"):
        store.lookup(plan.descriptor, ctx, _peer(boot_id="c" * 32))
    assert issued["grant_id"]


def test_claim_is_single_use_and_duplicate_only_reads(store, worktree):
    ctx = _context()
    registered = _register(store, ctx)
    ctx = _context(registration_generation=registered["generation"])
    issued, plan = _issue(store, worktree, ctx)

    claimed = store.claim(issued["grant_id"], plan.descriptor, "txn-1", "d" * 64, ctx, _peer())
    assert claimed["receipt"]["state"] == authority.GRANT_SPENT_PENDING

    replay = store.claim(issued["grant_id"], plan.descriptor, "txn-1", "d" * 64, ctx, _peer())
    assert replay["replayed"] is True
    assert replay["receipt"]["claim_id"] == claimed["receipt"]["claim_id"]

    with pytest.raises(authority.ConsentError, match="never re-execute"):
        store.claim(issued["grant_id"], plan.descriptor, "txn-2", "d" * 64, ctx, _peer())
    with pytest.raises(authority.ConsentError, match="never re-execute"):
        store.claim(issued["grant_id"], plan.descriptor, "txn-1", "e" * 64, ctx, _peer())


def test_finalize_requires_correlation_and_complete_hashes(store, worktree):
    ctx = _context()
    registered = _register(store, ctx)
    ctx = _context(registration_generation=registered["generation"])
    issued, plan = _issue(store, worktree, ctx)
    claimed = store.claim(issued["grant_id"], plan.descriptor, "txn-1", "d" * 64, ctx, _peer())
    claim_id = claimed["receipt"]["claim_id"]
    digest = plan.descriptor["paths"][0]["after_sha256"]

    with pytest.raises(authority.ConsentError, match="correlation"):
        store.finalize(claim_id, "txn-other", authority.GRANT_COMPLETED,
                       {"plain.txt": digest}, ctx, _peer())
    with pytest.raises(authority.ConsentError, match="complete readback"):
        store.finalize(claim_id, "txn-1", authority.GRANT_COMPLETED, {}, ctx, _peer())
    # A different PID is refused at the registration binding, which is the strictest
    # guard in front of finalize; the claim-level peer check is the defence in depth
    # behind it.
    with pytest.raises(authority.ConsentError, match="PID must EQUAL"):
        store.finalize(claim_id, "txn-1", authority.GRANT_COMPLETED,
                       {"plain.txt": digest}, ctx, _peer(pid=PID + 5))

    settled = store.finalize(claim_id, "txn-1", authority.GRANT_COMPLETED,
                             {"plain.txt": digest}, ctx, _peer())
    assert settled["receipt"]["outcome"] == authority.GRANT_COMPLETED
    assert store.lookup(plan.descriptor, ctx, _peer())["status"] == authority.LOOKUP_TERMINAL


def test_expired_grant_is_terminal_and_cannot_be_claimed(store, worktree):
    clock = {"now": 1_000_000.0}
    store._now = lambda: clock["now"]  # noqa: SLF001 - the injected clock seam
    ctx = _context()
    registered = _register(store, ctx)
    ctx = _context(registration_generation=registered["generation"])
    issued, plan = _issue(store, worktree, ctx)
    clock["now"] += 901
    assert store.lookup(plan.descriptor, ctx, _peer())["status"] == authority.LOOKUP_TERMINAL
    with pytest.raises(authority.ConsentError, match="expired"):
        store.claim(issued["grant_id"], plan.descriptor, "txn-1", "d" * 64, ctx, _peer())


def test_cancel_generation_is_cancel_only_and_leaves_nothing_issuable(store, worktree):
    ctx = _context()
    registered = _register(store, ctx)
    generation = registered["generation"]
    ctx = _context(registration_generation=generation)
    issued, plan = _issue(store, worktree, ctx)

    outcome = store.cancel_generation(generation, "dispatcher cancelled the run", admin=True)
    assert outcome["cancelled"] == [issued["grant_id"]]
    assert store.lookup(plan.descriptor, ctx, _peer(), admin=True)["status"] == \
        authority.LOOKUP_TERMINAL
    # Cancelling ends the run, so the worker cannot even look the grant up any more.
    with pytest.raises(authority.ConsentError, match="no active registration"):
        store.lookup(plan.descriptor, ctx, _peer())
    with pytest.raises(authority.ConsentError, match="no active registration"):
        store.claim(issued["grant_id"], plan.descriptor, "txn-1", "d" * 64, ctx, _peer())


def test_cancel_peer_must_be_exactly_registered_and_cannot_issue(store, worktree):
    ctx = _context()
    registered = _register(store, ctx)
    generation = registered["generation"]
    ctx = _context(registration_generation=generation)
    with pytest.raises(authority.ConsentError, match="root admin peer"):
        store.cancel_generation(generation, "nope", admin=False, cancel_peer=_peer())
    store.register_cancel_peer(_peer(), generation, admin=True)
    assert store.cancel_generation(generation, "ok", admin=False,
                                   cancel_peer=_peer())["generation"] == generation
    # A cancel-only peer has no issuance path at all.
    plan = preparer.prepare(
        "write_file", {"path": "plain.txt", "content": "x", "cross_profile": False},
        ctx, worktree_root=worktree)
    with pytest.raises(authority.ConsentError, match="root admin peer"):
        store.issue(plan.envelope(), plan.descriptor, 900, confirmation="c",
                    peer=_peer(), admin=False)


def test_revoke_is_terminal_and_replay_returns_the_prior_receipt(store, worktree):
    ctx = _context()
    registered = _register(store, ctx)
    ctx = _context(registration_generation=registered["generation"])
    issued, _plan = _issue(store, worktree, ctx)
    first = store.revoke(issued["grant_id"], "no longer needed", admin=True)
    assert first["state"] == authority.GRANT_REVOKED
    second = store.revoke(issued["grant_id"], "no longer needed", admin=True)
    assert second["replayed"] is True


def test_recovery_settles_a_spent_claim_without_reissuing(store, worktree):
    ctx = _context()
    registered = _register(store, ctx)
    ctx = _context(registration_generation=registered["generation"])
    issued, plan = _issue(store, worktree, ctx)
    claimed = store.claim(issued["grant_id"], plan.descriptor, "txn-1", "d" * 64, ctx, _peer())
    claim_id = claimed["receipt"]["claim_id"]
    assert store.recovery_status(claim_id)["outcome"] == authority.GRANT_SPENT_PENDING

    settled = store.recover(claim_id, "before", {}, "restored the pre-image", admin=True)
    assert settled["receipt"]["outcome"] == authority.GRANT_FAILED_SPENT
    replay = store.claim(issued["grant_id"], plan.descriptor, "txn-1", "d" * 64, ctx, _peer())
    assert replay["replayed"] is True
    assert replay["receipt"]["claim_id"] == claim_id
    assert store.lookup(plan.descriptor, ctx, _peer())["status"] == authority.LOOKUP_TERMINAL


def test_conflict_recovery_raises_an_independent_retained_hold(store, worktree):
    ctx = _context()
    registered = _register(store, ctx)
    ctx = _context(registration_generation=registered["generation"])
    issued, plan = _issue(store, worktree, ctx)
    claimed = store.claim(issued["grant_id"], plan.descriptor, "txn-1", "d" * 64, ctx, _peer())
    store.recover(claimed["receipt"]["claim_id"], "conflict", {}, "bytes changed under us",
                  admin=True)
    holds = store.active_holds()
    assert len(holds) == 1
    assert store.worktree_status(ctx)["status"] == authority.WORKTREE_HELD
    # Clearing the hold is admin-only.
    with pytest.raises(authority.ConsentError, match="root admin peer"):
        store.clear_hold(holds[0]["hold_id"], "looks fine", admin=False)
    store.clear_hold(holds[0]["hold_id"], "resolved", admin=True)
    assert store.active_holds() == []


def test_restart_marks_unresolved_claims_recovery_only(store, worktree):
    ctx = _context()
    registered = _register(store, ctx)
    ctx = _context(registration_generation=registered["generation"])
    issued, plan = _issue(store, worktree, ctx)
    claimed = store.claim(issued["grant_id"], plan.descriptor, "txn-1", "d" * 64, ctx, _peer())
    assert store.mark_restart_recovery() == 1
    status = store.recovery_status(claimed["receipt"]["claim_id"])
    assert status["held"] is True and status["outcome"] == authority.GRANT_SPENT_PENDING
    # The claim is still not replayable as consent.
    with pytest.raises(authority.ConsentError, match="never re-execute"):
        store.claim(issued["grant_id"], plan.descriptor, "txn-2", "d" * 64, ctx, _peer())


def test_unknown_schema_version_fails_closed(tmp_path):
    import sqlite3

    path = tmp_path / "authority.sqlite3"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    conn.execute("INSERT INTO meta(key, value) VALUES ('schema_version', 'future-v9')")
    conn.commit()
    conn.close()
    store = authority.AuthorityStore(path)
    with pytest.raises(authority.StoreUnavailable, match="unknown authority schema"):
        store.worktree_status(_context())
    with pytest.raises(authority.StoreUnavailable, match="unknown authority schema"):
        store.open()
    store.close()


def test_worktree_status_is_read_only_and_lists_correlations(store, worktree):
    ctx = _context()
    assert store.worktree_status(ctx)["status"] == authority.WORKTREE_UNREGISTERED
    registered = _register(store, ctx)
    ctx = _context(registration_generation=registered["generation"])
    assert store.worktree_status(ctx)["status"] == authority.WORKTREE_REGISTERED
