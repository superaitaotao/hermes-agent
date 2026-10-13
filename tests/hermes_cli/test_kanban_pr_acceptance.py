"""Two lifecycle invariants, using real SQLite and a local GitHub HTTP contract."""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from hermes_cli import kanban_db as kb
from hermes_cli.kanban_db_connect import connect


@pytest.fixture
def github(tmp_path, monkeypatch, *, db_path=None):
    state = {"conclusion": "success", "head": "a" * 40, "reads": 0, "requests": []}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            state["requests"].append(self.path)
            sha = state["head"]
            if self.path == "/graphql":
                value = {"data": {"repository": {"pullRequest": {
                    "headRefOid": sha, "baseRefName": "main", "state": "OPEN",
                    "baseRef": {"branchProtectionRule": {"requiredStatusChecks": [
                        {"context": "required", "app": {"databaseId": 1}}]}}}}}}
            elif "/rules/branches/" in self.path:
                value = [[]]
            elif "/check-runs" in self.path:
                run = {"id": 42, "name": "required", "head_sha": sha,
                       "app": {"id": 1}, "status": "in_progress" if state["conclusion"] == "pending" else "completed", "conclusion": state["conclusion"],
                       "html_url": "https://github.com/acme/repo/actions/runs/42"}
                if state.get("stale"):
                    run["head_sha"] = "b" * 40
                runs = [] if state.get("missing") else [run]
                value = [{"total_count": 100 + len(runs), "check_runs": [
                    {**run, "id": 1000 + i, "name": "optional", "conclusion": "skipped"}
                    for i in range(100)]}, {"total_count": 100 + len(runs), "check_runs": runs}]
                if state.get("race"):
                    state["race"]()
                if state.get("head_change"):
                    state["head"] = "b" * 40
            elif "/statuses" in self.path:
                value = [[]]
            elif "/pulls/" in self.path:
                value = {"head": {"sha": sha}, "base": {"ref": "main"}, "state": "open"}
            else:
                self.send_error(404)
                return
            if self.path == "/graphql":
                pr = value["data"]["repository"]["pullRequest"]
                pr["state"] = state.get("pr_state", "OPEN")
                if "base" in state:
                    pr["baseRef"] = state["base"]
                if state.get("omit_base"):
                    del pr["baseRef"]
            if "/pulls/" in self.path:
                if state.get("final_race"):
                    state["final_race"]()
                value = state.get("final", value)
            key = next((k for k in ("graphql", "rules", "check-runs", "statuses") if k in self.path), "final")
            value = state.get("responses", {}).get(key, value)
            code = state.get("http_errors", {}).get(key, 200)
            self.send_response(code)
            self.end_headers()
            body = state.get("raw", {}).get(key, json.dumps(value))
            self.wfile.write(body.encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    shim = tmp_path / "bin"
    shim.mkdir()
    gh = shim / "gh"
    gh.write_text(f"#!{sys.executable}\nimport sys,urllib.request\n"
                  f"u='http://127.0.0.1:{server.server_port}/'+sys.argv[2]\n"
                  "try:\n print(urllib.request.urlopen(u).read().decode())\n"
                  "except urllib.error.HTTPError as e:\n print('HTTP '+str(e.code), file=sys.stderr); sys.exit(1)\n")
    gh.chmod(0o755)
    monkeypatch.setenv("PATH", str(shim) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    kb.init_db(db_path=db_path)
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.platforms("linux")
def test_pr_completion_requires_current_required_evidence(github):
    with connect() as conn:
        for conclusion in ("failure", "pending", "cancelled", "timed_out", "action_required", "neutral", "skipped", None, "success"):
            github.update(conclusion=conclusion, head="a" * 40)
            tid = kb.create_task(conn, title="Publish", completion_contract="acme/repo")
            ok = kb.complete_task(conn, tid, result="done", metadata={"published_pr": "https://github.com/acme/repo/pull/7"})
            assert ok is (conclusion == "success")
            task = kb.get_task(conn, tid)
            assert (task.status == "done") is ok
            receipts = [json.loads(r[0]) for r in conn.execute(
                "SELECT payload FROM task_events WHERE task_id=? AND kind='pr_acceptance'", (tid,))]
            assert receipts and receipts[-1]["head_sha"] == "a" * 40
            if not ok:
                assert task.status in {"running", "ready", "blocked", "review"}
                assert "retry" in receipts[-1]["recovery"]
                assert receipts[-1]["checks"][0]["id"] == 42
        for policy, classification in (
            ({"responses": {"rules": [[], [{"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": "required", "integration_id": 1}]}}]]}}, "success"),
            ({"base": {"branchProtectionRule": None}, "responses": {"rules": [[{"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": "required", "integration_id": 9}]}}]]}}, "missing"),
            ({"base": {"branchProtectionRule": {"requiredStatusChecks": [{"context": "legacy"}]}}, "responses": {"statuses": [[{"id": 8, "context": "legacy", "state": "failure"}], [{"id": 9, "context": "legacy", "state": "success"}]]}}, "success"),
            ({"responses": {"check-runs": [{"total_count": 2, "check_runs": []}]}}, "infra"),
        ):
            github.update(conclusion="success")
            github.update(policy)
            tid = kb.create_task(conn, title="policy union", completion_contract="acme/repo")
            assert kb.complete_task(conn, tid, summary="evidence", metadata={"published_pr": "https://github.com/acme/repo/pull/7"}) is (classification == "success")
            receipt = json.loads(conn.execute("SELECT payload FROM task_events WHERE task_id=? AND kind='pr_acceptance'", (tid,)).fetchone()[0])
            assert receipt["classification"] == classification
            for key in policy:
                github.pop(key)
        for fault in ("missing", "stale", "head_change"):
            github.update(conclusion="success", head="a" * 40)
            github[fault] = True
            tid = kb.create_task(conn, title=fault, completion_contract="acme/repo")
            assert not kb.complete_task(conn, tid, result="done", metadata={"published_pr": "https://github.com/acme/repo/pull/7"})
            assert kb.get_task(conn, tid).status != "done"
            github.pop(fault)
        # Omission and a sibling repository cannot downgrade the stored declaration.
        tid = kb.create_task(conn, title="publish", completion_contract="acme/repo")
        assert not kb.complete_task(conn, tid, summary="local green")
        assert not kb.complete_task(conn, tid, result="done", metadata={"published_pr": "https://github.com/other/repo/pull/7"})
        before = len(github["requests"])
        local = kb.create_task(conn, title="local", completion_contract="local-only")
        assert kb.complete_task(conn, local, summary="https://github.com/acme/repo/pull/7 is background context")
        assert len(github["requests"]) == before


@pytest.mark.platforms("linux")
def test_acceptance_receipts_and_terminal_write_share_run_ownership(github):
    with connect() as conn:
        for conclusion in ("success", "failure", "absent"):
            tid = kb.create_task(conn, title="race", completion_contract="acme/repo")
            owner = kb.claim_task(conn, tid)
            run_id = owner.current_run_id
            def reclaim():
                with connect() as rival:
                    assert kb.block_task(rival, tid, reason="Reassigned during acceptance")
                    assert kb.unblock_task(rival, tid)
                    github["replacement"] = kb.claim_task(rival, tid).current_run_id
            if conclusion == "absent":
                github.update(base={"branchProtectionRule": None}, final_race=reclaim)
            else:
                github.update(conclusion=conclusion, race=reclaim)
            assert not kb.complete_task(conn, tid, result="done", expected_run_id=run_id,
                metadata={"published_pr": "https://github.com/acme/repo/pull/7"})
            assert kb.get_task(conn, tid).current_run_id == github["replacement"]
            assert github["replacement"] != run_id
            assert kb.get_task(conn, tid).status != "done"
            assert conn.execute("SELECT count(*) FROM task_events WHERE task_id=? AND kind='pr_acceptance'", (tid,)).fetchone()[0] == 0
            github.pop("race", None)
            github.pop("final_race", None)
            github.pop("base", None)




@pytest.mark.platforms("linux")
@pytest.mark.parametrize("pr_state", ["OPEN", "MERGED"])
@pytest.mark.parametrize("base,rules", [
    ({"branchProtectionRule": None}, [[]]),
    ({"branchProtectionRule": {"requiredStatusChecks": []}}, [[]]),
    ({"branchProtectionRule": None}, [[{"type": "pull_request"}], []]),
])
def test_absent_required_ci_completes_with_not_applicable_receipt(github, pr_state, base, rules):
    url = "https://github.com/acme/repo/pull/7"
    metadata = {"published_pr": url, "finding": "preserve caller"}
    github.update(base=base, pr_state=pr_state, responses={"rules": rules},
                  final={"head": {"sha": "a" * 40}, "base": {"ref": "main"},
                         "state": "open" if pr_state == "OPEN" else "closed", "merged": pr_state == "MERGED"})
    with connect() as conn:
        tid = kb.create_task(conn, title="Absent CI", completion_contract="acme/repo")
        owner = kb.claim_task(conn, tid)
        github["http_errors"] = {"rules": 503}
        assert kb.complete_task(conn, tid, summary="attempt", metadata=metadata,
                                expected_run_id=owner.current_run_id) is False
        github["http_errors"] = {}
        assert kb.complete_task(conn, tid, summary="delivered", metadata=metadata,
                                expected_run_id=owner.current_run_id) is True
        task = kb.get_task(conn, tid)
        assert (task.status, task.completion_contract, task.current_run_id) == ("done", url, None)
        receipts = [json.loads(r["payload"]) for r in conn.execute(
            "SELECT payload FROM task_events WHERE task_id=? AND kind='pr_acceptance' ORDER BY id", (tid,))]
        assert receipts[0]["classification"] == "infra"
        assert receipts[0]["ok"] is False
        assert receipts[1] == {
            "ok": True, "classification": "not_applicable", "head_sha": "a" * 40,
            "base_ref": "main", "pr_url": url, "required": [], "checks": [],
            "detail": "No repository-required CI checks are configured; CI is not applicable. Review and merge gates remain separate.",
            "recovery": "",
        }
        run = conn.execute("SELECT status, outcome, metadata FROM task_runs WHERE id=?", (owner.current_run_id,)).fetchone()
        assert (run["status"], run["outcome"]) == ("done", "completed")
        assert json.loads(run["metadata"])["published_pr"] == url
        assert conn.execute("SELECT count(*) FROM task_events WHERE task_id=? AND kind='completed'", (tid,)).fetchone()[0] == 1
    assert metadata == {"published_pr": url, "finding": "preserve caller"}


@pytest.mark.platforms("linux")
@pytest.mark.parametrize("fault,classification", [
    ({"omit_base": True}, "infra"),
    ({"base": None}, "infra"),
    ({"base": {}}, "infra"),
    ({"base": {"branchProtectionRule": {}}}, "infra"),
    ({"base": {"branchProtectionRule": {"requiredStatusChecks": None}}}, "infra"),
    ({"base": {"branchProtectionRule": {"requiredStatusChecks": "bad"}}}, "infra"),
    ({"base": {"branchProtectionRule": {"requiredStatusChecks": [{"context": ""}]}}}, "infra"),
    ({"base": {"branchProtectionRule": {"requiredStatusChecks": [{"context": 7}]}}}, "infra"),
    ({"base": {"branchProtectionRule": {"requiredStatusChecks": [{"context": "ci", "app": {}}]}}}, "infra"),
    ({"base": {"branchProtectionRule": {"requiredStatusChecks": [{"context": "ci", "app": {"databaseId": "bad"}}]}}}, "infra"),
    ({"responses": {"rules": []}}, "infra"),
    ({"responses": {"rules": None}}, "infra"),
    ({"responses": {"rules": [{}]}}, "infra"),
    ({"responses": {"rules": [[], None]}}, "infra"),
    ({"responses": {"rules": [[{"type": "required_status_checks"}]]}}, "infra"),
    ({"responses": {"rules": [[{"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": "ci", "integration_id": False}]}}]]}}, "infra"),
    ({"responses": {"rules": [[], [{"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": "later"}]}}]]}}, "missing"),
    ({"responses": {"graphql": {"data": {"repository": None}}}}, "auth"),
    ({"responses": {"graphql": {"errors": [{"message": "partial"}], "data": {"repository": None}}}}, "infra"),
    ({"http_errors": {"rules": 401}}, "auth"),
    ({"http_errors": {"rules": 403}}, "auth"),
    ({"http_errors": {"rules": 404}}, "auth"),
    ({"http_errors": {"rules": 503}}, "infra"),
    ({"raw": {"rules": "not json"}}, "infra"),
    ({"final": {"head": {"sha": "b" * 40}, "base": {"ref": "main"}, "state": "open"}}, "stale"),
    ({"final": {"head": {"sha": "a" * 40}, "base": {"ref": "other"}, "state": "open"}}, "stale"),
    ({"final": {"head": {"sha": "a" * 40}, "base": {"ref": "main"}, "state": "closed", "merged": False}}, "stale"),
    ({"final": {"head": {"sha": "a" * 40}, "base": {"ref": "main"}, "state": "invalid"}}, "infra"),
    ({"final": {}}, "infra"),
])
def test_requirements_discovery_refuses_unavailable_or_changed_identity(github, fault, classification):
    github.update(base={"branchProtectionRule": None})
    github.update(fault)
    with connect() as conn:
        tid = kb.create_task(conn, title="Unavailable discovery", completion_contract="acme/repo")
        owner = kb.claim_task(conn, tid)
        assert kb.complete_task(conn, tid, summary="attempt", expected_run_id=owner.current_run_id,
                                metadata={"published_pr": "https://github.com/acme/repo/pull/7"}) is False
        receipt = json.loads(conn.execute(
            "SELECT payload FROM task_events WHERE task_id=? AND kind='pr_acceptance'", (tid,)).fetchone()[0])
        assert (receipt["ok"], receipt["classification"]) == (False, classification)
        assert kb.get_task(conn, tid).status == "running"
        assert kb.get_task(conn, tid).current_run_id == owner.current_run_id


# --- #122689: acceptance must read the repo as the ASSIGNEE profile's gh login ---

@pytest.mark.platforms("posix")
def test_acceptance_runs_gh_as_the_assignee_profile(tmp_path, monkeypatch):
    """The gh child env carries the assignee's own GH credentials (its .env),
    never the ambient/launch residue, and an invisible repo is classified
    `auth` naming the repository — not a retryable `infra` failure."""
    from pathlib import Path

    launch_home = tmp_path / "home"
    launch_home.mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(launch_home))
    assignee_home = launch_home / "profiles" / "b"
    assignee_home.mkdir(parents=True)
    (assignee_home / ".env").write_text("GH_TOKEN=b-token\n", encoding="utf-8")
    # Ambient residue that must NOT decide the login.
    monkeypatch.setenv("GH_TOKEN", "launch-token")
    monkeypatch.setenv("GH_CONFIG_DIR", "/nonexistent/launch/gh")

    env_dump = tmp_path / "gh_env.json"
    shim = tmp_path / "bin"
    shim.mkdir()
    gh = shim / "gh"
    gh.write_text(f"#!{sys.executable}\nimport json, os\n"
                  f"json.dump(dict(os.environ), open({str(env_dump)!r}, 'w'))\n"
                  "print(json.dumps({'data': {'repository': None}}))\n")
    gh.chmod(0o755)
    monkeypatch.setenv("PATH", str(shim) + os.pathsep + os.environ["PATH"])
    kb.init_db()
    with connect() as conn:
        tid = kb.create_task(conn, title="as-b", completion_contract="acme/repo", assignee="b")
        assert not kb.complete_task(conn, tid, result="done",
                                    metadata={"published_pr": "https://github.com/acme/repo/pull/7"})
        assert kb.get_task(conn, tid).status != "done"
        receipts = [json.loads(r[0]) for r in conn.execute(
            "SELECT payload FROM task_events WHERE task_id=? AND kind='pr_acceptance'", (tid,))]
        assert receipts[-1]["classification"] == "auth"
        assert "acme/repo" in receipts[-1]["detail"]
    captured = json.loads(env_dump.read_text())
    assert captured["GH_TOKEN"] == "b-token"
    assert captured.get("GH_CONFIG_DIR") != "/nonexistent/launch/gh"
    assert "credentials" in (kb.get_task(conn, tid).last_failure_error or "")


@pytest.mark.platforms("posix")
def test_assignee_without_own_gh_login_never_falls_through_to_ambient_login(tmp_path, monkeypatch):
    """An assignee profile with no GH_TOKEN/GH_CONFIG_DIR of its own must not inherit the
    launch user's ~/.config/gh (HOME/XDG_CONFIG_HOME stay the launch process's): gh is pinned
    to a profile-owned config dir, its 'not logged in' exit is classified `auth` naming the profile."""
    launch_home = tmp_path / "home"
    launch_home.mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(launch_home))
    assignee_home = launch_home / "profiles" / "b"
    assignee_home.mkdir(parents=True)
    (assignee_home / ".env").write_text("", encoding="utf-8")
    monkeypatch.setenv("GH_TOKEN", "launch-token")
    monkeypatch.setenv("GH_CONFIG_DIR", "/nonexistent/launch/gh")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "launch-xdg"))

    env_dump = tmp_path / "gh_env.json"
    shim = tmp_path / "bin"
    shim.mkdir()
    gh = shim / "gh"
    # Real gh: GH_CONFIG_DIR wins; a config dir without hosts.yml means "not logged in" (exit 4).
    gh.write_text(f"#!{sys.executable}\nimport json, os, pathlib, sys\n"
                  f"pathlib.Path({str(env_dump)!r}).write_text(json.dumps(dict(os.environ)), encoding='utf-8')\n"
                  "if 'GH_CONFIG_DIR' in os.environ and not os.path.exists(os.environ['GH_CONFIG_DIR']):\n"
                  "    sys.exit(4)\n"
                  "print(json.dumps({'data': {'repository': None}}))\n")
    gh.chmod(0o755)
    monkeypatch.setenv("PATH", str(shim) + os.pathsep + os.environ["PATH"])
    kb.init_db()
    with connect() as conn:
        tid = kb.create_task(conn, title="as-b", completion_contract="acme/repo", assignee="b")
        assert not kb.complete_task(conn, tid, result="done",
                                    metadata={"published_pr": "https://github.com/acme/repo/pull/7"})
        receipt = json.loads(conn.execute(
            "SELECT payload FROM task_events WHERE task_id=? AND kind='pr_acceptance'", (tid,)).fetchone()[0])
    assert receipt["classification"] == "auth"
    assert "'b'" in receipt["detail"] and "no login" in receipt["detail"]
    captured = json.loads(env_dump.read_text(encoding="utf-8-sig"))
    assert captured["GH_CONFIG_DIR"] == str(assignee_home / "gh")
    assert "GH_TOKEN" not in captured and "GITHUB_TOKEN" not in captured


def test_assigned_card_with_unresolvable_profile_is_auth_not_ambient(tmp_path, monkeypatch):
    """A card assigned to a profile that no longer exists must not run gh as the completing
    process's ambient login: classification `auth` naming the profile, gh never invoked."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))  # any gh spawn would fail as infra
    kb.init_db()
    with connect() as conn:
        tid = kb.create_task(conn, title="as-ghost", completion_contract="acme/repo", assignee="ghost")
        assert not kb.complete_task(conn, tid, result="done",
                                    metadata={"published_pr": "https://github.com/acme/repo/pull/7"})
        receipt = json.loads(conn.execute(
            "SELECT payload FROM task_events WHERE task_id=? AND kind='pr_acceptance'", (tid,)).fetchone()[0])
    assert receipt["classification"] == "auth"
    assert "'ghost'" in receipt["detail"] and "cannot be resolved" in receipt["detail"]
