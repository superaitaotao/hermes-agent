"""Real Git update selection must retain the delivered Kanban tool contracts."""
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from hermes_cli import main, update_cmd
from hermes_cli.update_channel import set_install_channel
from tests.hermes_cli.test_source_release_channels import git, releases as releases_fixture

releases = releases_fixture

pytestmark = pytest.mark.real_release_channels


def read_contracts(checkout):
    code = """
import json,runpy,sys
from tools.schema_sanitizer import sanitize_tool_schemas
s=runpy.run_path(sys.argv[1])
a,c=sanitize_tool_schemas([{'type':'function','function':s[n]} for n in ('KANBAN_ATTACH_SCHEMA','KANBAN_COMPLETE_SCHEMA')])
a,c=a['function']['parameters'],c['function']['parameters']
print(json.dumps({'metadata_open':c['properties']['metadata'].get('additionalProperties') is True,
'path':'path' in a['properties'] and not a.get('required'), 'published_pr':'published_pr' in c['properties']}))
"""
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run([sys.executable, "-B", "-c", code, str(checkout / "schema.py")],
                            cwd=root, check=True, capture_output=True, text=True, timeout=30)
    return json.loads(result.stdout)


@pytest.mark.parametrize("selection", ["main", "stable", "unpatched-main"])
def test_actual_update_preserves_contracts_only_on_patched_fork_main(releases, monkeypatch, selection):
    root = Path(__file__).resolve().parents[2]
    import copy
    from tools.kanban_tools_schemas import KANBAN_ATTACH_SCHEMA, KANBAN_COMPLETE_SCHEMA

    current = f"KANBAN_ATTACH_SCHEMA = {KANBAN_ATTACH_SCHEMA!r}\nKANBAN_COMPLETE_SCHEMA = {KANBAN_COMPLETE_SCHEMA!r}\n"
    attach = copy.deepcopy(KANBAN_ATTACH_SCHEMA)
    complete = copy.deepcopy(KANBAN_COMPLETE_SCHEMA)
    attach["parameters"]["properties"].pop("path")
    attach["parameters"]["required"] = ["filename", "content_base64"]
    complete["parameters"]["properties"].pop("published_pr")
    complete["parameters"]["properties"]["metadata"].pop("additionalProperties")
    old = f"KANBAN_ATTACH_SCHEMA = {attach!r}\nKANBAN_COMPLETE_SCHEMA = {complete!r}\n"
    (releases.origin / "schema.py").write_text(old)
    git(releases.origin, "add", "schema.py")
    git(releases.origin, "commit", "-m", "unpatched contracts")
    unpatched = git(releases.origin, "rev-parse", "HEAD")
    (releases.origin / "schema.py").write_text(current)
    git(releases.origin, "commit", "-am", "delivered contracts")
    candidate = git(releases.origin, "rev-parse", "HEAD")
    # Stable is a different published target, not an alias for patched main.
    releases.responses[f"/repos/NousResearch/hermes-agent/commits/{releases.tags['stable']}"] = {"sha": unpatched}
    git(releases.origin, "tag", "-f", releases.tags["stable"], unpatched)
    releases.commits[1] = unpatched
    git(releases.origin, "switch", "--detach", candidate)
    if selection == "unpatched-main":
        git(releases.origin, "branch", "-f", "main", unpatched)
    set_install_channel("stable" if selection == "stable" else "main", releases.root)
    options = update_cmd._UpdateOptions(pre_update_version=None, gw_input_fn=None, assume_yes=True,
                                       keep_stash=False, switch_branch=False, discard_local_changes=False)
    monkeypatch.setattr(update_cmd, "_resolve_update_options", lambda *_: options)
    monkeypatch.setattr(update_cmd, "_begin_update_receipt_and_plan", lambda *_: None)
    monkeypatch.setattr(main, "_run_pre_update_backup", lambda *_: None)
    monkeypatch.setattr(main, "_pause_windows_gateways_for_update", lambda: None)
    monkeypatch.setattr(update_cmd, "_prepare_git_command", lambda **_: (False, ["git"], False))
    monkeypatch.setattr(update_cmd, "_complete_source_update", lambda request: None)
    args = SimpleNamespace(branch=None, channel=None, force_venv=True)
    update_cmd._cmd_update_impl(args, False)
    expected = candidate if selection == "main" else unpatched
    assert git(releases.root, "rev-parse", "HEAD") == expected
    assert read_contracts(releases.root) == {"metadata_open": selection == "main",
                                           "path": selection == "main", "published_pr": selection == "main"}
    if selection == "main":
        update_cmd._cmd_update_impl(args, False)
        assert git(releases.root, "rev-parse", "HEAD") == candidate
        assert read_contracts(releases.root) == {"metadata_open": True, "path": True, "published_pr": True}
