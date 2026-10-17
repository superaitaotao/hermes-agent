"""Resolve native PR scheduling without pretending to execute another host's tests."""
from pathlib import Path

import hermes_yaml
import pytest

from tests.ci import _gha_expr as gha
from tests.ci import workflow_steps

_REPO = Path(__file__).resolve().parents[2]


def _job(workflow, name):
    return hermes_yaml.safe_load(
        (_REPO / ".github/workflows" / workflow).read_text(encoding="utf-8")
    )["jobs"][name]


def _step(job, name):
    return next(step for step in job["steps"] if step.get("name") == name)


@pytest.mark.parametrize("repository, fork", [
    ("NousResearch/hermes-agent", False),
    ("superaitaotao/hermes-agent", True),
    ("another-owner/hermes-agent", False),
])
def test_repository_native_pr_execution_contract(repository, fork):
    ctx = {"github": {"repository": repository}, "inputs": {"desktop_updater": True}}
    linux = _job("tests.yml", "test")
    assert linux["strategy"]["matrix"]["slice"] == [1, 2]
    for slice_number in linux["strategy"]["matrix"]["slice"]:
        cell = {**ctx, "matrix": {"slice": slice_number}}
        assert gha.render(linux["runs-on"], cell) == (
            "ubuntu-latest" if fork else "ubuntu-latest-32-core")
        assert gha.render(linux["timeout-minutes"], cell) == (120 if fork else 30)
        env = _step(linux, "Run tests")["env"]
        assert gha.to_string(gha.render(env["HERMES_TEST_WORKERS"], cell)) == ("2" if fork else "32")
        assert gha.render(env["HERMES_TEST_SLICE"], cell) == f"{slice_number}/2"

    os_job = _job("tests-os.yml", "os-tests")
    rows = os_job["strategy"]["matrix"]["include"]
    resolved = []
    windows_selection = []
    for row in rows:
        cell = {**ctx, "matrix": row}
        row_runner = gha.render(row["runner"], cell)
        cell["matrix"] = {**row, "runner": row_runner}
        runner = gha.render(os_job["runs-on"], cell)
        arch = "ARM64" if "arm" in runner else "X64"
        cell["runner"] = {"os": "Windows" if row["marker"] == "windows" else "macOS", "arch": arch}
        step = _step(os_job, "Run ${{ matrix.marker }} tests")
        workers = gha.to_string(gha.render(step["env"]["HERMES_TEST_WORKERS"], cell))
        file_cap = gha.to_string(gha.render(step["env"].get("HERMES_TEST_FILE_TIMEOUT", ""), cell))
        assert file_cap == ("900" if fork and row["marker"] == "windows" else "")
        resolved.append((runner, workers, gha.render(step["env"]["HERMES_TEST_SLICE"], cell)))
        guard = _step(os_job, "Require native Windows test interpreter")
        assert gha.condition(guard["if"], cell) == (fork and row["marker"] == "windows")
        assert gha.render(os_job["timeout-minutes"], cell) == (
            75 if fork and row["marker"] == "windows" else (60 if arch == "ARM64" else 30))
        if row["marker"] == "windows":
            assert gha.render(guard["env"]["EXPECTED_RUNNER_ARCH"], cell) == arch
            assert os_job["steps"].index(guard) < os_job["steps"].index(step)
            windows_selection.append(workflow_steps.selected_files(step, cell, _REPO))
    assert resolved == [
        ("macos-latest", "", "1/2"), ("macos-latest", "", "2/2"),
        ("windows-latest" if fork else "windows-latest-32-core", "2" if fork else "16", ""),
        ("windows-11-arm" if fork else "windows-latest-32-arm-core", "2" if fork else "16", ""),
    ]
    assert windows_selection[0] == windows_selection[1]
    assert "tests/ci/test_update_ci_routing.py" in windows_selection[0]

    js = _job("js-tests.yml", "check")
    rust = _job("rust-tests.yml", "bootstrap-installer")
    nix = _job("nix.yml", "flake-check")
    assert gha.render(js["timeout-minutes"], ctx) == (60 if fork else 30)
    assert gha.render(rust["timeout-minutes"], ctx) == 30
    assert gha.render(nix["timeout-minutes"], ctx) == 60
    for job in (js, rust, nix):
        assert gha.render(job["runs-on"], ctx) == (
            "ubuntu-latest" if fork else "ubuntu-latest-32-core")
    assert gha.render(_step(js, "Run all workspace checks")["run"], ctx).strip() == (
        "node .github/scripts/run-workspace-checks.mjs --concurrency 1" if fork
        else "node .github/scripts/run-workspace-checks.mjs")
    cargo = _step(rust, "cargo test")
    assert gha.render(cargo["run"], ctx) == (
        "CARGO_BUILD_JOBS=2 cargo test --lib" if fork else "cargo test --lib")
    assert gha.render(_step(nix, "nix flake check")["run"], ctx) == (
        'nix flake check "." --print-build-logs --max-jobs 1 --cores 2' if fork
        else 'nix flake check "." --print-build-logs')
    release_ctx = {**ctx, "inputs": {"release": True},
                   "runner": {"temp": "/release-trial"},
                   "env": {"CANDIDATE_COMMIT": "a" * 40},
                   "github": {"repository": repository, "sha": "a" * 40}}
    assert gha.render(nix["runs-on"], release_ctx) == "ubuntu-latest-32-core"
    assert gha.render(_step(nix, "nix flake check")["run"], release_ctx) == (
        'nix flake check "path:/release-trial/release-source?rev=' + "a" * 40 + '" --print-build-logs')
