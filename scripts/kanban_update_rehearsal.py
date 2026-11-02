"""Namespace-isolated actual updater replay for the three Kanban contracts."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.verify_kanban_runtime_contracts import (
    FORK, ROOT, SHA, advance_fixture, git, source_identity, trial_environment,
    validate_trial_homes, verify_target,
)


def sandbox_argv(trial, runner, command):
    argv = ["bwrap", "--unshare-all", "--share-net", "--die-with-parent", "--new-session"]
    for path in ("/usr", "/bin", "/lib", "/lib64", "/etc"):
        argv += ["--ro-bind", path, path]
    # no-tmp: ok — ephemeral namespace mount, not host scratch
    argv += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/run",
             "--tmpfs", "/home", "--bind", str(trial), "/trial", "--ro-bind", str(runner), "/runner",
             "--clearenv"]
    for key, value in trial_environment().items():
        argv += ["--setenv", key, value]
    return argv + ["--chdir", "/trial/checkout", "--", *command]


def namespace_preflight(helpers=False):
    homes = validate_trial_homes(os.environ)
    for forbidden in ("/home/nekee/.hermes", "/run/user/1000/bus"):
        if Path(forbidden).exists():
            raise ValueError("Live home or user bus visible")
    mounts = []
    for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8-sig").splitlines():
        fields = line.split()
        destination, options = fields[4], fields[5].split(",")
        kind = fields[fields.index("-") + 1]
        if "rw" in options and kind not in {"tmpfs", "proc", "devpts", "mqueue"} and not destination.startswith("/trial"):
            raise ValueError("Writable persisted mount outside /trial")
        mounts.append({"destination": destination, "kind": kind, "writable": "rw" in options})
    for root in (Path("/trial/home"), Path("/trial/state"), Path("/trial/run")):
        for path in root.rglob("*"):
            if path.is_symlink() and not path.resolve().is_relative_to("/trial"):
                raise ValueError("Trial state symlink escapes /trial")
            if path.exists() and stat.S_ISSOCK(path.stat().st_mode):
                raise ValueError("Unexpected service control socket")
    bus = subprocess.run(["systemctl", "--user", "show", "hermes-gateway.service"],
                         capture_output=True, timeout=30, check=False)
    if bus.returncode == 0:
        raise ValueError("Host service bus reachable")
    report = {"homes": homes, "mounts": mounts, "service_bus_absent": True,
              "namespaces": {name: os.readlink(f"/proc/self/ns/{name}")
                             for name in ("mnt", "pid", "ipc", "user", "cgroup")}}
    if helpers:
        sys.path.insert(0, "/trial/checkout")
        from hermes_constants import get_default_hermes_root
        from hermes_cli.update_receipt import _profile_homes
        from hermes_cli.update_fleet_scope import update_scope_homes, home_in_update_scope
        from gateway.host_rendezvous import host_state_dir
        from scripts.verify_kanban_runtime_contracts import pending

        scope = update_scope_homes()
        profiles = list(_profile_homes())
        if get_default_hermes_root() != Path("/trial/home/.hermes"):
            raise ValueError("Native Hermes root escaped trial")
        if not all(home.resolve().is_relative_to("/trial") for _, home in profiles):
            raise ValueError("Profile home escaped trial")
        if not all(home.resolve().is_relative_to("/trial") for home in scope):
            raise ValueError("Update scope escaped trial")
        if home_in_update_scope("/home/nekee/.hermes", scope) or not host_state_dir().resolve().is_relative_to("/trial/state"):
            raise ValueError("Live home or host state in update scope")
        pending(Path("/trial/checkout"))
        report.update(profiles=[(name, str(home)) for name, home in profiles],
                      scope=[str(home) for home in scope], host_state=str(host_state_dir()))
    return report


class Trial:
    def __init__(self, root, runner):
        self.root = root
        self.runner = runner
        self.phases = []

    def run(self, label, argv, *, manual=False, check=True):
        command = list(argv)
        if manual:
            command = ["env", "HERMES_DISABLE_LAZY_INSTALLS=1", *command]
        log = self.root / "evidence" / f"{len(self.phases):02d}-{label}.log"
        started = time.time()
        with log.open("wb") as stream:
            result = subprocess.run(sandbox_argv(self.root, self.runner, command), stdin=subprocess.DEVNULL,
                                    stdout=stream, stderr=subprocess.STDOUT, timeout=86400, check=False)
        entry = {"phase": label, "argv": command, "exit_code": result.returncode,
                 "elapsed_seconds": round(time.time() - started, 3), "log": str(log)}
        self.phases.append(entry)
        (self.root / "evidence/phases.json").write_text(json.dumps(self.phases, indent=2), encoding="utf-8")
        if check and result.returncode:
            raise ValueError(f"Rehearsal phase {label} failed with exit {result.returncode}; see {log}")
        return log

    def preflight(self, helpers=False):
        if helpers:
            command = self.python() + ["-B", "/runner/scripts/kanban_update_rehearsal.py", "--preflight", "--helpers"]
        else:
            command = ["/usr/bin/python3", "-B", "/runner/scripts/kanban_update_rehearsal.py", "--preflight"]
        log = self.run("scope-helpers" if helpers else "scope-native", command, manual=helpers)
        return json.loads(log.read_text(encoding="utf-8-sig"))

    def python(self):
        log = self.run("bootstrap-interpreter", ["bash", "-c", ". scripts/_activation.sh; hermes_bootstrap_python /trial/checkout"], manual=True)
        executable = log.read_text(encoding="utf-8-sig").strip()
        if not executable.startswith("/trial/") or "\n" in executable:
            raise ValueError("Bootstrap interpreter escaped trial")
        return [executable]

    def prepare(self, sha, baseline=False):
        git(self.root / "checkout", "switch", "--detach", sha)
        self.preflight()
        python = self.python()
        self.run("pm-install", python + ["-B", "-m", "pm.cli", "install"], manual=True)
        self.run("publish-launchers", python + ["-I", "-B", "/trial/checkout/hermes_cli/_launchers.py", "/trial/checkout/.hermes/bin"], manual=True)
        for command in ("doctor", "status"):
            self.run("pm-" + command, ["/trial/checkout/.hermes/bin/hermes", "pm", command], manual=True)
        self.preflight(helpers=True)
        return self.readback(sha, baseline)

    def readback(self, sha, baseline=False):
        source_identity(self.root / "checkout", sha)
        argv = self.python() + ["-B", "/runner/scripts/verify_kanban_runtime_contracts.py", "--runtime-ready",
                               "--source", "/trial/checkout", "--expected-sha", sha]
        if baseline:
            argv += ["--allow-baseline-contract-gaps"]
        log = self.run("runtime-readiness", argv, manual=True)
        report = json.loads(log.read_text(encoding="utf-8-sig"))
        if report.get("ok") is not True:
            raise ValueError("Runtime readiness refused")
        if not baseline:
            log = self.run("registry-contracts", self.python() + ["-B", "/runner/scripts/verify_kanban_runtime_contracts.py",
                            "--source", "/trial/checkout", "--expected-sha", sha], manual=True)
            report["dispatch"] = json.loads(log.read_text(encoding="utf-8-sig"))
        receipt_root = self.root / "home/.hermes/logs/update_receipts"
        receipts = []
        for path in sorted(receipt_root.glob("update_*.json")):
            value = json.loads(path.read_text(encoding="utf-8-sig"))
            if value.get("outcome") != "success" or value.get("followups") or value.get("user_action"):
                raise ValueError("Updater receipt has owed work")
            receipts.append({"file": path.name, "outcome": value.get("outcome"),
                             "steps": value.get("steps"), "post_update": value.get("post_update")})
        report["receipts"] = receipts
        report["origin"] = git(self.root / "checkout", "remote", "get-url", "origin")
        return report

    def update(self, sha):
        scope = self.preflight(helpers=True)
        self.run("actual-update", ["/trial/checkout/.hermes/bin/hermes", "update", "--no-gateway-restart"])
        report = self.readback(sha)
        report["scope"] = scope
        return report


def rehearse(options):
    source = options.source.resolve()
    source_identity(source, options.candidate)
    for sha in (options.candidate, options.installed):
        if not sha or not SHA.fullmatch(sha):
            raise ValueError("Candidate and installed require full lowercase SHAs")
    if not options.target_mode:
        raise ValueError("Explicit target mode required")
    workspace = Path(os.environ.get("HERMES_KANBAN_WORKSPACE", source)).resolve()
    root = Path(tempfile.mkdtemp(prefix="w04-trial-", dir=workspace))
    root.chmod(0o700)
    for name in ("home", "state", "run", "tmp", "evidence"):
        (root / name).mkdir(mode=0o700)
    profile = root / "home/.hermes/profiles/probe"
    profile.mkdir(parents=True)
    (profile / "config.yaml").write_text("model: harmless-probe\n", encoding="utf-8")
    trial = Trial(root, source)
    report = {"candidate": options.candidate, "installed": options.installed,
              "trial": str(root), "target_mode": options.target_mode, "phases": trial.phases}
    try:
        if options.target_mode == "local-fixture":
            git(source, "clone", "--bare", "--no-local", str(source), str(root / "origin.git"))
            git(root / "origin.git", "update-ref", "refs/heads/main", options.candidate)
            git(root / "origin.git", "symbolic-ref", "HEAD", "refs/heads/main")
            origin = str(root / "origin.git")
            report["target"] = verify_target(source, origin, options.candidate)
            git(source, "clone", "--no-local", origin, str(root / "writer"))
        else:
            origin = FORK
            report["target"] = verify_target(source, origin, options.candidate)
        git(source, "clone", "--no-local", origin, str(root / "checkout"))
        if options.target_mode == "local-fixture":
            git(root / "checkout", "remote", "set-url", "origin", "/trial/origin.git")
        git(root / "checkout", "switch", "--detach", options.installed)
        trial.preflight()
        trial.run("bootstrap-installed", ["bash", "setup-hermes.sh", "--runtime-only"])
        report["old_readiness"] = trial.prepare(options.installed, baseline=True)
        trial.preflight(helpers=True)
        trial.run("set-main", ["/trial/checkout/.hermes/bin/hermes", "update", "--set-channel", "main"], manual=True)
        trial.preflight(helpers=True)
        trial.run("actual-check", ["/trial/checkout/.hermes/bin/hermes", "update", "--check"])
        report["first_update"] = trial.update(options.candidate)
        report["same_head_update"] = trial.update(options.candidate)
        if options.target_mode == "local-fixture":
            child = advance_fixture(root / "writer", root / "origin.git", options.candidate)
            report["moving_target"] = verify_target(root / "writer", str(root / "origin.git"), child, options.candidate)
            report["moving_update"] = trial.update(child)
        else:
            report["target_after"] = verify_target(source, origin, options.candidate)
        report["reverse_readiness"] = trial.prepare(options.installed, baseline=True)
        report["forward_readiness"] = trial.prepare(options.candidate)
        report["ok"] = True
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        report.update(ok=False, error_type=type(exc).__name__, detail=str(exc))
    report["phases"] = trial.phases
    report["disk_free_bytes"] = shutil.disk_usage(root).free
    (root / "evidence/report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    if not report["ok"]:
        raise ValueError("Update rehearsal failed; retained evidence at " + str(root / "evidence/report.json"))
    return report


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
    print(json.dumps(namespace_preflight("--helpers" in sys.argv), indent=2))
