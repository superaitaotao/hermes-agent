"""Temporary native diagnostics, never included in the reviewed candidate."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time

import pytest


def pytest_addoption(parser):
    parser.addoption('--diag-output')


def pytest_runtest_logreport(report):
    print(f'DIAG CASE {report.nodeid} {report.when} {report.outcome} {report.duration:.3f}s', flush=True)


@pytest.fixture(autouse=True)
def native_case_artifacts(request, tmp_path):
    target = Path(request.config.getoption('--diag-output'))
    case = target / hashlib.sha256(request.node.nodeid.encode()).hexdigest()[:16]
    case.mkdir(parents=True, exist_ok=True)
    started = time.time()
    yield
    rows = subprocess.run(
        ['powershell', '-NoProfile', '-Command',
         'Get-CimInstance Win32_Process | Where-Object { $_.Name -match "^(python|pythonw|powershell|pwsh).*" } | '
         'Select-Object ProcessId,ParentProcessId,Name,CreationDate,CommandLine | ConvertTo-Json -Depth 3'],
        capture_output=True, text=True, timeout=30, check=False)
    (case / 'case.json').write_text(json.dumps({
        'nodeid': request.node.nodeid, 'started': started, 'finished': time.time(),
        'process_exit': rows.returncode, 'processes': rows.stdout, 'process_error': rows.stderr,
    }, indent=2), encoding='utf-8')
    for i, log in enumerate(tmp_path.rglob('desktop-update-handoff.log')):
        shutil.copyfile(log, case / f'handoff-{i}.log')
