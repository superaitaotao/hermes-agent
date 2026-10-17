"""Temporary native diagnostics, never included in the reviewed candidate."""
import hashlib
import json
from pathlib import Path
import shutil
import time

import pytest


def pytest_addoption(parser):
    parser.addoption('--diag-output')


_OUTPUT = None


def pytest_configure(config):
    global _OUTPUT
    _OUTPUT = Path(config.getoption('--diag-output'))
    _OUTPUT.mkdir(parents=True, exist_ok=True)


def pytest_runtest_logreport(report):
    with (_OUTPUT / 'reports.jsonl').open('a', encoding='utf-8') as stream:
        stream.write(json.dumps({'nodeid': report.nodeid, 'when': report.when,
                                 'outcome': report.outcome, 'duration': report.duration,
                                 'longrepr': str(report.longrepr)}) + '\n')
    print(f'DIAG CASE {report.nodeid} {report.when} {report.outcome} {report.duration:.3f}s', flush=True)


@pytest.fixture(autouse=True)
def native_case_artifacts(request, tmp_path, monkeypatch):
    target = Path(request.config.getoption('--diag-output'))
    case = target / hashlib.sha256(request.node.nodeid.encode()).hexdigest()[:16]
    case.mkdir(parents=True, exist_ok=True)
    if request.node.name == 'test_result_finished_at_is_stamped_after_the_r6_release_wait':
        original = request.module._handoff

        def capture_handoff(*args, **kwargs):
            outcome = original(*args, **kwargs)
            (case / 'handoff-return.json').write_text(json.dumps(outcome[:4], indent=2), encoding='utf-8')
            return outcome

        monkeypatch.setattr(request.module, '_handoff', capture_handoff)
    started = time.time()
    import faulthandler
    trace = (case / 'stacks.log').open('w', encoding='utf-8')
    faulthandler.dump_traceback_later(100, repeat=True, file=trace)
    yield
    faulthandler.cancel_dump_traceback_later()
    trace.close()
    import psutil
    rows = []
    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'create_time', 'cmdline']):
        if (proc.info['name'] or '').lower().startswith(('python', 'powershell', 'pwsh')):
            rows.append(proc.info)
    (case / 'case.json').write_text(json.dumps({
        'nodeid': request.node.nodeid, 'started': started, 'finished': time.time(),
        'processes': rows,
    }, indent=2), encoding='utf-8')
    for i, log in enumerate(tmp_path.rglob('desktop-update-handoff.log')):
        shutil.copyfile(log, case / f'handoff-{i}.log')
