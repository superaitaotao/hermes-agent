"""Temporary native diagnostics, never included in the reviewed candidate."""
import faulthandler
import hashlib
import json
import os
from pathlib import Path
import shutil
import threading
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
    with (_OUTPUT / f'reports-{os.getpid()}.jsonl').open('a', encoding='utf-8') as stream:
        stream.write(json.dumps({'nodeid': report.nodeid, 'when': report.when,
                                 'outcome': report.outcome, 'duration': report.duration,
                                 'longrepr': str(report.longrepr)}) + '\n')
    print(f'DIAG CASE {report.nodeid} {report.when} {report.outcome} {report.duration:.3f}s', flush=True)


@pytest.fixture(autouse=True)
def native_case_artifacts(request, tmp_path):
    import psutil

    target = Path(request.config.getoption('--diag-output'))
    case = target / hashlib.sha256(request.node.nodeid.encode()).hexdigest()[:16]
    case.mkdir(parents=True, exist_ok=True)
    started = time.time()
    (case / 'started.json').write_text(json.dumps({'nodeid': request.node.nodeid, 'started': started}))
    trace = (case / 'stacks.log').open('w', encoding='utf-8')
    faulthandler.dump_traceback_later(100, repeat=True, file=trace)
    stop = threading.Event()

    def capture():
        while not stop.is_set():
            for i, log in enumerate(tmp_path.rglob('desktop-update-handoff.log')):
                try:
                    shutil.copyfile(log, case / f'handoff-{i}.log')
                except (PermissionError, FileNotFoundError):
                    pass
            rows = []
            for proc in psutil.Process().children(recursive=True):
                try:
                    rows.append(proc.as_dict(attrs=['pid', 'ppid', 'name', 'create_time', 'cmdline']))
                except psutil.NoSuchProcess:
                    pass
            (case / 'children.json').write_text(json.dumps({'time': time.time(), 'processes': rows}, indent=2))
            stop.wait(2)

    monitor = threading.Thread(target=capture, daemon=True)
    monitor.start()
    yield
    stop.set()
    monitor.join(timeout=5)
    faulthandler.cancel_dump_traceback_later()
    trace.close()
    (case / 'finished.json').write_text(json.dumps({'nodeid': request.node.nodeid, 'finished': time.time()}))
