"""Run the approved bounded native diagnosis phases from a temporary branch."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time

FILES = {
    'commit_outcome': 'tests/scripts/desktop_update/test_desktop_update_windows_commit_outcome.py',
    'handoff_lineage': 'tests/scripts/desktop_update/test_desktop_update_windows_handoff_lineage.py',
    'marker': 'tests/scripts/desktop_update/test_desktop_update_windows_marker.py',
    'marker_lock': 'tests/scripts/desktop_update/test_desktop_update_windows_marker_lock.py',
}


def run_case(paths, workers, output, pytest_args=()):
    output.mkdir(parents=True, exist_ok=True)
    command = [os.environ['DIAG_BASH'], 'scripts/run_tests.sh', *paths, '-j', str(workers), '--',
               '-m', 'platforms and not integration', '-v', '--tb=long',
               '-o', 'faulthandler_timeout=100', '-p', 'tests.ci.diag_r_windows',
               '--diag-output', str(output), *pytest_args]
    start = time.time()
    with (output / 'runner.log').open('w', encoding='utf-8') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=False)
    receipt = {'command': command, 'started': start, 'finished': time.time(),
               'exit_code': result.returncode,
               'source_sha': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()}
    (output / 'invocation.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    print(json.dumps(receipt), flush=True)
    print((output / 'runner.log').read_text(encoding='utf-8', errors='replace'), flush=True)
    return result.returncode


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=['alone', 'overlap', 'full', 'r6', 'probe'])
    parser.add_argument('--file', choices=FILES)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    codes = []
    if args.phase == 'probe':
        for repeat in range(1, 6):
            codes.append(run_case([FILES['commit_outcome']], 1, args.output / str(repeat),
                                  ['-k', 'hanging_update_help_probe_is_bounded']))
    elif args.phase == 'alone':
        for repeat in range(1, 6):
            codes.append(run_case([FILES[args.file]], 1, args.output / str(repeat)))
    elif args.phase == 'overlap':
        for repeat in range(1, 4):
            codes.append(run_case([FILES[key] for key in ['commit_outcome', 'handoff_lineage', 'marker']],
                                  2, args.output / str(repeat)))
    elif args.phase == 'r6':
        for mode in ['alone', 'overlap']:
            for repeat in range(1, 6):
                paths = [FILES['commit_outcome']]
                if mode == 'overlap':
                    paths.append('tests/scripts/desktop_update/test_desktop_update_windows_cwd.py')
                codes.append(run_case(paths, 1 if mode == 'alone' else 2,
                                      args.output / mode / str(repeat),
                                      ['-k', 'r6_release_wait or handoff_children or install_root_cannot']))
    else:
        selected = subprocess.check_output(['python', 'scripts/ci/list_os_marked_tests.py', 'windows'], text=True)
        path_list = os.pathsep.join(selected.splitlines())
        codes.append(run_case(['--files', path_list], 2, args.output / 'full'))
    (args.output / 'summary.json').write_text(json.dumps({'phase': args.phase, 'exits': codes}, indent=2),
                                               encoding='utf-8')
    return int(any(codes))


if __name__ == '__main__':
    raise SystemExit(main())
