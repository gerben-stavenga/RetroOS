#!/usr/bin/env python3
"""Validate workflow syntax and shell harness syntax with declared test inputs."""
from pathlib import Path
import ast
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    for source in (ROOT / 'test').rglob('*.py'):
        tree = ast.parse(source.read_text(), filename=str(source))
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call) or not call.args:
                continue
            args = call.args[0].elts if isinstance(call.args[0], (ast.List, ast.Tuple)) else call.args
            words = [arg.value for arg in args if isinstance(arg, ast.Constant) and isinstance(arg.value, str)]
            if words and words[0] in ('bazel', 'bazelisk'):
                assert not set(words) & {'build', 'test', 'info', 'cquery'}, (
                    f'{source}:{call.lineno}: declare artifacts on the Bazel test target')
    workflows = sorted((ROOT / '.github/workflows').glob('*.yml'))
    subprocess.run([str(ROOT / 'bazel-bin/test-tools/actionlint'), '-shellcheck=', *map(str, workflows)], check=True)
    scripts = sorted((ROOT / 'test').rglob('*.sh'))
    scripts += [ROOT / 'run.sh', ROOT / 'tools/workspace_status.sh']
    for script in scripts:
        subprocess.run(['bash', '-n', str(script)], check=True)


if __name__ == '__main__':
    main()
