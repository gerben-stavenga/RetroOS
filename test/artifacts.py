"""Paths supplied by the Bazel test rule; no queries or builds at test time."""
import json
import os
from pathlib import Path


def artifact_path(label):
    files = json.loads(os.environ['RETROOS_TEST_ARTIFACTS'])[label]
    if len(files) != 1:
        raise ValueError(f'{label} must have one output, got {len(files)}')
    return Path(files[0])
