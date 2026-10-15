#!/usr/bin/env python3
"""Export the pinned RustDOS catalog, preserving every scenario and input."""
import ast
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
VARIANTS = {"Cycles", "Focus", "Wait", "Key", "Keys", "Hold", "Type", "PressUntil",
            "WaitFor", "Check", "Shot", "Listen", "Record", "Mode", "Text", "Colours", "Not"}


def debug_value(text):
    def parse(node):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, (ast.List, ast.Tuple)):
            return [parse(x) for x in node.elts]
        if isinstance(node, ast.Name) and node.id in {"None", "ShellIdle", "Running"}:
            return None if node.id == "None" else {"kind": node.id, "args": []}
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and not node.keywords:
            if node.func.id == "Some" and len(node.args) == 1:
                return parse(node.args[0])
            if node.func.id in VARIANTS:
                return {"kind": node.func.id, "args": [parse(x) for x in node.args]}
        raise ValueError(f"unexpected catalog expression: {ast.dump(node)}")
    return parse(ast.parse(text, mode="eval").body)


def export():
    with tempfile.TemporaryDirectory(prefix="retroos-catalog-") as work:
        binary = Path(work) / "export"
        subprocess.run(["rustc", "--edition=2024", str(ROOT / "tools/export_rustdos_suite.rs"),
                        "-o", str(binary)], check=True)
        lines = subprocess.check_output([str(binary)], text=True).splitlines()
    games, scenarios = [], []
    for line in lines:
        kind, *fields = line.split("\t")
        values = [debug_value(x) for x in fields]
        if kind == "GAME":
            game = {"id": values[0], "archives": []}
            games.append(game)
        elif kind == "ARCHIVE":
            game["archives"].append(dict(zip(("file", "url", "sha256"), values)))
        elif kind == "UNPACK":
            game["install"] = {"kind": "Unpack", "strip": values[0]}
        elif kind == "INSTALL":
            game["install"] = dict(zip(("ini", "steps", "wants"), values)) | {"kind": "Installer"}
        elif kind == "SCENARIO":
            scenario = dict(zip(("name", "game", "ini", "timeout"), values)) | {"files": {}}
            scenarios.append(scenario)
        elif kind in {"GOLDEN", "PARTNER", "EXPECT_FAIL", "STEPS"}:
            scenario[kind.lower()] = values[0]
        elif kind == "FILE":
            scenario["files"][values[0]] = values[1]
        else:
            raise ValueError(kind)
    upstream = (ROOT / "third_party/rustdos_suite/UPSTREAM").read_text().splitlines()
    return {"upstream": upstream[0], "revision": upstream[1], "games": games, "scenarios": scenarios}


if __name__ == "__main__":
    output = ROOT / "test/games/rustdos.json"
    catalog = export()
    output.write_text(json.dumps(catalog, indent=2) + "\n")
    print(f"{len(catalog['games'])} installations, {len(catalog['scenarios'])} scenarios -> {output}")
