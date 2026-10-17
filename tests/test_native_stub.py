"""Guard against drift between the Rust extension and ``_native.pyi``."""

from __future__ import annotations

import ast
from pathlib import Path

from narrowvine import _native


def _stub_api(path: Path) -> tuple[set[str], set[str], dict[str, set[str]]]:
    tree = ast.parse(path.read_text())
    functions: set[str] = set()
    constants: set[str] = set()
    classes: dict[str, set[str]] = {}
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            classes[node.name] = {
                child.name
                for child in node.body
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                and not child.name.startswith("_")
            }
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.add(node.name)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            constants.add(node.target.id)
    return functions, constants, classes


def _live_api():
    functions, constants, classes = set(), set(), {}
    for name in dir(_native):
        if name.startswith("_"):
            continue
        value = getattr(_native, name)
        if isinstance(value, type):
            classes[name] = {m for m in dir(value) if not m.startswith("_")}
        elif callable(value):
            functions.add(name)
        elif isinstance(value, int):
            constants.add(name)
    return functions, constants, classes


def test_stub_matches_native_module():
    stub_path = Path(_native.__file__).parent / "_native.pyi"
    assert stub_path.is_file(), f"missing stub: {stub_path}"

    stub_funcs, stub_consts, stub_classes = _stub_api(stub_path)
    live_funcs, live_consts, live_classes = _live_api()

    assert stub_funcs == live_funcs
    assert stub_consts == live_consts
    assert set(stub_classes) == set(live_classes)
    for name, methods in stub_classes.items():
        assert methods == live_classes[name], f"{name} stub methods drifted"


def test_py_typed_marker_exists():
    assert (Path(_native.__file__).parent / "py.typed").is_file()
