#!/usr/bin/env python3
"""angr-backed tools exposed to the ReAct agent."""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


TOOL_DESCRIPTIONS = {
    "inspect_target": {
        "name": "inspect_target",
        "description": "Inspect the target binary and report architecture, entry point, useful symbols, and strings.",
        "parameters": {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the crackme binary.",
                }
            },
            "required": ["binary_path"],
        },
    },
    "explore_paths": {
        "name": "explore_paths",
        "description": "Use angr symbolic execution to find a path that prints Success while avoiding trapped paths.",
        "parameters": {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the crackme binary.",
                },
                "max_steps": {
                    "type": "integer",
                    "description": "Maximum symbolic execution steps.",
                    "default": 200,
                },
            },
            "required": ["binary_path"],
        },
    },
    "solve_input": {
        "name": "solve_input",
        "description": "Solve the symbolic success state for a concrete password and verify it against the target.",
        "parameters": {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the crackme binary.",
                }
            },
            "required": ["binary_path"],
        },
    },
}


@dataclass
class AngrSession:
    binary_path: str | None = None
    found_state: Any | None = None
    symbolic_bytes: list[Any] | None = None
    password: str | None = None
    method: str | None = None
    success_output: str | None = None


SESSION = AngrSession()


def _json(data: dict[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)


def _require_angr():
    try:
        import angr  # type: ignore
        import claripy  # type: ignore
    except ImportError as exc:
        raise RuntimeError("angr is not installed; run `uv sync` first") from exc
    return angr, claripy


def _abs_path(binary_path: str) -> str:
    path = Path(binary_path).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    return str(path.resolve())


def _run_file(binary_path: str) -> str:
    try:
        result = subprocess.run(
            ["file", binary_path],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() or result.stderr.strip()
    except Exception as exc:  # pragma: no cover - diagnostic only
        return f"file command unavailable: {exc}"


def _extract_strings(binary_path: str, min_len: int = 4) -> list[str]:
    data = Path(binary_path).read_bytes()
    pattern = rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}"
    strings = [m.group(0).decode("ascii", errors="replace") for m in re.finditer(pattern, data)]
    interesting = []
    for value in strings:
        if any(token in value for token in ("Success", "Wrong", "trapped", "password", "Flag")):
            interesting.append(value)
    return interesting[:20]


def _load_project(binary_path: str):
    angr, _ = _require_angr()
    return angr.Project(binary_path, auto_load_libs=False)


def _find_symbol(project: Any, names: tuple[str, ...]) -> tuple[str, int] | None:
    for name in names:
        symbol = project.loader.find_symbol(name)
        if symbol is not None and getattr(symbol, "rebased_addr", None) is not None:
            return name, int(symbol.rebased_addr)
    return None


def inspect_target(binary_path: str) -> str:
    """Inspect target metadata and strings."""
    resolved = _abs_path(binary_path)
    if not os.path.exists(resolved):
        return _json({"ok": False, "error": f"binary not found: {resolved}"})

    info: dict[str, Any] = {
        "ok": True,
        "binary_path": resolved,
        "file": _run_file(resolved),
        "interesting_strings": _extract_strings(resolved),
    }

    try:
        project = _load_project(resolved)
        check_symbol = _find_symbol(project, ("check_password", "_check_password"))
        main_symbol = _find_symbol(project, ("main", "_main"))
        info.update(
            {
                "arch": project.arch.name,
                "bits": project.arch.bits,
                "entry": hex(project.entry),
                "check_password": hex(check_symbol[1]) if check_symbol else None,
                "main": hex(main_symbol[1]) if main_symbol else None,
                "loader_format": project.loader.main_object.__class__.__name__,
                "analysis_hint": "Prefer check_password direct symbolic call; avoid gadget_trap and trapped output.",
            }
        )
    except Exception as exc:
        info.update({"ok": False, "angr_error": str(exc)})

    return _json(info)


def _make_symbolic_password(state: Any, claripy: Any, input_addr: int) -> list[Any]:
    symbolic_bytes = [claripy.BVS(f"pw_{idx}", 8) for idx in range(4)]
    for idx, byte in enumerate(symbolic_bytes):
        state.memory.store(input_addr + idx, byte)
        state.solver.add(byte >= 0x20)
        state.solver.add(byte <= 0x7E)
    state.memory.store(input_addr + 4, claripy.BVV(0, 8))
    for idx in range(5, 10):
        state.memory.store(input_addr + idx, claripy.BVV(0, 8))
    return symbolic_bytes


def _stdout_text(state: Any) -> str:
    try:
        raw = state.posix.dumps(1)
        if isinstance(raw, bytes):
            return raw.decode("utf-8", errors="replace")
        return str(raw)
    except Exception:
        return ""


def _return_value_is_one(state: Any) -> bool:
    register = "eax"
    arch_name = getattr(state.arch, "name", "").lower()
    if "arm" in arch_name or "aarch64" in arch_name:
        register = "w0"
    try:
        value = getattr(state.regs, register)
        return bool(state.solver.satisfiable(extra_constraints=[value == 1]))
    except Exception:
        return False


def _password_from_state(state: Any, symbolic_bytes: list[Any]) -> str:
    values = [state.solver.eval(byte, cast_to=int) for byte in symbolic_bytes]
    return bytes(values).decode("ascii", errors="replace")


def explore_paths(binary_path: str, max_steps: int = 200) -> str:
    """Explore paths with angr and keep the first success state in SESSION."""
    resolved = _abs_path(binary_path)
    if not os.path.exists(resolved):
        return _json({"ok": False, "error": f"binary not found: {resolved}"})

    angr, claripy = _require_angr()
    project = _load_project(resolved)
    symbol = _find_symbol(project, ("check_password", "_check_password"))
    if symbol is None:
        return _json(
            {
                "ok": False,
                "error": "check_password symbol not found; compile with debug symbols and without stripping",
            }
        )

    input_addr = 0x100000
    return_addr = 0x500000
    state = project.factory.call_state(symbol[1], input_addr, ret_addr=return_addr)
    symbolic_bytes = _make_symbolic_password(state, claripy, input_addr)

    def is_success(candidate: Any) -> bool:
        return "Success!" in _stdout_text(candidate) or (
            candidate.addr == return_addr and _return_value_is_one(candidate)
        )

    def should_avoid(candidate: Any) -> bool:
        output = _stdout_text(candidate)
        return "trapped" in output or "dead loop" in output or "Wrong password!" in output

    simgr = project.factory.simulation_manager(state)
    found_states: list[Any] = []
    for _ in range(max_steps):
        for active_state in list(simgr.active):
            if is_success(active_state):
                found_states.append(active_state)
                break
        if found_states:
            break
        simgr.move(
            from_stash="active",
            to_stash="avoid",
            filter_func=lambda candidate: (
                candidate.addr == return_addr and not is_success(candidate)
            )
            or should_avoid(candidate),
        )
        if not simgr.active:
            break
        simgr.step()

    if not found_states:
        return _json(
            {
                "ok": False,
                "method": "angr_call_state",
                "error": "no success state found",
                "active": len(simgr.active),
                "deadended": len(simgr.deadended),
                "avoided": len(simgr.avoid),
            }
        )

    found = found_states[0]
    password = _password_from_state(found, symbolic_bytes)
    output = _stdout_text(found)
    SESSION.binary_path = resolved
    SESSION.found_state = found
    SESSION.symbolic_bytes = symbolic_bytes
    SESSION.password = password
    SESSION.method = "angr_call_state"
    SESSION.success_output = output if output else "check_password returned 1"

    return _json(
        {
            "ok": True,
            "method": SESSION.method,
            "target_function": symbol[0],
            "target_address": hex(symbol[1]),
            "password_candidate": password,
            "success_output": (output or "check_password returned 1").strip(),
            "avoided_paths": len(simgr.avoid),
            "deadended_paths": len(simgr.deadended),
        }
    )


def solve_input(binary_path: str) -> str:
    """Return and verify the concrete input for the current success state."""
    resolved = _abs_path(binary_path)
    if SESSION.password is None or SESSION.binary_path != resolved:
        exploration = json.loads(explore_paths(resolved))
        if not exploration.get("ok"):
            return _json({"ok": False, "error": "exploration failed", "exploration": exploration})

    password = SESSION.password or ""
    verification: dict[str, Any] = {"attempted": False}
    verify_path = resolved
    if not os.access(verify_path, os.X_OK):
        sibling_native = str(Path(resolved).with_name("crackme"))
        if os.access(sibling_native, os.X_OK):
            verify_path = sibling_native

    if os.access(verify_path, os.X_OK):
        try:
            proc = subprocess.run(
                [verify_path],
                input=password + "\n",
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            combined = (proc.stdout or "") + (proc.stderr or "")
            verification = {
                "attempted": True,
                "binary": verify_path,
                "returncode": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "success": "Success! Flag is found." in combined,
            }
        except Exception as exc:
            verification = {"attempted": True, "success": False, "error": str(exc)}

    return _json(
        {
            "ok": True,
            "password": password,
            "success_output": (SESSION.success_output or "").strip(),
            "method": SESSION.method,
            "verification": verification,
        }
    )


TOOL_MAP = {
    "inspect_target": inspect_target,
    "explore_paths": explore_paths,
    "solve_input": solve_input,
}
