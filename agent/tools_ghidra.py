"""
Ghidra tool wrappers for ReAct Agent static analysis.
Reads pre-analyzed data (exported by ExportAnalysis.java via analyzeHeadless).
All tools are READ-ONLY — no Ghidra runtime needed.
"""

import json
import os
import re

GHIDRA_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ghidra_data")

# Lazy-loaded data cache
_functions = None
_decompiled = None
_xrefs = None
_memory = None
_callgraph = None


def _ensure_loaded():
    global _functions, _decompiled, _xrefs, _memory, _callgraph
    if _functions is not None:
        return
    try:
        with open(os.path.join(GHIDRA_DATA_DIR, "ghidra_functions.json")) as f:
            _functions = json.load(f)
        with open(os.path.join(GHIDRA_DATA_DIR, "ghidra_decompiled.json")) as f:
            _decompiled = json.load(f)
        with open(os.path.join(GHIDRA_DATA_DIR, "ghidra_xrefs.json")) as f:
            _xrefs = json.load(f)
        with open(os.path.join(GHIDRA_DATA_DIR, "ghidra_memory.json")) as f:
            _memory = json.load(f)
        with open(os.path.join(GHIDRA_DATA_DIR, "ghidra_callgraph.json")) as f:
            _callgraph = json.load(f)
    except Exception as e:
        raise RuntimeError(f"Failed to load Ghidra data: {e}")


def _find_func_by_addr(addr: str) -> dict | None:
    """Look up a function by its address string (e.g. '00401200')."""
    _ensure_loaded()
    addr = addr.lower().lstrip("0x")
    for f in _functions:
        if f["address"] == addr:
            return f
    return None


def _find_func_by_name(name: str) -> dict | None:
    """Look up a function by name (case-insensitive contains)."""
    _ensure_loaded()
    for f in _functions:
        if name.lower() in f["name"].lower():
            return f
    return None


def _resolve_target(target: str) -> str | None:
    """Resolve 'main', '0x...' etc to an address string."""
    target = target.strip()
    if re.match(r'^0x[0-9a-f]+$', target, re.IGNORECASE):
        return target[2:].lower().zfill(8)
    if re.match(r'^[0-9a-f]{6,16}$', target, re.IGNORECASE) and not target.startswith('0x'):
        t = target.lower().zfill(8)
        if _find_func_by_addr(t):
            return t
    # Try name lookup
    f = _find_func_by_name(target)
    if f:
        return f["address"]
    # Try as raw address
    return None


# ── Tool descriptions (OpenAI tool calling format) ──

GHIDRA_TOOL_DESCRIPTIONS = {
    "ghidra_list_functions": {
        "name": "ghidra_list_functions",
        "description": "List all functions detected by Ghidra with addresses, sizes, and signatures.",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    "ghidra_get_decompilation": {
        "name": "ghidra_get_decompilation",
        "description": "Get the full decompiled C code for a function by address or name (e.g. 'main', '0x401216'). Only available for non-external functions.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Function name (e.g. 'main') or address (e.g. '0x401200')"
                }
            },
            "required": ["target"]
        }
    },
    "ghidra_get_xrefs": {
        "name": "ghidra_get_xrefs",
        "description": "List cross-references to a function showing what code/data references it.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Function name or address"
                }
            },
            "required": ["target"]
        }
    },
    "ghidra_get_callgraph": {
        "name": "ghidra_get_callgraph",
        "description": "List functions called by a given function (outgoing calls and jumps).",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Function name or address"
                }
            },
            "required": ["target"]
        }
    },
    "ghidra_get_memory_map": {
        "name": "ghidra_get_memory_map",
        "description": "List memory blocks with start/end addresses, permissions, and sizes.",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    "ghidra_search_strings": {
        "name": "ghidra_search_strings",
        "description": "Search all strings found in the binary by keyword.",
        "parameters": {
            "type": "object",
            "properties": {
                "keyword": {
                    "type": "string",
                    "description": "Keyword to search for in strings (case-insensitive)"
                }
            },
            "required": ["keyword"]
        }
    },
}


# ── Tool implementations ──

def ghidra_list_functions() -> str:
    """Return a formatted list of all Ghidra-detected functions."""
    _ensure_loaded()
    lines = []
    for f in _functions:
        addr = f["address"]
        name = f["name"]
        size = f.get("size", 0)
        sig = f.get("signature", "")
        external = " [EXTERNAL]" if f.get("is_external") else ""
        lines.append(f"0x{addr} ({size:4d}B) {name}{external}")
        lines.append(f"       sig: {sig}")
    return "\n".join(lines)


def ghidra_get_decompilation(target: str) -> str:
    """Get decompiled C code for a function."""
    _ensure_loaded()
    addr = _resolve_target(target)
    if not addr:
        return f"(error: function '{target}' not found)"
    if addr not in _decompiled:
        return f"(error: no decompilation available for 0x{addr})"
    entry = _decompiled[addr]
    name = entry.get("name", "unknown")
    code = entry.get("code", "")
    return f"// Ghidra decompilation: {name} (0x{addr})\n{code}"


def ghidra_get_xrefs(target: str) -> str:
    """List cross-references to a function."""
    _ensure_loaded()
    addr = _resolve_target(target)
    if not addr:
        return f"(error: function '{target}' not found)"
    if addr not in _xrefs:
        return f"(no cross-references to 0x{addr})"
    entries = _xrefs[addr]
    lines = [f"Cross-references to 0x{addr}:"]
    for x in entries:
        from_addr = x.get("from", "?")
        ref_type = x.get("ref_type", "?")
        lines.append(f"  {from_addr:25s} type={ref_type}")
    return "\n".join(lines)


def ghidra_get_callgraph(target: str) -> str:
    """List calls made by a function."""
    _ensure_loaded()
    addr = _resolve_target(target)
    if not addr:
        return f"(error: function '{target}' not found)"
    if addr not in _callgraph:
        return f"(no outgoing calls from 0x{addr})"
    entries = _callgraph[addr]
    lines = [f"Outgoing calls from 0x{addr}:"]
    for c in entries:
        to_addr = c.get("to", "?")
        to_name = c.get("to_name", "?")
        call_type = c.get("type", "?")
        lines.append(f"  -> 0x{to_addr} ({to_name}) type={call_type}")
    return "\n".join(lines)


def ghidra_get_memory_map() -> str:
    """List memory blocks."""
    _ensure_loaded()
    lines = ["Memory Map:"]
    for b in _memory:
        name = b.get("name", "?")
        start = b.get("start", "?")
        end = b.get("end", "?")
        size = b.get("size", 0)
        perms = b.get("permissions", "?")
        lines.append(f"  0x{start}-0x{end} {size:8d}B {perms:4s} {name}")
    return "\n".join(lines)


def ghidra_search_strings(keyword: str) -> str:
    """Search strings in the decompiled code and function names."""
    _ensure_loaded()
    results = []
    kw = keyword.lower()

    # Search in function names
    for f in _functions:
        if kw in f["name"].lower():
            results.append(f"[function] 0x{f['address']} {f['name']}")

    # Search in decompiled code
    for addr, entry in _decompiled.items():
        code = entry.get("code", "")
        if kw in code.lower():
            name = entry.get("name", "?")
            # Extract context lines
            for line in code.split("\n"):
                if kw in line.lower():
                    results.append(f"[code @ 0x{addr} {name}] {line.strip()}")

    if not results:
        return f"(no matches for '{keyword}')"
    return "\n".join(results)


# ── Tool registry ──

TOOL_MAP = {
    "ghidra_list_functions": ghidra_list_functions,
    "ghidra_get_decompilation": ghidra_get_decompilation,
    "ghidra_get_xrefs": ghidra_get_xrefs,
    "ghidra_get_callgraph": ghidra_get_callgraph,
    "ghidra_get_memory_map": ghidra_get_memory_map,
    "ghidra_search_strings": ghidra_search_strings,
}
