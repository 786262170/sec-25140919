"""
radare2 tool wrappers for ReAct Agent static analysis.
All tools are READ-ONLY — no modification to the binary.
"""

import subprocess
import json
import tempfile
import os

R2_CMD = ["r2", "-q", "-e", "bin.relocs.apply=true", "-e", "bin.cache=true"]

R2_TOOL_DESCRIPTIONS = {
    "get_binary_info": {
        "name": "get_binary_info",
        "description": "Get basic info about the binary (arch, bits, type, compiler, protections).",
        "parameters": {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary file"
                }
            },
            "required": ["binary_path"]
        }
    },
    "list_functions": {
        "name": "list_functions",
        "description": "List all functions in the binary after deep analysis.",
        "parameters": {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary file"
                }
            },
            "required": ["binary_path"]
        }
    },
    "disassemble_function": {
        "name": "disassemble_function",
        "description": "Disassemble a specific function at given address or name.",
        "parameters": {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary file"
                },
                "function": {
                    "type": "string",
                    "description": "Function address (hex) or name (e.g., 'main', '0x401264')"
                }
            },
            "required": ["binary_path", "function"]
        }
    },
    "check_security": {
        "name": "check_security",
        "description": "Check security mitigations: canary, PIE, NX, RELRO.",
        "parameters": {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary file"
                }
            },
            "required": ["binary_path"]
        }
    },
    "list_strings": {
        "name": "list_strings",
        "description": "List all printable strings in the binary (rodata section).",
        "parameters": {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary file"
                }
            },
            "required": ["binary_path"]
        }
    },
    "list_imports": {
        "name": "list_imports",
        "description": "List all imported functions/symbols.",
        "parameters": {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary file"
                }
            },
            "required": ["binary_path"]
        }
    },
    "hexdump_address": {
        "name": "hexdump_address",
        "description": "Hex dump bytes at a specific address range.",
        "parameters": {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary file"
                },
                "address": {
                    "type": "string",
                    "description": "Address in hex (e.g., '0x401264')"
                },
                "size": {
                    "type": "integer",
                    "description": "Number of bytes to dump (default: 64)"
                }
            },
            "required": ["binary_path", "address"]
        }
    },
    "list_sections": {
        "name": "list_sections",
        "description": "List ELF section headers with permissions.",
        "parameters": {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary file"
                }
            },
            "required": ["binary_path"]
        }
    },
    "find_xrefs": {
        "name": "find_xrefs",
        "description": "Find cross-references to/from a given address.",
        "parameters": {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary file"
                },
                "address": {
                    "type": "string",
                    "description": "Address in hex (e.g., '0x401264')"
                }
            },
            "required": ["binary_path", "address"]
        }
    },
    "decompile_function": {
        "name": "decompile_function",
        "description": "Get a pseudo-C decompilation of a function (r2 pdc).",
        "parameters": {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary file"
                },
                "function": {
                    "type": "string",
                    "description": "Function address (hex) or name"
                }
            },
            "required": ["binary_path", "function"]
        }
    }
}


def _r2_cmd(binary_path: str, cmd: str) -> str:
    """Run a single r2 command and return output."""
    try:
        result = subprocess.run(
            R2_CMD + ["-c", cmd, binary_path],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout
        if result.stderr:
            # Filter warnings
            stderr_lines = [l for l in result.stderr.split("\n") if "WARN" not in l and "INFO" not in l]
            if stderr_lines:
                output += "\n[stderr] " + "\n".join(stderr_lines)
        return output.strip() or "(no output)"
    except subprocess.TimeoutExpired:
        return "(timeout)"
    except Exception as e:
        return f"(error: {e})"


def get_binary_info(binary_path: str) -> str:
    """Get file info and architecture details."""
    out = _r2_cmd(binary_path, "iIj")
    try:
        data = json.loads(out)
        fields = [
            "arch", "bits", "bintype", "class", "compiler",
            "endian", "machine", "os", "stripped", "static",
            "canary", "nx", "pic", "relro", "sanitize", "lang",
            "binsz", "havecode", "intrp"
        ]
        lines = []
        for f in fields:
            if f in data:
                lines.append(f"{f}: {data[f]}")
        return "\n".join(lines)
    except json.JSONDecodeError:
        return out


def list_functions(binary_path: str) -> str:
    """Run aaa analysis and list functions with sizes."""
    out = _r2_cmd(binary_path, "aaa 2>/dev/null; aflj")
    try:
        funcs = json.loads(out)
        lines = []
        for f in sorted(funcs, key=lambda x: x.get("offset", 0)):
            offset = f.get("offset", 0)
            size = f.get("size", 0)
            name = f.get("name", "unknown")
            lines.append(f"0x{offset:x} ({size:4d}B) {name}")
        return "\n".join(lines) if lines else "(no functions found)"
    except json.JSONDecodeError:
        return out


def disassemble_function(binary_path: str, function: str) -> str:
    """Disassemble a function."""
    if function.startswith("0x") or function.startswith("0X"):
        cmd = f"aaa 2>/dev/null; s {function}; pdf"
    else:
        cmd = f"aaa 2>/dev/null; pdf @ {function}"
    return _r2_cmd(binary_path, cmd)


def check_security(binary_path: str) -> str:
    """Check binary security features."""
    out = _r2_cmd(binary_path, "iIj")
    try:
        data = json.loads(out)
        features = {
            "Stack Canary": not data.get("canary", True),
            "PIE (Position Independent)": data.get("pic", False),
            "NX (Non-Executable Stack)": data.get("nx", False),
            "RELRO": data.get("relro", "none"),
            "Stripped": data.get("stripped", False),
            "Static Binary": data.get("static", False),
            "Fortify": "Yes" if data.get("lang") == "c" else "Unknown",
        }
        lines = []
        for name, val in features.items():
            status = "✅ Enabled" if val and val != "none" else \
                     "❌ Disabled" if val is False else str(val)
            lines.append(f"{name}: {status}")
        return "\n".join(lines)
    except json.JSONDecodeError:
        return out


def list_strings(binary_path: str) -> str:
    """List strings in .rodata section."""
    out = _r2_cmd(binary_path, "aaa 2>/dev/null; izj")
    try:
        strs = json.loads(out)
        lines = []
        for s in strs:
            vaddr = s.get("vaddr", 0)
            string = s.get("string", "")
            lines.append(f"0x{vaddr:x}: \"{string}\"")
        return "\n".join(lines) if lines else "(no strings found)"
    except json.JSONDecodeError:
        return _r2_cmd(binary_path, "aaa 2>/dev/null; iz")


def list_imports(binary_path: str) -> str:
    """List imported symbols."""
    out = _r2_cmd(binary_path, "iiij")
    try:
        imports = json.loads(out)
        lines = []
        for imp in imports:
            name = imp.get("name", "unknown")
            plt = imp.get("plt", 0)
            lines.append(f"0x{plt:x} {name}")
        return "\n".join(lines) if lines else "(no imports)"
    except json.JSONDecodeError:
        return _r2_cmd(binary_path, "iii")


def hexdump_address(binary_path: str, address: str, size: int = 64) -> str:
    """Hex dump bytes at address."""
    cmd = f"s {address}; px {size}"
    return _r2_cmd(binary_path, cmd)


def list_sections(binary_path: str) -> str:
    """List ELF sections."""
    out = _r2_cmd(binary_path, "Sj")
    try:
        sections = json.loads(out)
        lines = []
        for s in sections:
            name = s.get("name", "")
            vaddr = s.get("vaddr", 0)
            size = s.get("size", 0)
            perm = s.get("perm", "")
            lines.append(f"0x{vaddr:x} {size:8d}B {perm:4s} {name}")
        return "\n".join(lines)
    except json.JSONDecodeError:
        return _r2_cmd(binary_path, "S")


def find_xrefs(binary_path: str, address: str) -> str:
    """Find cross-references to/from an address."""
    cmd = f"aaa 2>/dev/null; axt @ {address}"
    out = _r2_cmd(binary_path, cmd)
    if not out or out == "(no output)":
        return "(no cross-references found)"
    return out


def decompile_function(binary_path: str, function: str) -> str:
    """Get pseudo-C decompilation of a function."""
    if function.startswith("0x") or function.startswith("0X"):
        cmd = f"aaa 2>/dev/null; s {function}; pdc"
    else:
        cmd = f"aaa 2>/dev/null; pdc @ {function}"
    return _r2_cmd(binary_path, cmd)


# Map function names to callables
TOOL_MAP = {
    "get_binary_info": get_binary_info,
    "list_functions": list_functions,
    "disassemble_function": disassemble_function,
    "check_security": check_security,
    "list_strings": list_strings,
    "list_imports": list_imports,
    "hexdump_address": hexdump_address,
    "list_sections": list_sections,
    "find_xrefs": find_xrefs,
    "decompile_function": decompile_function,
}
