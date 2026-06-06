#@category ReActAgent
#@menupath ReActAgent.ExportAnalysis
"""
Ghidra headless script: Export binary analysis data as JSON.
Run with: analyzeHeadless <project_dir> <project_name> -import <binary> -scriptPath <dir> -postScript export_analysis.py <output_dir>

Outputs JSON files used by the ReAct Agent's Ghidra tools.
"""

import json
import os
import sys

from ghidra.program.model.listing import Function, FunctionManager
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import Address
from ghidra.util.task import ConsoleTaskMonitor

# Get output directory from script arguments
output_dir = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
os.makedirs(output_dir, exist_ok=True)

monitor = ConsoleTaskMonitor()
program = getCurrentProgram()
if program is None:
    print("[!] No program loaded")
    sys.exit(1)

listing = program.getListing()
function_manager = program.getFunctionManager()
addr_factory = program.getAddressFactory()

name = program.getName()
print("[*] Exporting analysis for: {}".format(name))


# ---- Functions ----
def export_functions():
    functions = []
    func = function_manager.getFunctions(True)
    for f in func:
        entry = {
            "name": f.getName(),
            "address": str(f.getEntryPoint()),
            "size": f.getBody().getNumAddresses(),
            "signature": str(f.getSignature()),
            "calling_convention": str(f.getCallingConventionName()),
            "has_no_return": f.hasNoReturn(),
            "is_external": f.isExternal(),
            "comment": f.getComment(),
        }
        functions.append(entry)

    with open(os.path.join(output_dir, "ghidra_functions.json"), "w") as fp:
        json.dump(functions, fp, indent=2)
    print("[+] Exported {} functions".format(len(functions)))
    return functions


# ---- Decompilation ----
def decompile_function(func_addr_str):
    """Decompile a specific function by address."""
    try:
        addr = addr_factory.getAddress(func_addr_str)
        func = function_manager.getFunctionAt(addr)
        if func is None:
            return {"error": "Function not found at " + func_addr_str}

        from ghidra.app.decompiler import DecompInterface
        decomp = DecompInterface()
        decomp.openProgram(program)

        results = decomp.decompileFunction(func, 60, monitor)
        if results and results.getDecompiledFunction():
            code = results.getDecompiledFunction().getC()
            return {"address": func_addr_str, "name": func.getName(), "decompiled": code}
        else:
            return {"address": func_addr_str, "name": func.getName(), "decompiled": "(decompilation failed)"}
    except Exception as e:
        return {"error": str(e), "address": func_addr_str}


def export_all_decompilations():
    decomp_results = {}
    func = function_manager.getFunctions(True)
    for f in func:
        if f.isExternal():
            continue
        addr = str(f.getEntryPoint())
        decomp_results[addr] = decompile_function(addr)

    with open(os.path.join(output_dir, "ghidra_decompiled.json"), "w") as fp:
        json.dump(decomp_results, fp, indent=2)
    print("[+] Exported {} decompilations".format(len(decomp_results)))
    return decomp_results


# ---- Cross References ----
def export_xrefs():
    xrefs = {}
    func = function_manager.getFunctions(True)
    for f in func:
        if f.isExternal():
            continue
        addr_str = str(f.getEntryPoint())
        entry_xrefs = []

        # XREFS TO this function
        refs_to = program.getListing().getCodeUnits(f.getBody(), True)
        # Actually use reference manager
        ref_mgr = program.getReferenceManager()
        addr = f.getEntryPoint()
        refs = ref_mgr.getReferencesTo(addr)
        for ref in refs:
            from_addr = ref.getFromAddress()
            ref_type = str(ref.getReferenceType())
            entry_xrefs.append({
                "type": "to",
                "from": str(from_addr),
                "ref_type": ref_type
            })

        if entry_xrefs:
            xrefs[addr_str] = entry_xrefs

    with open(os.path.join(output_dir, "ghidra_xrefs.json"), "w") as fp:
        json.dump(xrefs, fp, indent=2)
    print("[+] Exported xrefs for {} functions".format(len(xrefs)))
    return xrefs


# ---- Data Types ----
def export_data_types():
    dt_mgr = program.getDataTypeManager()
    types = []
    for dt in dt_mgr.getAllDataTypes():
        try:
            types.append({
                "name": str(dt.getName()),
                "size": dt.getLength(),
                "category": str(dt.getCategoryPath()),
                "type": str(type(dt).__name__),
            })
        except:
            pass

    with open(os.path.join(output_dir, "ghidra_datatypes.json"), "w") as fp:
        json.dump(types, fp, indent=2)
    print("[+] Exported {} data types".format(len(types)))


# ---- Memory Map ----
def export_memory():
    mem_blocks = []
    mem = program.getMemory()
    for block in mem.getBlocks():
        entry = {
            "name": block.getName(),
            "start": str(block.getStart()),
            "end": str(block.getEnd()),
            "size": block.getSize(),
            "permissions": "{}{}{}".format(
                "r" if block.isRead() else "",
                "w" if block.isWrite() else "",
                "x" if block.isExecute() else "",
            ),
            "initialized": block.isInitialized(),
        }
        mem_blocks.append(entry)

    with open(os.path.join(output_dir, "ghidra_memory.json"), "w") as fp:
        json.dump(mem_blocks, fp, indent=2)
    print("[+] Exported {} memory blocks".format(len(mem_blocks)))


# ---- Call Graph ----
def export_call_graph():
    calls = {}
    func = function_manager.getFunctions(True)
    for f in func:
        if f.isExternal():
            continue
        caller_addr = str(f.getEntryPoint())
        callees = []
        body = f.getBody()
        code_units = listing.getCodeUnits(body, True)
        for cu in code_units:
            for ref in cu.getReferencesFrom():
                to_addr = ref.getToAddress()
                ref_type = str(ref.getReferenceType())
                if "CALL" in ref_type.upper() or "JUMP" in ref_type.upper():
                    to_func = function_manager.getFunctionAt(to_addr)
                    callees.append({
                        "to": str(to_addr),
                        "to_name": to_func.getName() if to_func else "unknown",
                        "type": ref_type,
                    })
        if callees:
            calls[caller_addr] = callees

    with open(os.path.join(output_dir, "ghidra_callgraph.json"), "w") as fp:
        json.dump(calls, fp, indent=2)
    print("[+] Exported call graph: {} callers".format(len(calls)))


# ---- Main ----
export_functions()
export_all_decompilations()
export_xrefs()
export_data_types()
export_memory()
export_call_graph()

print("[*] Ghidra analysis export complete -> {}".format(output_dir))
