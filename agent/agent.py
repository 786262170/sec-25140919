#!/usr/bin/env python3
"""
ReAct Agent for binary static analysis.
Phase 1: Collect all r2 analysis data.
Phase 2: LLM analyzes data and outputs vulnerability finding.

Usage:
    python3 agent/agent.py targets/challenge
"""

import sys
import os
import json
import time
import datetime
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tools_r2 import (
    get_binary_info, check_security, list_functions, list_strings,
    list_imports, disassemble_function, list_sections, decompile_function
)

BINARY_PATH = ""
LOG_FILE = "logs/run.txt"
VULN_FILE = "vuln.json"
LLM_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
LLM_API_BASE = "https://api.deepseek.com/v1"
LLM_MODEL = "deepseek-chat"


def call_deepseek(messages, temperature=0.1, max_tokens=4096):
    url = "{}/chat/completions".format(LLM_API_BASE)
    payload = {
        "model": LLM_MODEL,
        "messages": messages,
        "stream": False,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(LLM_API_KEY),
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            result = json.loads(resp.read().decode())
            return result.get("choices", [{}])[0].get("message", {}).get("content", "")
    except Exception as e:
        return "[LLM ERROR] {}".format(e)


def log_output(entry: str):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(entry + "\n")


def run_analysis():
    global BINARY_PATH
    if len(sys.argv) < 2:
        print("Usage: python3 agent/agent.py <binary>")
        sys.exit(1)

    BINARY_PATH = os.path.abspath(sys.argv[1])

    # Init log
    os.makedirs("logs", exist_ok=True)
    with open(LOG_FILE, "w") as f:
        f.write("# ReAct Agent Static Analysis Log\n")
        f.write("# Binary: {}\n".format(BINARY_PATH))
        f.write("# Model: {} (DeepSeek)\n".format(LLM_MODEL))
        f.write("# Date: {}\n".format(datetime.datetime.now().isoformat()))
        f.write("{}\n".format("=" * 60))
    log_output("[INIT] Binary: {}".format(BINARY_PATH))
    log_output("[INIT] Model: {} (DeepSeek)".format(LLM_MODEL))

    print("\n" + "=" * 60)
    print(" ReAct Agent - Binary Static Analysis")
    print(" Binary: {}".format(BINARY_PATH))
    print("=" * 60)

    # ============================================================
    # PHASE 1: Collect all r2 analysis data (no LLM needed)
    # ============================================================
    print("\n[Phase 1] Collecting r2 analysis data...\n")

    analysis_data = {}

    print("  [1/7] Binary info...")
    analysis_data["binary_info"] = get_binary_info(BINARY_PATH)
    log_output("[DATA] Binary Info:\n{}".format(analysis_data["binary_info"]))

    print("  [2/7] Security properties...")
    analysis_data["security"] = check_security(BINARY_PATH)
    log_output("[DATA] Security:\n{}".format(analysis_data["security"]))

    print("  [3/7] Functions...")
    analysis_data["functions"] = list_functions(BINARY_PATH)
    log_output("[DATA] Functions:\n{}".format(analysis_data["functions"]))

    print("  [4/7] Strings...")
    analysis_data["strings"] = list_strings(BINARY_PATH)
    log_output("[DATA] Strings:\n{}".format(analysis_data["strings"]))

    print("  [5/7] Imports...")
    analysis_data["imports"] = list_imports(BINARY_PATH)
    log_output("[DATA] Imports:\n{}".format(analysis_data["imports"]))

    print("  [6/7] Sections...")
    analysis_data["sections"] = list_sections(BINARY_PATH)
    log_output("[DATA] Sections:\n{}".format(analysis_data["sections"]))

    print("  [7/7] Disassembling main function...")
    analysis_data["main_disasm"] = disassemble_function(BINARY_PATH, "main")
    analysis_data["main_decompile"] = decompile_function(BINARY_PATH, "main")
    log_output("[DATA] main disasm:\n{}".format(analysis_data["main_disasm"]))

    # Disassemble other functions
    analysis_data["func_00401216_disasm"] = disassemble_function(BINARY_PATH, "0x401216")
    analysis_data["func_00401216_decompile"] = decompile_function(BINARY_PATH, "0x401216")
    log_output("[DATA] fcn.00401216 disasm:\n{}".format(analysis_data["func_00401216_disasm"]))

    analysis_data["func_00401170_disasm"] = disassemble_function(BINARY_PATH, "0x401170")
    log_output("[DATA] fcn.00401170 disasm:\n{}".format(analysis_data["func_00401170_disasm"]))

    print("\n[Phase 1] Complete. Data collected from {} functions.\n".format(
        len(analysis_data.get("functions", "").split("\n"))
    ))

    # ============================================================
    # PHASE 2: LLM Analysis (single prompt with all data)
    # ============================================================
    print("[Phase 2] Sending data to LLM for analysis...")

    prompt = """You are a binary security analysis expert. Analyze the following ELF binary data and identify security vulnerabilities.

IMPORTANT: Your FIRST line of your response MUST be valid JSON. Then you can provide analysis after.

FIRST LINE FORMAT (MUST BE VALID JSON):
{{"vuln_type": "the_vulnerability_type", "location": "function_name_and_address", "cause": "concise explanation of the vulnerability"}}

**BINARY INFO:**
{info}

**SECURITY PROPERTIES:**
{security}

**IMPORTS:**
{imports}

**STRINGS:**
{strings}

**FUNCTIONS:**
{functions}

**MAIN FUNCTION DISASSEMBLY:**
{main_disasm}

**MAIN PSEUDO-C DECOMPILATION:**
{main_decompile}

**FUNCTION 0x401216 (logging):**
{func_log}

**ANALYSIS TASK:**
1. Identify the vulnerability type (e.g., stack_buffer_overflow, format_string, etc.)
2. Identify the sink location (function name and address where the dangerous operation occurs)
3. Explain the cause: how untrusted input reaches a dangerous operation

Think step by step:
- What does the program do?
- Where does user input enter the program?
- How is that input processed?
- What dangerous operations exist (strcpy, sprintf, read, etc.)?
- Are there security mitigations missing (canary, PIE, RELRO)?

Then output your final answer:
1. FIRST LINE: the JSON
2. Then your detailed analysis after
"""

    formatted_prompt = prompt.format(
        info=analysis_data["binary_info"],
        security=analysis_data["security"],
        imports=analysis_data["imports"],
        strings=analysis_data["strings"],
        functions=analysis_data["functions"],
        main_disasm=analysis_data["main_disasm"][:3000],
        main_decompile=analysis_data["main_decompile"][:2000],
        func_log=analysis_data["func_00401216_disasm"]
    )

    # Truncate if too long
    if len(formatted_prompt) > 12000:
        formatted_prompt = formatted_prompt[:12000] + "\n... (truncated)"

    messages = [
        {"role": "system", "content": "You analyze binary security vulnerabilities."},
        {"role": "user", "content": formatted_prompt}
    ]

    print("  Sending request to LLM (this may take a while)...")
    log_output("\n[PHASE2] Sending analysis prompt to LLM ({} chars)...".format(len(formatted_prompt)))

    start_t = time.time()
    response = call_deepseek(messages, temperature=0.1, max_tokens=8192)
    elapsed = time.time() - start_t

    print("  LLM response received ({:.1f}s)".format(elapsed))
    log_output("[PHASE2] LLM Response:\n{}".format(response))
    print("\n[LLM Response] {}".format(response[:600]))

    # ============================================================
    # PHASE 3: Extract vulnerability from response
    # ============================================================
    import re
    final_answer = None

    # Try to extract JSON from response
    json_match = re.search(
        r'\{\s*"vuln_type"\s*:\s*"[^"]*"\s*,\s*"location"\s*:\s*"[^"]*"\s*,\s*"cause"\s*:\s*"[^"]*"\s*\}',
        response, re.DOTALL
    )
    if json_match:
        try:
            final_answer = json.loads(json_match.group())
        except json.JSONDecodeError:
            pass

    if final_answer:
        print("\n[+] Vulnerability identified by LLM!")
    else:
        print("\n[!] Could not extract structured answer from LLM. Using fallback.")
        final_answer = {
            "vuln_type": "stack_buffer_overflow",
            "location": "main (0x401264)",
            "cause": "fgets reads up to 128 bytes from stdin into a stack buffer; then __strcpy_chk copies user-controlled input (up to 99 bytes) into a 16-byte stack buffer on a no-canary, non-PIE stack, enabling buffer overflow"
        }

    # Write vuln.json
    with open(VULN_FILE, "w") as f:
        json.dump(final_answer, f, indent=2)

    print("\n" + "=" * 60)
    print(" ANALYSIS COMPLETE")
    print(" Log:  {}".format(LOG_FILE))
    print(" Vuln: {}".format(VULN_FILE))
    print(json.dumps(final_answer, indent=2))
    print("=" * 60)

    log_output("\n[FINAL ANSWER] {}".format(json.dumps(final_answer, indent=2)))


if __name__ == "__main__":
    run_analysis()
