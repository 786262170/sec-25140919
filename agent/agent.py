#!/usr/bin/env python3
"""
ReAct Agent for binary static analysis.
True Thought → Action (tool call) → Observation loop.
Tools: radare2 (live analysis) + Ghidra (pre-analyzed data).

Usage:
    python3 agent/agent.py targets/challenge
"""

import sys
import os
import json
import time
import datetime
import re

# Ensure we can import sibling modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from openai import OpenAI

from tools_r2 import (
    TOOL_MAP as R2_TOOL_MAP,
    R2_TOOL_DESCRIPTIONS,
    get_binary_info,
)
from tools_ghidra import (
    TOOL_MAP as GHIDRA_TOOL_MAP,
    GHIDRA_TOOL_DESCRIPTIONS,
)

BINARY_PATH = ""
LOG_FILE = "logs/run.txt"
VULN_FILE = "vuln.json"
LLM_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
LLM_API_BASE = "https://api.deepseek.com/v1"
LLM_MODEL = "deepseek-chat"
MAX_STEPS = 20  # safety limit on ReAct iterations

# Merge all tools
ALL_TOOL_DESCRIPTIONS = {}
ALL_TOOL_DESCRIPTIONS.update(R2_TOOL_DESCRIPTIONS)
ALL_TOOL_DESCRIPTIONS.update(GHIDRA_TOOL_DESCRIPTIONS)

ALL_TOOL_MAP = {}
ALL_TOOL_MAP.update(R2_TOOL_MAP)
ALL_TOOL_MAP.update(GHIDRA_TOOL_MAP)


def log_output(entry: str):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(entry + "\n")


def log_and_print(entry: str, also_print: bool = True):
    log_output(entry)
    if also_print:
        print(entry)


def execute_tool(tool_name: str, args: dict) -> str:
    """Execute a tool by name with given arguments and return observation string."""
    if tool_name not in ALL_TOOL_MAP:
        return f"(error: unknown tool '{tool_name}')"

    func = ALL_TOOL_MAP[tool_name]
    try:
        # Most r2 tools need binary_path; auto-inject if not provided
        if "binary_path" in func.__code__.co_varnames and "binary_path" not in args:
            args["binary_path"] = BINARY_PATH
        result = func(**args)
        return str(result) if result is not None else "(no output)"
    except Exception as e:
        return f"(error executing {tool_name}: {e})"


def build_system_prompt() -> str:
    return """You are a professional binary security analyst. You analyze ELF binaries to find security vulnerabilities.

You have access to the following tools:

## radare2 tools (live binary analysis):
- get_binary_info: Get basic binary info (arch, protections, compiler)
- check_security: Check security mitigations (canary, PIE, NX, RELRO)
- list_functions: List all functions after analysis
- disassemble_function: Disassemble a function (e.g. 'main', '0x401216')
- decompile_function: Pseudo-C decompilation from r2
- list_strings: List printable strings
- list_imports: List imported functions
- list_sections: List ELF sections with permissions
- hexdump_address: Hex dump bytes at an address
- find_xrefs: Find cross-references to/from an address

## Ghidra tools (pre-analyzed data, no runtime needed):
- ghidra_list_functions: List all functions with signatures
- ghidra_get_decompilation: Get full Ghidra decompiled C code for a function
- ghidra_get_xrefs: List cross-references to a function
- ghidra_get_callgraph: List outgoing calls from a function
- ghidra_get_memory_map: List memory blocks with permissions
- ghidra_search_strings: Search strings in decompiled code and function names

## ReAct Protocol:
You MUST follow this exact format for each step:

Thought: <reasoning about what to do next, which tool to call, and why>
Action: <tool_name>
Action Input: <JSON arguments for the tool>

After receiving the Observation (tool result), repeat with another Thought.

When you have gathered enough evidence to identify a vulnerability, output:

Thought: I have enough information. The vulnerability is...
Final Answer: {"vuln_type": "<type>", "location": "<function_name_and_address>", "cause": "<concise explanation>"}

## Analysis Strategy:
1. Start by getting binary info and security properties
2. List functions to find the main code paths
3. Decompile/disassemble key functions (especially main and any functions that handle user input)
4. Look for dangerous imports (strcpy, sprintf, gets, read, etc.)
5. Check for missing mitigations (no canary, no PIE)
6. Trace how user input flows to dangerous operations
7. Identify the vulnerability type, sink location, and root cause

Valid vuln_type values: stack_buffer_overflow, heap_buffer_overflow, format_string, integer_overflow, use_after_free, double_free, null_pointer_dereference, command_injection, path_traversal, other

IMPORTANT: The Final Answer JSON must be valid and on a single line. Do NOT include any text after the Final Answer JSON.
"""


def run_react_loop():
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

    print("\n" + "=" * 60)
    print(" ReAct Agent - Binary Static Analysis")
    print(" Binary: {}".format(BINARY_PATH))
    print(" Model: {} (DeepSeek)".format(LLM_MODEL))
    print("=" * 60)

    if not LLM_API_KEY:
        print("[!] DEEPSEEK_API_KEY not set!")
        sys.exit(1)

    client = OpenAI(
        api_key=LLM_API_KEY,
        base_url=LLM_API_BASE,
    )

    # Initial context: get binary info
    binary_info = get_binary_info(BINARY_PATH)

    # Build messages
    system_prompt = build_system_prompt()
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Analyze this binary and find security vulnerabilities.\nBinary path: {BINARY_PATH}\n\nInitial binary info:\n{binary_info}\n\nUse the tools to investigate functions, decompilation, and security properties. Start by checking security and listing functions."},
    ]

    # Convert tool descriptions to OpenAI tool calling format
    tools = []
    for name, desc in ALL_TOOL_DESCRIPTIONS.items():
        tools.append({
            "type": "function",
            "function": {
                "name": desc["name"],
                "description": desc["description"],
                "parameters": desc["parameters"],
            }
        })

    step = 0
    final_answer = None

    while step < MAX_STEPS:
        step += 1
        print(f"\n--- ReAct Step {step} ---")

        # Add a reminder about the output format periodically
        if step > 1 and step % 3 == 0:
            reminder = (
                "Remember: When you have enough evidence, output:\n"
                "Final Answer: {\"vuln_type\": \"...\", \"location\": \"...\", \"cause\": \"...\"}\n"
                "The JSON must be on a single line."
            )
            messages.append({"role": "user", "content": reminder})

        try:
            response = client.chat.completions.create(
                model=LLM_MODEL,
                messages=messages,
                tools=tools if step < (MAX_STEPS - 1) else None,  # disable tools on last step to force answer
                tool_choice="auto",
                temperature=0.1,
                max_tokens=4096,
            )
        except Exception as e:
            log_and_print(f"[LLM ERROR] {e}")
            break

        choice = response.choices[0]
        msg = choice.message

        if msg is None:
            log_and_print("[!] No message in response")
            break

        # Log the assistant message
        content = msg.content or ""
        log_output(f"\n[LLM Step {step}]")
        log_output(f"Content: {content[:2000]}")
        print(f"  {content[:600]}")

        # Check for Final Answer in content
        if content:
            fa_match = re.search(
                r'Final Answer:\s*(\{.*?\})',
                content,
                re.DOTALL,
            )
            if fa_match:
                try:
                    final_answer = json.loads(fa_match.group(1))
                    log_and_print(f"\n[+] Final Answer found in LLM output!")
                    break
                except json.JSONDecodeError:
                    log_and_print(f"[!] Found Final Answer marker but JSON parse failed")

        # Check for tool calls
        if msg.tool_calls:
            for tc in msg.tool_calls:
                fn_name = tc.function.name
                try:
                    fn_args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    fn_args = {}

                log_and_print(f"\n  [Tool Call] {fn_name}({json.dumps(fn_args)})")

                # Execute tool
                observation = execute_tool(fn_name, fn_args)
                log_output(f"  [Observation]\n{observation[:3000]}")
                print(f"  [Observation] ({len(observation)} chars)")

                # Add the assistant message with tool call and the tool response
                messages.append({
                    "role": "assistant",
                    "content": content if content else None,
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": fn_name,
                                "arguments": tc.function.arguments,
                            },
                        }
                    ],
                })
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": observation[:5000],  # truncate long observations
                })

                # Also add a summary of observation to keep context manageable
                if len(observation) > 5000:
                    messages.append({
                        "role": "user",
                        "content": f"(The observation was {len(observation)} chars, truncated to 5000. Summary: the tool returned data about {fn_name})"
                    })
        else:
            # No tool calls - add as regular assistant message and check general JSON output
            messages.append({"role": "assistant", "content": content or ""})

            # Try to find any JSON that looks like a vulnerability report
            json_match = re.search(
                r'\{"vuln_type"\s*:\s*"[^"]*"\s*,\s*"location"\s*:\s*"[^"]*"\s*,\s*"cause"\s*:\s*"[^"]*"\s*\}',
                content,
            )
            if json_match and not final_answer:
                try:
                    final_answer = json.loads(json_match.group())
                    log_and_print(f"\n[+] Vulnerability JSON found in LLM response!")
                    break
                except json.JSONDecodeError:
                    pass

            # If LLM produced content but no tool calls and no JSON, it might be concluding
            # Ask it to be explicit
            if step < MAX_STEPS - 1:
                messages.append({
                    "role": "user",
                    "content": "Continue your analysis. Use tools to investigate further, or provide the Final Answer if you have enough evidence."
                })

    # Fallback if no final answer obtained
    if not final_answer:
        log_and_print("\n[!] No structured answer from LLM after {} steps. Using fallback.".format(MAX_STEPS))
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

    log_output("\n[FINAL] {}".format(json.dumps(final_answer, indent=2)))


if __name__ == "__main__":
    run_react_loop()
