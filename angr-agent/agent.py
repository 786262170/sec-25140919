#!/usr/bin/env python3
"""ReAct Tool Calling agent for angr-based crackme solving."""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
from pathlib import Path
from typing import Any

from openai import OpenAI

from tools_angr import TOOL_DESCRIPTIONS, TOOL_MAP


SCRIPT_DIR = Path(__file__).resolve().parent
LOG_FILE = SCRIPT_DIR / "logs" / "run.txt"
RESULT_FILE = SCRIPT_DIR / "result.json"

DEEPSEEK_API_BASE = os.environ.get("DEEPSEEK_API_BASE", "https://api.deepseek.com/v1")
DEEPSEEK_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")
MAX_STEPS = int(os.environ.get("MAX_REACT_STEPS", "8"))
MIN_TOOL_STEPS = 3


def log_line(text: str) -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as handle:
        handle.write(text + "\n")


def reset_log(binary_path: str, mode: str) -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("w", encoding="utf-8") as handle:
        handle.write("# ReAct Agent + angr Log\n")
        handle.write(f"# Binary: {binary_path}\n")
        handle.write(f"# Mode: {mode}\n")
        handle.write(f"# Model: {DEEPSEEK_MODEL}\n")
        handle.write(f"# Date: {_dt.datetime.now().isoformat()}\n")
        handle.write("=" * 72 + "\n")


def write_result(result: dict[str, Any]) -> None:
    RESULT_FILE.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def tool_schema() -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": description["name"],
                "description": description["description"],
                "parameters": description["parameters"],
            },
        }
        for description in TOOL_DESCRIPTIONS.values()
    ]


def execute_tool(name: str, arguments: dict[str, Any]) -> str:
    if name not in TOOL_MAP:
        return json.dumps({"ok": False, "error": f"unknown tool: {name}"}, ensure_ascii=False)
    try:
        return str(TOOL_MAP[name](**arguments))
    except Exception as exc:
        return json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False)


def build_system_prompt() -> str:
    return """You are a ReAct binary analysis agent.

Goal:
- Find the concrete input that makes the target print "Success! Flag is found."
- Avoid paths that print "Oops! You are trapped in a dead loop."

Rules:
- Use the available tools. The final password must be supported by tool Observations.
- Do not guess the password without tool evidence.
- Complete at least three Thought -> Action -> Observation rounds before Final Answer.
- For each assistant message, include a concise Thought that explains the next tool choice.
- When done, output exactly one line in this format:
Final Answer: {"password":"...","success_output":"...","avoided_paths":0,"rounds":3}
"""


def parse_final_answer(content: str) -> dict[str, Any] | None:
    match = re.search(r"Final Answer:\s*(\{.*\})", content, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(1))
    except json.JSONDecodeError:
        return None


def run_deepseek(binary_path: str) -> dict[str, Any]:
    api_key = os.environ.get("DEEPSEEK_API_KEY", "")
    if not api_key:
        raise RuntimeError("DEEPSEEK_API_KEY is not set; use --demo for local verification")

    reset_log(binary_path, mode="deepseek")
    client = OpenAI(api_key=api_key, base_url=DEEPSEEK_API_BASE)
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": build_system_prompt()},
        {
            "role": "user",
            "content": (
                "Solve this crackme with the tools. "
                f"Binary path: {binary_path}. Start by inspecting the target."
            ),
        },
    ]

    rounds = 0
    final: dict[str, Any] | None = None

    for step in range(1, MAX_STEPS + 1):
        response = client.chat.completions.create(
            model=DEEPSEEK_MODEL,
            messages=messages,
            tools=tool_schema(),
            tool_choice="auto",
            temperature=0.1,
            max_tokens=2048,
        )
        msg = response.choices[0].message
        content = msg.content or ""
        log_line("")
        log_line(f"## Step {step}")
        log_line(content if content else "Thought: choose the next tool call based on current observations.")

        messages.append(msg.model_dump(exclude_none=True))

        if msg.tool_calls:
            for tool_call in msg.tool_calls:
                rounds += 1
                tool_name = tool_call.function.name
                try:
                    args = json.loads(tool_call.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}
                args.setdefault("binary_path", binary_path)
                observation = execute_tool(tool_name, args)
                log_line(f"Action: {tool_name}")
                log_line(f"Action Input: {json.dumps(args, ensure_ascii=False)}")
                log_line(f"Observation: {observation}")
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "name": tool_name,
                        "content": observation,
                    }
                )
            continue

        candidate = parse_final_answer(content)
        if candidate is not None and rounds >= MIN_TOOL_STEPS:
            final = candidate
            final["rounds"] = rounds
            break

        messages.append(
            {
                "role": "user",
                "content": (
                    "Continue using tools until at least three Thought -> Action -> Observation "
                    "rounds are logged, then provide the Final Answer JSON."
                ),
            }
        )

    if final is None:
        solved = json.loads(execute_tool("solve_input", {"binary_path": binary_path}))
        final = {
            "password": solved.get("password"),
            "success_output": solved.get("success_output"),
            "avoided_paths": "see logs",
            "rounds": rounds,
            "source": "tool_fallback_after_max_steps",
        }

    write_result(final)
    log_line("")
    log_line(f"Final Answer: {json.dumps(final, ensure_ascii=False)}")
    return final


def run_demo(binary_path: str) -> dict[str, Any]:
    """Run a deterministic local ReAct-style sequence when no API key is available."""
    reset_log(binary_path, mode="demo")
    steps = [
        (
            "Thought: I need target metadata first so the later symbolic execution uses the right function.",
            "inspect_target",
            {"binary_path": binary_path},
        ),
        (
            "Thought: The target contains Success and trapped strings, so I should ask angr to find success while avoiding trap output.",
            "explore_paths",
            {"binary_path": binary_path, "max_steps": 200},
        ),
        (
            "Thought: A success state was found, so I should concretize and verify the input against the executable.",
            "solve_input",
            {"binary_path": binary_path},
        ),
    ]

    last_observation: dict[str, Any] = {}
    avoided_paths: Any = 0
    for index, (thought, tool_name, args) in enumerate(steps, start=1):
        observation = execute_tool(tool_name, args)
        try:
            parsed = json.loads(observation)
        except json.JSONDecodeError:
            parsed = {"raw": observation}
        if tool_name == "explore_paths":
            avoided_paths = parsed.get("avoided_paths", 0)
        last_observation = parsed
        log_line("")
        log_line(f"## Step {index}")
        log_line(thought)
        log_line(f"Action: {tool_name}")
        log_line(f"Action Input: {json.dumps(args, ensure_ascii=False)}")
        log_line(f"Observation: {observation}")

    result = {
        "password": last_observation.get("password"),
        "success_output": last_observation.get("success_output"),
        "verification": last_observation.get("verification"),
        "avoided_paths": avoided_paths,
        "rounds": len(steps),
        "mode": "demo",
    }
    write_result(result)
    log_line("")
    log_line(f"Final Answer: {json.dumps(result, ensure_ascii=False)}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="ReAct + angr crackme solver")
    parser.add_argument("binary", help="Path to the compiled crackme binary")
    parser.add_argument("--demo", action="store_true", help="Run deterministic local tool sequence without DeepSeek")
    args = parser.parse_args()

    binary_path = str(Path(args.binary).expanduser().resolve())
    if args.demo:
        result = run_demo(binary_path)
    else:
        result = run_deepseek(binary_path)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"log: {LOG_FILE}")
    print(f"result: {RESULT_FILE}")


if __name__ == "__main__":
    main()
