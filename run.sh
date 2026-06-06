#!/usr/bin/env bash
# ReAct Agent - Static Analysis Runner
# Usage: bash run.sh

set -e

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="${PROJECT_DIR}/agent/challenge"
AGENT="${PROJECT_DIR}/agent/agent.py"
LOG_DIR="${PROJECT_DIR}/agent/logs"

echo "[*] ReAct Agent Static Analysis"
echo "[*] Project: ${PROJECT_DIR}"
echo "[*] Binary:  ${BINARY}"
echo "[*] Agent:   ${AGENT}"
echo ""

# Verify binary exists
if [ ! -f "${BINARY}" ]; then
    echo "[!] Binary not found: ${BINARY}"
    exit 1
fi

# Verify file type
file "${BINARY}"

# Verify r2 is available
if ! command -v r2 &>/dev/null; then
    echo "[!] radare2 (r2) not found. Please install it."
    exit 1
fi

echo ""
echo "[*] Starting Agent analysis..."
echo ""

# Run the agent
cd "${PROJECT_DIR}"
python3 "${AGENT}" "${BINARY}"

echo ""
echo "[*] Done."
echo "    Log:  ${LOG_DIR}/run.txt"
echo "    Vuln: ${PROJECT_DIR}/agent/vuln.json"
