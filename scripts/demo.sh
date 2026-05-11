#!/usr/bin/env bash
# Clean local demo stores, (re)install extras, run example scripts.
# Usage:
#   ./scripts/demo.sh help
#   ./scripts/demo.sh clean
#   ./scripts/demo.sh install
#   ./scripts/demo.sh run langgraph
#   ./scripts/demo.sh clean install run minimal
#   ./scripts/demo.sh run all

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Demo identity data dirs (relative to repo root; examples use these paths)
DEMO_DATA_DIRS=(
  ".asid-demo"
  ".asid-delegate-demo"
  ".asid-langgraph-multi"
  ".asid-langchain-demo"
  ".asid-swap-demo"
  ".asid-a2a-demo"
)

usage() {
  cat <<'EOF'
autonomous-identity demos

  ./scripts/demo.sh clean              Remove demo data dirs, __pycache__, build artifacts
  ./scripts/demo.sh install            uv sync (or pip) with dev + langchain + langgraph extras
  ./scripts/demo.sh install-a2a        same + a2a-sdk (for examples/a2a_identity_agent)
  ./scripts/demo.sh run <name>       Run one example (see list below)
  ./scripts/demo.sh run all          Run all non-interactive demos in sequence

Examples (name -> script):

  minimal      examples/minimal_local.py
  delegate     examples/delegate_handoff.py
  langchain    examples/langchain_tool.py
  swap         examples/swap_storage_backends.py
  langgraph    examples/langgraph_multi_agent_delegation.py  (needs langgraph extra)
  mcp          examples/mcp_research_server.py               (stdio MCP; blocks)
  a2a-server   examples/a2a_identity_agent/server.py        (needs [a2a] extra; blocks)
  a2a-client   examples/a2a_identity_agent/demo_client.py    (needs server running)

Chain: ./scripts/demo.sh clean install run langgraph
EOF
}

clean() {
  echo "==> clean: demo data dirs"
  for d in "${DEMO_DATA_DIRS[@]}"; do
    if [[ -e "$d" ]]; then
      echo "    rm -rf $d"
      rm -rf "$d"
    fi
  done
  echo "==> clean: Python caches & build artifacts"
  find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
  find . -type d -name .pytest_cache -prune -exec rm -rf {} + 2>/dev/null || true
  rm -rf build dist .eggs
  find . -maxdepth 3 -type d -name '*.egg-info' -prune -exec rm -rf {} + 2>/dev/null || true
  echo "==> clean: done"
}

install() {
  echo "==> install: editable package + dev + langchain + langgraph"
  if command -v uv >/dev/null 2>&1; then
    uv sync --extra dev --extra langchain --extra langgraph
  else
    python3 -m pip install -U pip
    python3 -m pip install -e ".[dev,langchain,langgraph]"
  fi
  echo "==> install: done"
}

install_a2a() {
  echo "==> install-a2a: dev + langchain + langgraph + a2a"
  if command -v uv >/dev/null 2>&1; then
    uv sync --extra dev --extra langchain --extra langgraph --extra a2a
  else
    python3 -m pip install -U pip
    python3 -m pip install -e ".[dev,langchain,langgraph,a2a]"
  fi
  echo "==> install-a2a: done"
}

run_py() {
  if command -v uv >/dev/null 2>&1; then
    uv run python "$@"
  else
    PYTHONPATH=src python3 "$@"
  fi
}

run_one() {
  local name="${1:?demo name required}"
  case "$name" in
    minimal)
      run_py examples/minimal_local.py
      ;;
    delegate)
      run_py examples/delegate_handoff.py
      ;;
    langchain)
      run_py examples/langchain_tool.py
      ;;
    swap)
      run_py examples/swap_storage_backends.py
      ;;
    langgraph)
      run_py examples/langgraph_multi_agent_delegation.py
      ;;
    mcp)
      echo "Starting stdio MCP server (Ctrl+C to stop). Configure Cursor MCP to this command if needed."
      run_py examples/mcp_research_server.py
      ;;
    a2a-server)
      run_py examples/a2a_identity_agent/server.py
      ;;
    a2a-client)
      run_py examples/a2a_identity_agent/demo_client.py
      ;;
    all)
      for d in minimal delegate langchain swap langgraph; do
        echo ""
        echo "---------- run: $d ----------"
        run_one "$d"
      done
      echo ""
      echo "(Skipped 'mcp' — long-running stdio server. Run: ./scripts/demo.sh run mcp)"
      ;;
    *)
      echo "Unknown demo: $name" >&2
      usage >&2
      exit 1
      ;;
  esac
}

if [[ $# -eq 0 ]]; then
  usage
  exit 0
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    help|-h|--help)
      usage
      exit 0
      ;;
    clean)
      clean
      shift
      ;;
    install)
      install
      shift
      ;;
    install-a2a)
      install_a2a
      shift
      ;;
    run)
      shift
      [[ $# -gt 0 ]] || { echo "run: missing demo name" >&2; exit 1; }
      run_one "$1"
      shift
      ;;
    *)
      echo "Unknown command: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done
