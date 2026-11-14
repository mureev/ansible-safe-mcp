#!/bin/bash
# ansible-safe-mcp installer for macOS and the Claude desktop app.
#   bash install.sh            install or update
#   bash install.sh --check    show what is installed; changes nothing
#   bash install.sh --remove   take out the Claude entry and the installed copy (keeps state, project and venv)
# What it does:
#   1. Finds Python 3.10+ (Homebrew's or uv's; macOS's own is 3.9), makes a venv with ansible-core in it.
#   2. Copies server/ and collections/ to ~/.config/claude-mcp/ansible-safe-mcp/app, read-only. Claude runs that
#      copy, never this folder, so nothing that can write here can change what runs.
#   3. Checks the copy answers the MCP handshake.
#   4. Backs up claude_desktop_config.json, then adds or replaces ONLY the ansible-safe entry.
set -euo pipefail
NAME=ansible-safe
HERE="$(cd "$(dirname "$0")" && pwd)"
DEST="$HOME/.config/claude-mcp/ansible-safe-mcp"
APP="$DEST/app"
VENV="$DEST/venv"
PROJECT="${ASM_PROJECT:-$HOME/ansible-safe}"
CFG="${CLAUDE_CONFIG:-$HOME/Library/Application Support/Claude/claude_desktop_config.json}"
MODE="${1:-install}"; MODE="${MODE#--}"

say() { printf '\033[1m%s\033[0m\n' "$*"; }
ok() { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
die() { printf '\033[31mSTOPPED:\033[0m %s\n' "$*"; exit 1; }

[ "$(uname)" = Darwin ] || die "this installer is for macOS (the server itself runs anywhere: see the README)."
if [ -n "${MAC_TERMINAL:-}" ] && [ "$MODE" != check ]; then
  die "install.sh runs from your own Terminal, not through Claude's tools. --check is fine from anywhere."
fi

find_python() {
  for c in /opt/homebrew/bin/python3.13 /opt/homebrew/bin/python3.12 /opt/homebrew/bin/python3.11 \
           /opt/homebrew/bin/python3.10 /usr/local/bin/python3.13 /usr/local/bin/python3.12 /usr/local/bin/python3.11 \
           "$(command -v python3 || true)"; do
    [ -n "$c" ] && [ -x "$c" ] && "$c" -I -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
      2>/dev/null && { echo "$c"; return 0; }
  done
  if command -v uv >/dev/null 2>&1; then uv python find '>=3.10' 2>/dev/null && return 0; fi
  return 1
}

claude_running() { [ -z "${SKIP_APP_CONTROL:-}" ] && pgrep -x Claude >/dev/null 2>&1; }
quit_claude() {
  claude_running || return 0
  say "Claude is open. It has to be closed while its config is edited."
  read -r -p "  Quit Claude now? It reopens at the end. [Y/n] " a
  [[ "$a" =~ ^[Nn]$ ]] && die "Quit Claude (Cmd+Q) and run this again."
  osascript -e 'quit app "Claude"' >/dev/null 2>&1 || true
  for _ in $(seq 1 90); do claude_running || break; sleep 1; done
  claude_running && die "Claude didn't quit. Quit it with Cmd+Q and run this again."
  ok "Claude closed"
  trap 'open -a Claude >/dev/null 2>&1 && printf "  Claude reopened\n"' EXIT
}
edit_cfg() {  # edit_cfg set|remove: changes ONLY our entry; the file is replaced only after it parses back
  CFG="$CFG" ACTION="$1" NAME="$NAME" APP="$APP" VENV="$VENV" PROJECT="$PROJECT" /usr/bin/python3 -I - <<'PY'
import json, os, tempfile
p, action, name = os.environ["CFG"], os.environ["ACTION"], os.environ["NAME"]
try:
    cfg = json.load(open(p))
except FileNotFoundError:
    cfg = {}
except json.JSONDecodeError as e:
    raise SystemExit(f"  The Claude config isn't valid JSON ({e}); not touching it.")
servers = cfg.setdefault("mcpServers", {})
before = sorted(servers)
if action == "set":
    app, venv = os.environ["APP"], os.environ["VENV"]
    entry = {"command": f"{venv}/bin/python", "args": ["-I", "-B", f"{app}/server/ansible_safe_mcp.py"],
             "env": {"ASM_PROJECT": os.environ["PROJECT"], "ASM_COLLECTIONS": f"{app}/collections",
                     "ASM_ANSIBLE_BIN": f"{venv}/bin"}}
    what = "unchanged" if servers.get(name) == entry else ("replaced" if name in servers else "added")
    servers[name] = entry
else:
    what = "removed" if servers.pop(name, None) is not None else "was not there"
os.makedirs(os.path.dirname(p), exist_ok=True)
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(p), prefix=".cfg-")
with os.fdopen(fd, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
json.load(open(tmp))
os.replace(tmp, p)
after = sorted(json.load(open(p))["mcpServers"])
lost = set(before) - set(after) - {name}
if lost:
    raise SystemExit(f"  Lost entries {sorted(lost)}?! Restore the backup.")
print(f"  \033[32m✓\033[0m {name} entry {what}; servers now: {', '.join(after)}")
PY
}
backup_cfg() {
  mkdir -p "$HOME/.config/claude-mcp/backups"; chmod 700 "$HOME/.config/claude-mcp/backups"
  if [ -f "$CFG" ]; then
    BK="$HOME/.config/claude-mcp/backups/claude_desktop_config.$(date +%Y%m%d-%H%M%S).json"
    cp -p "$CFG" "$BK"; chmod 600 "$BK"; ok "Backed up the Claude config to $BK"
  fi
}

if [ "$MODE" = check ]; then
  say "ansible-safe-mcp: what is installed"
  PY="$(find_python || true)"; [ -n "$PY" ] && ok "Python 3.10+: $PY" || warn "no Python 3.10+ (brew install python@3.12)"
  [ -x "$VENV/bin/ansible-playbook" ] && ok "venv: $("$VENV/bin/ansible-playbook" --version | head -1)" \
    || warn "no venv yet at $VENV"
  if [ -d "$APP" ]; then
    if diff -rq "$HERE/server" "$APP/server" >/dev/null 2>&1 && diff -rq "$HERE/collections" "$APP/collections" \
         >/dev/null 2>&1; then ok "installed copy matches this folder"; else warn "installed copy differs from this folder"; fi
  else warn "not installed ($APP missing)"; fi
  /usr/bin/python3 -I -c 'import json,sys; s=json.load(open(sys.argv[1])).get("mcpServers",{}); print("  \033[32m✓\033[0m Claude entry present" if "ansible-safe" in s else "  \033[33m!\033[0m no Claude entry")' "$CFG" 2>/dev/null || warn "no Claude config"
  ok "project folder: $PROJECT"
  exit 0
fi

if [ "$MODE" = remove ]; then
  quit_claude
  backup_cfg
  edit_cfg remove
  [ -d "$APP" ] && { chmod -R u+w "$APP"; rm -rf "$APP"; ok "removed $APP"; }
  ok "kept: the venv ($VENV), your project ($PROJECT) and the state and audit log (~/.local/state/ansible-safe-mcp)"
  exit 0
fi

[ "$MODE" = install ] || die "usage: bash install.sh [--check|--remove]"
say "ansible-safe-mcp: install"
PY="$(find_python)" || die "needs Python 3.10 or newer. macOS's own is 3.9: brew install python@3.12 (or uv python install 3.12)."
ok "Python: $PY ($("$PY" -c 'import platform; print(platform.python_version())'))"
mkdir -p "$DEST"; chmod 700 "$DEST"
if [ ! -x "$VENV/bin/python" ]; then "$PY" -m venv "$VENV"; ok "venv created at $VENV"; fi
"$VENV/bin/python" -m pip install -q --upgrade pip >/dev/null
"$VENV/bin/python" -m pip install -q "ansible-core>=2.17,<2.24"
ok "$("$VENV/bin/ansible-playbook" --version | head -1)"

[ -d "$APP" ] && chmod -R u+w "$APP" && rm -rf "$APP"
mkdir -p "$APP"
cp -R "$HERE/server" "$HERE/collections" "$HERE/LICENSE" "$APP/"
find "$APP" -name '__pycache__' -prune -exec rm -rf {} +
rm -rf "$APP/collections/ansible_collections/mureev/confirmed/tests"
chmod -R a-w "$APP"
ok "installed a read-only copy at $APP"

reply="$(printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"install"}}}' \
  | ASM_PROJECT="$PROJECT" ASM_COLLECTIONS="$APP/collections" ASM_ANSIBLE_BIN="$VENV/bin" \
    "$VENV/bin/python" -I -B "$APP/server/ansible_safe_mcp.py" 2>&1 | head -1)"
case "$reply" in *'"ansible-safe-mcp"'*) ok "the server answers the MCP handshake" ;;
  *) die "the server did not answer: $reply" ;; esac

quit_claude
backup_cfg
edit_cfg set
cat <<EOF

$(say "Next:")
  - Each host needs two accounts with your SSH key (from your ssh-agent): one that can only read (no sudo, not in
    the docker group), one with passwordless sudo. Then ask Claude to add the host: it shows you the host key first.
  - Your playbooks live in $PROJECT (a git repo; every change Claude writes is a commit).
  - If you use mac-terminal-mcp, add ~/.local/state/ansible-safe-mcp to its deny_paths (policy.local.json) and
    reinstall it, so a sandboxed shell can't touch this server's state.
  - Everything is logged to ~/.local/state/ansible-safe-mcp/audit.jsonl.
EOF
