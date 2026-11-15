#!/bin/bash
# ansible-safe-mcp installer for macOS and the Claude desktop app.
#   bash install.sh            install or update
#   bash install.sh --check    show what is installed; changes nothing
#   bash install.sh --remove   take out the Claude entry and the installed copy (keeps state, project and venv)
# What it does:
#   1. Makes a venv with ansible-core on a uv-managed Python 3.12 (installing uv with Homebrew if needed). Not
#      Homebrew's or python.org's Python: those are framework builds that run as their own app ("Python.app"), and
#      macOS then wants a separate Local Network permission for it before the server can reach hosts on your LAN.
#      A plain (non-bundle) Python inherits the Claude app's permission, as Node-based servers do.
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
# the project and masking settings: from the environment, else what the Claude entry already has, else defaults
PROJECT="${ASM_PROJECT:-}"
CFG="${CLAUDE_CONFIG:-$HOME/Library/Application Support/Claude/claude_desktop_config.json}"
if [ -z "$PROJECT" ]; then
  PROJECT=$(CFG="$CFG" /usr/bin/python3 -I -c 'import json,os
try: print(json.load(open(os.environ["CFG"]))["mcpServers"]["ansible-safe"]["env"]["ASM_PROJECT"])
except Exception: pass' 2>/dev/null || true)
  PROJECT="${PROJECT:-$HOME/ansible-safe}"
fi
export ASM_MASK_DOMAINS="${ASM_MASK_DOMAINS:-}"
MODE="${1:-install}"; MODE="${MODE#--}"

say() { printf '\033[1m%s\033[0m\n' "$*"; }
ok() { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
die() { printf '\033[31mSTOPPED:\033[0m %s\n' "$*"; exit 1; }

[ "$(uname)" = Darwin ] || die "this installer is for macOS (the server itself runs anywhere: see AGENTS.md)."
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
    old_env = (servers.get(name) or {}).get("env") or {}
    env = {"ASM_PROJECT": os.environ.get("PROJECT") or old_env.get("ASM_PROJECT")
           or os.path.expanduser("~/ansible-safe"),
           "ASM_COLLECTIONS": f"{app}/collections", "ASM_ANSIBLE_BIN": f"{venv}/bin"}
    masks = os.environ.get("ASM_MASK_DOMAINS") or old_env.get("ASM_MASK_DOMAINS", "")
    if masks:
        env["ASM_MASK_DOMAINS"] = masks
    entry = {"command": f"{venv}/bin/python", "args": ["-I", "-B", f"{app}/server/ansible_safe_mcp.py"], "env": env}
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
# OpenAI Codex (CLI and app) reads MCP servers from ~/.codex/config.toml. Added when Codex is there (or ASM_CODEX=1);
# only our own [mcp_servers.ansible-safe] tables are touched, and the file is replaced only after it parses back.
CODEX_CFG="${CODEX_HOME:-$HOME/.codex}/config.toml"
codex_wanted() { [ "${ASM_CODEX:-}" = 1 ] || [ -d "${CODEX_HOME:-$HOME/.codex}" ] || command -v codex >/dev/null 2>&1; }
edit_codex() {  # edit_codex set|remove
  [ "$1" = remove ] && [ ! -f "$CODEX_CFG" ] && return 0
  mkdir -p "$(dirname "$CODEX_CFG")"
  CODEX_CFG="$CODEX_CFG" ACTION="$1" APP="$APP" VENV="$VENV" PROJECT="$PROJECT" "$VENV/bin/python" -I - <<'PY'
import os, re, tomllib
p, act = os.environ["CODEX_CFG"], os.environ["ACTION"]
old = open(p).read() if os.path.exists(p) else ""
before = tomllib.loads(old)
# drop our tables: [mcp_servers.ansible-safe] and [mcp_servers.ansible-safe.<sub>], up to the next other header
out, skip = [], False
for line in old.splitlines(keepends=True):
    h = re.match(r'^\s*\[+\s*([^\]]+?)\s*\]+\s*(#.*)?$', line)
    if h:
        name = h.group(1).replace('"', '')
        skip = name == "mcp_servers.ansible-safe" or name.startswith("mcp_servers.ansible-safe.")
    if not skip and line.strip() != "# ansible-safe-mcp (written by its install.sh)":
        out.append(line)
text = "".join(out).rstrip() + "\n"
if act == "set":
    def q(v):
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    env = {"ASM_PROJECT": os.environ["PROJECT"], "ASM_COLLECTIONS": os.environ["APP"] + "/collections",
           "ASM_ANSIBLE_BIN": os.environ["VENV"] + "/bin"}
    if os.environ.get("ASM_MASK_DOMAINS"):
        env["ASM_MASK_DOMAINS"] = os.environ["ASM_MASK_DOMAINS"]
    text += ("\n# ansible-safe-mcp (written by its install.sh)\n[mcp_servers.ansible-safe]\n"
             "command = %s\nargs = [\"-I\", \"-B\", %s]\n"
             "startup_timeout_sec = 30\ntool_timeout_sec = 120\n\n[mcp_servers.ansible-safe.env]\n"
             % (q(os.environ["VENV"] + "/bin/python"), q(os.environ["APP"] + "/server/ansible_safe_mcp.py"))
             + "".join("%s = %s\n" % (k, q(v)) for k, v in env.items()))
after = tomllib.loads(text)
lost = set(before) - set(after)
lost |= set(before.get("mcp_servers", {})) - set(after.get("mcp_servers", {})) - {"ansible-safe"}
if lost:
    raise SystemExit("  Codex config: would lose %s; not written" % sorted(lost))
tmp = p + ".asm-tmp"
with open(tmp, "w") as f:
    f.write(text)
os.chmod(tmp, 0o600)
os.replace(tmp, p)
print("  \033[32m✓\033[0m Codex: ansible-safe entry %s in %s" % ("written" if act == "set" else "removed", p))
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
  grep -q '^\[mcp_servers.ansible-safe\]' "$CODEX_CFG" 2>/dev/null && ok "Codex entry present ($CODEX_CFG)" || ok "no Codex entry"
  ok "project folder: $PROJECT"
  exit 0
fi

if [ "$MODE" = remove ]; then
  quit_claude
  backup_cfg
  edit_cfg remove
  [ -x "$VENV/bin/python" ] && edit_codex remove
  [ -d "$APP" ] && { chmod -R u+w "$APP"; rm -rf "$APP"; ok "removed $APP"; }
  ok "kept: the venv ($VENV), your project ($PROJECT) and the state and audit log (~/.local/state/ansible-safe-mcp)"
  exit 0
fi

[ "$MODE" = install ] || die "usage: bash install.sh [--check|--remove]"
say "ansible-safe-mcp: install"
mkdir -p "$DEST"; chmod 700 "$DEST"
UV="$(command -v uv || true)"
for c in /opt/homebrew/bin/uv /usr/local/bin/uv "$HOME/.local/bin/uv" "$HOME/.cargo/bin/uv"; do
  [ -z "$UV" ] && [ -x "$c" ] && UV="$c"
done
if [ -z "$UV" ] && command -v brew >/dev/null 2>&1; then
  say "Installing uv (a Python manager) with Homebrew"; brew install uv >/dev/null && UV="$(command -v uv)"
fi
framework() { "$1" -I -c 'import sysconfig,sys; sys.exit(0 if sysconfig.get_config_var("PYTHONFRAMEWORK") else 1)' 2>/dev/null; }
if [ -x "$VENV/bin/python" ] && framework "$VENV/bin/python" && [ -n "$UV" ]; then
  warn "the old venv runs on a framework Python (Python.app); replacing it"
  rm -rf "$VENV"
fi
if [ ! -x "$VENV/bin/python" ]; then
  if [ -n "$UV" ]; then
    "$UV" python install 3.12 >/dev/null 2>&1 || true
    "$UV" venv -q --python 3.12 --python-preference only-managed "$VENV" || die "uv could not make the venv"
  else
    PY="$(find_python)" || die "needs uv (brew install uv) or Python 3.10+."
    "$PY" -m venv "$VENV"
  fi
  ok "venv created at $VENV"
fi
framework "$VENV/bin/python" && warn "this Python is a framework build: allow \"Python\" in System Settings > Privacy & Security > Local Network, or install uv and run this again"
ok "Python: $("$VENV/bin/python" -c 'import platform,sys; print(platform.python_version(), sys.base_prefix)')"
if [ -n "$UV" ]; then "$UV" pip install -q --python "$VENV/bin/python" "ansible-core>=2.17,<2.24"
else "$VENV/bin/python" -m pip install -q --upgrade pip >/dev/null; "$VENV/bin/python" -m pip install -q "ansible-core>=2.17,<2.24"; fi
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
if codex_wanted; then
  [ -f "$CODEX_CFG" ] && { cp -p "$CODEX_CFG" "$HOME/.config/claude-mcp/backups/codex-config.$(date +%Y%m%d-%H%M%S).toml"; }
  edit_codex set || warn "Codex config not changed (see above)"
fi
cat <<EOF

$(say "Next:")
  - Each host needs two accounts with your SSH key (from your ssh-agent): one that can only read (no sudo, not in
    the docker group), one with passwordless sudo. Then ask Claude to add the host: it shows you the host key first.
  - macOS asks before a new program may reach your local network: the first time the server connects to a host on
    your LAN, allow "Python" (or turn it on in System Settings > Privacy & Security > Local Network). Until then
    LAN hosts fail with "No route to host".
  - Your playbooks live in $PROJECT (a git repo; every change Claude writes is a commit).
  - If you use mac-terminal-mcp, add ~/.local/state/ansible-safe-mcp to its deny_paths (policy.local.json) and
    reinstall it, so a sandboxed shell can't touch this server's state.
  - Everything is logged to ~/.local/state/ansible-safe-mcp/audit.jsonl.
EOF
