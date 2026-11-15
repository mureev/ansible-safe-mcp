#!/usr/bin/env bash
# install.sh's Codex step: writes only its own [mcp_servers.ansible-safe] tables, keeps everything else, removes them
# again. Needs Python 3.11+ (tomllib) as "python3".
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"; t="$(mktemp -d)"; trap 'rm -rf "$t"' EXIT
mkdir -p "$t/venv/bin"; ln -s "$(command -v python3)" "$t/venv/bin/python"
cat > "$t/config.toml" <<'TOML'
model = "gpt-5-codex"

[mcp_servers.github]
command = "gh-mcp"

# ansible-safe-mcp (written by its install.sh)
[mcp_servers.ansible-safe]
command = "/old/python"

[mcp_servers.ansible-safe.env]
ASM_PROJECT = "/old"

[profiles.fast]
model = "o4"
TOML
ok() { echo "PASS $*"; }; bad() { echo "FAIL $*"; exit 1; }
eval "$(sed -n '/^CODEX_CFG=/,/^backup_cfg() {/p' "$here/install.sh" | sed '$d')"
CODEX_CFG="$t/config.toml" APP=/app VENV="$t/venv" PROJECT='/Users/x/my "repo"/ansible'
export ASM_MASK_DOMAINS=example.org
edit_codex set >/dev/null
python3 - "$t/config.toml" <<'PY' || bad "set: content"
import sys, tomllib
d = tomllib.load(open(sys.argv[1], "rb"))
e = d["mcp_servers"]["ansible-safe"]
assert e["command"].endswith("/venv/bin/python") and e["args"][-1] == "/app/server/ansible_safe_mcp.py", e
assert e["env"]["ASM_PROJECT"] == '/Users/x/my "repo"/ansible' and e["env"]["ASM_MASK_DOMAINS"] == "example.org"
assert e["tool_timeout_sec"] == 120
assert d["model"] == "gpt-5-codex" and d["mcp_servers"]["github"]["command"] == "gh-mcp" and d["profiles"]["fast"]
PY
ok "set: our entry written, the rest kept"
[ "$(grep -c '^\[mcp_servers.ansible-safe\]' "$t/config.toml")" = 1 ] && ok "set: one entry, the old one replaced" || bad "duplicate entry"
edit_codex remove >/dev/null
grep -q 'ansible-safe' "$t/config.toml" && bad "remove left something" || ok "remove: our tables gone"
grep -q 'gh-mcp' "$t/config.toml" && grep -q 'profiles.fast' "$t/config.toml" && ok "remove: the rest kept" || bad "remove lost other tables"
echo "install codex: all passed"
