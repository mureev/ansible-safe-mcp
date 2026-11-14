# Changelog

## 0.3.0 (preview) — 2026-11-14

- **Windows hosts**: a PowerShell guard in `C:\ProgramData\asm-guard` (ACL'd to SYSTEM and Administrators) snapshots
  the registry keys and files you list and registers a one-time SYSTEM scheduled task that restores them at the
  deadline, also after the PC was off. Tested on Windows 11 Home with a Russian locale (errors decoded from the
  console code page).
- **macOS hosts**: the server sends the collection's guard over SSH and arms it as a LaunchDaemon, so a Mac without
  Python can still be changed under the guard. Reads go over plain SSH.
- **Jump hosts**: `kind="jump"` bastions with their own account, key and pinned host key; hosts with `jump=<name>`
  get a `ProxyCommand` the server writes and the inventory check recomputes.
- README for people (two screens, new diagrams of why it's safe); everything for agents in `AGENTS.md`.

## 0.2.0 (preview) — 2026-11-14

- **OpenWrt hosts**: an on-device guard (busybox sh, no Python), sent at arm time; it snapshots `/etc/config` and
  friends and reverts from a timer unless cancelled. Results show a `uci` diff. Tested on a Xiaomi Mi Router 3G.
- **RouterOS hosts**: changes under Safe Mode held by the server (Ctrl+X keeps, Ctrl+D undoes, a dropped session
  undoes). Reads over plain SSH. Tested on a hAP ax² (RouterOS 7.24.5).
- **`hands`**: guarded one-off changes, saved as playbooks in `oneoffs/`.
- **apply** starts a job at once and answers while the user is still deciding (remote clients wait ~80 s).
- Native macOS alert for approvals; per-account SSH keys; the installer uses a uv-managed Python (a framework
  Python needs its own Local Network permission).
- `mureev.confirmed` passes `ansible-test sanity`.

## 0.1.0 (preview) — 2026-11-14

- **mureev.confirmed** collection: `arm`, `confirm`, `revert`, `extend`, `status` for Linux hosts. The revert timer
  lives on the host (`systemd-run` plus a boot check, or a detached process without systemd). `confirm` drops the
  persistent SSH connection and checks over a new one; a failed check reverts at once.
- **MCP server**: `hosts`, `look`, `playbook`, `plan`, `apply`, `job`, `status`. Reads as an unprivileged account;
  approvals per playbook version (content, roles, hosts) with declared parameters, signed with a Keychain key; lint
  guard against code that would run on the Mac; inventory check; hash-chained audit log; the project folder is a
  git repo.
- macOS installer (`install.sh`, `--check`, `--remove`).
- RouterOS hosts: reads only. Changes come in 0.2.
