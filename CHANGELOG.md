# Changelog

## 0.3.1 (unreleased)

- **Checks**: `look check=<name>` runs a read-only script of your own from `checks/<kind>/` (Linux, macOS and Synology
  as root through sudo; OpenWrt, RouterOS in blocks, Windows), with a per-kind `_lib` prepended. Each script version
  is approved once, like a playbook version. `playbook` writes and lists them; `status` counts their approvals.
- **Masked output**: everything `look` returns goes through a port of infra-bridge's masking (keys, tokens,
  passwords, uci secrets, WireGuard keys, UUIDs and opaque tokens as stable pseudonyms, RouterOS script bodies,
  serials; `ASM_MASK_DOMAINS` for your own URL paths), linear-time on hostile input (`tests/test_redact.py`).
- **Docker and journal reads as the look account**: adding a Linux host installs `/etc/sudoers.d/ansible-safe-look`
  (checked with `visudo`), so the look account may run `docker ps/logs/inspect/images/stats` and
  `journalctl --no-pager` through sudo and nothing else; it stays out of the docker group. `hosts action=setup`
  installs it on a host added earlier.
- **`create_look`**: adding a Linux host can create the look account through the change account (no password,
  no sudo, no groups, the change account's keys).
- **Synology DSM hosts** (`kind="synology"`): DSM's Python (3.8) is too old for Ansible, so the server reads and
  changes them over plain SSH like macOS (raw commands with sudo, `paths=[...]`, the guard on a systemd timer), and,
  since DSM lets only administrators log in over SSH, one account may do both. Adding a DSM host as `linux` says so.
- `hands` writes raw commands when every target is changed over plain SSH (macOS, Synology, Windows, routers).
- A job whose server stopped mid-run (the app restarted when the network changed) is shown as interrupted, with
  a pointer to the guard read, instead of "running" forever. Seen on a Windows PC behind a jump host: its SYSTEM
  task restored it at the deadline.
- Two host adds waiting on the user at the same time no longer lose one of them: the inventory is re-read and
  written under a lock.
- **`tags` and `skip_tags`** on plan and apply (Linux plays): part of the approved version; the safety net's arm
  and confirm run whatever the tags.
- **The approved version covers the whole project a play can pull in**: roles, files, templates, vars and
  `inventory/group_vars` / `host_vars` (now allowed, for the project's own variables; `ansible_*` and `asm_*` keys
  there are refused, since connection settings are the hosts tool's). A changed variable asks again.
- `install.sh` keeps the project folder and `ASM_MASK_DOMAINS` already in the Claude entry unless the environment
  sets them: `ASM_PROJECT=~/repo/ops ASM_MASK_DOMAINS=example.org bash install.sh` once, plain `bash install.sh` after.
- **`hosts action=rename`** (no approval: it grants nothing); hosts that went through it as a jump follow.
- `examples/`: apt updates, Docker Compose updates, Windows Update (through a SYSTEM task), keep-awake for Windows
  and macOS.
- `look` across kinds sends only Linux hosts through Ansible; macOS, Windows, RouterOS and OpenWrt are read over
  plain SSH even in a mixed pattern (a guard read over `all` showed a Mac behind a jump host as unreachable).
- **`backup`**: pull a copy of hosts' configuration into `~/.local/state/ansible-safe-mcp/backups/<host>/<time>/`
  (0700 folders, 0600 files, never the project repo): RouterOS `/export terse` as the look account, OpenWrt
  `sysupgrade -b` plus `uci export`, a tar.gz of the listed paths on Linux and macOS, a zip with files and registry
  exports on Windows. Over a fresh plain SSH connection, no Ansible and no `fetch` (the lint guard still refuses it).
  Never asks; every file is in the audit log with its sha256; `status` shows the latest backup.

## 0.3.0 (preview) — 2026-11-14

- **Windows hosts**: a PowerShell guard in `C:\ProgramData\asm-guard` (ACL'd to SYSTEM and Administrators) snapshots
  the registry keys and files you list and registers a one-time SYSTEM scheduled task that restores them at the
  deadline, also after the PC was off. Tested on Windows 11 Home with a Russian locale (errors decoded from the
  console code page).
- **macOS hosts**: the server sends the collection's guard over SSH and arms it as a LaunchDaemon, so a Mac without
  Python can still be changed under the guard. Playbooks there are raw commands, run with sudo over a fresh SSH
  connection. Reads go over plain SSH. Tested on macOS 26 reached through a jump host.
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
