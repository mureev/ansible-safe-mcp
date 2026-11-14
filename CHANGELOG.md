# Changelog

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
