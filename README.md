<div align="center">

# Ansible Safe MCP

**Run Ansible from Claude. Every change undoes itself unless it's confirmed.**

![Status](https://img.shields.io/badge/status-0.3%20preview-d29922)
![Ansible](https://img.shields.io/badge/ansible--core-2.17%2B-EE0000)
[![Galaxy](https://img.shields.io/badge/galaxy-mureev.confirmed-EE0000?logo=ansible&logoColor=white)](https://galaxy.ansible.com/ui/repo/published/mureev/confirmed/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

<img src="docs/hero.svg" width="760" alt="A change cuts SSH. Who holds the undo? With plain Ansible the undo is on your Mac, so the server stays broken until you get there. With ansible-safe-mcp the undo is on the server, so it puts itself back at the deadline.">

Claude writes the playbook, shows you the diff, and runs it under a timer that lives on the host.<br>
To install it, give your agent this link:

```
https://github.com/mureev/ansible-safe-mcp
```

</div>

---

## Why it's safe

The fear that stops people from letting an agent near their servers is specific: *it changes something, loses the
connection, and nobody can get back in.* Ansible's own safety net can't catch that, because the rescue runs on the
machine that just lost the connection. Network gear solved this long ago with *commit confirmed*: apply, start a
timer on the device, and roll back unless someone reconnects and says "keep it". This brings that to every host
Ansible can reach (Linux: a systemd timer; Windows: a SYSTEM task; macOS: a LaunchDaemon; RouterOS: Safe Mode;
OpenWrt: a timer in RAM), and puts four more gates in front of it:

<img src="docs/gates.svg" width="760" alt="Five gates between Claude and your hosts: Look as a read-only account; Lint, so nothing runs on your Mac; your yes, once per playbook version, Keychain-signed; Arm, a snapshot and revert timer on the host before the first task; Prove, a brand-new connection and your checks. Stopping at gates 1 to 4 means nothing ran; failing gate 5 means the host restores itself. Passing all five: confirmed, kept.">

**What a revert can't undo:** deleted data, calls to outside services, and package downgrades. The plan says when a
playbook touches those.

## Is it for you?

You run a few servers, routers or PCs over SSH and want Claude to do the chores: patch, fix, look into why the disk
filled up. It works on **Linux, Windows, macOS, MikroTik RouterOS and OpenWrt**, directly or through a jump host,
from the Claude desktop app on a Mac. If you have Ansible Automation Platform, Red Hat's own MCP server fits better
([the other options](AGENTS.md#why-not-the-standard-options)).

The timers also work without Claude: [`mureev.confirmed`](https://galaxy.ansible.com/ui/repo/published/mureev/confirmed/)
is a plain Ansible collection on Galaxy.

## For agents

Everything an agent needs, to install it and then to use it, is in **[AGENTS.md](AGENTS.md)**. Read it before installing.

## License

MIT. Ansible® is a registered trademark of Red Hat, Inc. This project is not affiliated with or endorsed by Red Hat.
