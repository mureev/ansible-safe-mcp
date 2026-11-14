# mureev.confirmed

**Commit-confirmed for Ansible.** A change undoes itself, from a timer on the host, unless it's confirmed over a
fresh connection. For the changes that can lock you out: sshd, firewalls, networking, VPNs.

```yaml
- hosts: web
  become: true
  tasks:
    - mureev.confirmed.arm:                 # snapshot + revert timer, on the host
        window: 10m
        paths: [/etc/ssh/sshd_config.d/50-hardening.conf]
        services: [ssh]
    - ansible.builtin.copy:
        src: 50-hardening.conf
        dest: /etc/ssh/sshd_config.d/50-hardening.conf
    - ansible.builtin.service: {name: ssh, state: reloaded}
    - mureev.confirmed.confirm:             # new connection + checks, then keep it
        checks: [ssh, service:nginx]
```

If the new SSH config keeps you out, `confirm` can't connect, the task fails, and ten minutes later the host restores
the file and reloads sshd by itself. Ansible's `block`/`rescue` can't do that: a rescue runs on the controller, and
the controller is exactly what got locked out.

| Module | Does |
|---|---|
| `arm` | Snapshot `paths` (files or whole directories; paths that don't exist yet are removed on revert) and optionally the firewall ruleset, then start the revert timer. Refuses if another change is armed. |
| `confirm` | Drop the persistent connection, open a new one, run `checks` (`ssh`, `service:NAME`, `port:N`, `url:URL`, or a shell command), then stop the timer. A failed check reverts at once. |
| `revert` | Undo the armed change now. |
| `extend` | Move the deadline. |
| `status` | What's armed and what happened last. Works without root. |

**Hosts:** Linux in 0.1. With systemd the timer is a `systemd-run` unit plus a boot check, so a reboot inside the
window still reverts; without systemd it's a detached process (`survives_reboot: false`). RouterOS, OpenWrt, Windows
and macOS follow.

**What a revert can't undo:** data deleted outside `paths`, calls to other systems, package downgrades.

Part of [ansible-safe-mcp](https://github.com/mureev/ansible-safe-mcp), which lets Claude run Ansible this way, but the
collection needs nothing from it. MIT.
