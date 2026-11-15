# Example playbooks

Copy one into your project with `playbook action=write`, then `plan` and `apply` it. Each is approved once per
version. All of these ran on the author's hosts.

| Playbook | Hosts | What it does | Apply with |
|---|---|---|---|
| `updates-apt.yml` | Debian, Ubuntu | safe upgrade, reports a pending reboot | — |
| `docker-update.yml` | Linux with Docker Compose | pull newer images, recreate changed containers | `params={"project_dir": "/srv/app"}`, `checks=["url:…"]` |
| `updates-windows.yml` | Windows | Windows Update through a one-time SYSTEM task (Windows refuses to install updates from an SSH session) | `paths=["HKLM:\\SOFTWARE\\asm-updates"]` |
| `keep-awake-windows.yml` | Windows | no sleep for 4 hours, then it ends by itself | `paths=["HKLM:\\SOFTWARE\\asm-awake"]` |
| `keep-awake-macos.yml` | macOS | `caffeinate` for 4 hours | `paths=["/var/tmp/asm-awake"]` |

A revert can't uninstall updates or bring old images back; the plan says so.
