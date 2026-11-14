# -*- coding: utf-8 -*-
# Copyright (c) 2026 Constantine Mureev
# MIT License (see LICENSE)
"""Shared code for the mureev.confirmed modules.

The real work happens in GUARD_SH, a POSIX sh script installed on the host. It has to be sh, not Python: the
revert runs from a timer long after Ansible has gone, possibly after a reboot, and must need nothing but the host.
"""
from __future__ import annotations

import os
import re

DEFAULT_DIR = '/var/lib/ansible-confirmed'
MIN_WINDOW = 5
MAX_WINDOW = 24 * 3600

GUARD_SH = r'''#!/bin/sh
# ansible-confirmed guard (mureev.confirmed collection). Commit-confirmed for Linux hosts:
#   guard.sh arm ID SECONDS REQDIR   snapshot what REQDIR lists, start a revert timer ON THIS HOST
#   guard.sh confirm [ID]            keep the change: stop the timer, drop the snapshot
#   guard.sh revert WHY [ID]         put the snapshot back now (the timer runs: revert timeout)
#   guard.sh extend SECONDS          move the deadline to SECONDS from now
#   guard.sh boot                    after a reboot: revert if the deadline passed, else restart the timer
#   guard.sh status
# Output is key=value lines. State lives in $D; the files a non-root reader may see are 0644.
D=${ANSIBLE_CONFIRMED_DIR:-/var/lib/ansible-confirmed}
UNIT=ansible-confirmed-revert
PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH
umask 077

now() { date +%s; }
iso() { date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "$1"; }
stamp() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { echo "$(stamp) $*" >> "$D/guard.log"; logger -t ansible-confirmed "$*" 2>/dev/null; }
note() { echo "$*" > "$D/last"; chmod 644 "$D/last"; }
last_out() { [ -f "$D/last" ] && echo "last=$(cat "$D/last")"; return 0; }
has_systemd() { [ -d /run/systemd/system ] && command -v systemd-run >/dev/null 2>&1; }
key() { echo "$1" | sed 's|/|_|g'; }
backend() { cat "$D/backend" 2>/dev/null; }

schedule() {
  secs=$1
  if [ "$(backend)" = systemd ]; then
    systemctl stop "$UNIT.timer" "$UNIT.service" 2>/dev/null
    systemctl reset-failed "$UNIT.timer" "$UNIT.service" 2>/dev/null
    systemd-run --quiet --unit="$UNIT" --on-active="$secs" \
      --description="ansible-confirmed: revert an unconfirmed change" /bin/sh "$D/guard.sh" revert timeout || return 1
    systemctl is-active --quiet "$UNIT.timer"
  else
    # Detached from the SSH session: own session, no inherited descriptors, HUP ignored.
    rm -f "$D/timer.pid"
    nohup setsid /bin/sh -c 'trap "" HUP; echo $$ > "$1/timer.pid"; sleep "$2"; exec /bin/sh "$1/guard.sh" revert timeout' \
      sh "$D" "$secs" </dev/null >/dev/null 2>&1 &
    i=0
    while [ ! -s "$D/timer.pid" ] && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
    [ -s "$D/timer.pid" ] || return 1
    chmod 644 "$D/timer.pid"
    [ -d "/proc/$(cat "$D/timer.pid")" ]
  fi
}

unschedule() {
  if [ "$(backend)" = systemd ]; then
    systemctl stop "$UNIT.timer" 2>/dev/null
    systemctl reset-failed "$UNIT.timer" "$UNIT.service" 2>/dev/null
  elif [ -s "$D/timer.pid" ]; then
    p=$(cat "$D/timer.pid")
    kill -TERM -- "-$p" 2>/dev/null || kill -TERM "$p" 2>/dev/null
  fi
  rm -f "$D/timer.pid"
}

timer_alive() {
  if [ "$(backend)" = systemd ]; then systemctl is-active --quiet "$UNIT.timer" && echo yes || echo no
  elif [ -s "$D/timer.pid" ] && [ -d "/proc/$(cat "$D/timer.pid")" ]; then echo yes
  else echo no; fi
}

install_boot_unit() {
  u=/etc/systemd/system/ansible-confirmed-boot.service
  [ -f "$u" ] && return 0
  cat > "$u" <<EOF
[Unit]
Description=ansible-confirmed: revert a change a reboot left unconfirmed
ConditionPathExists=$D/armed
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/bin/sh $D/guard.sh boot

[Install]
WantedBy=multi-user.target
EOF
  chmod 644 "$u"
  systemctl daemon-reload
  systemctl enable --quiet ansible-confirmed-boot.service
}

arm() {
  id=$1; secs=$2; req=$3
  case "$secs" in ''|*[!0-9]*) echo "error=arm needs a number of seconds"; return 2;; esac
  case "$id" in ''|*[!A-Za-z0-9_.-]*) echo "error=bad id"; return 2;; esac
  if [ -e "$D/armed" ] || [ -e "$D/reverting" ]; then
    echo "error=another change is armed here ($(cat "$D/armed" "$D/reverting" 2>/dev/null)); confirm or revert it first"
    rm -rf "$req"; return 3
  fi
  rm -rf "$D/snap"; mkdir -p "$D/snap"
  mv "$req" "$D/snap/req" || { echo "error=request missing"; return 2; }
  : > "$D/snap/present"; : > "$D/snap/absent"
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    if [ -e "$p" ] || [ -L "$p" ]; then
      echo "${p#/}" >> "$D/snap/present"
      if [ -d "$p" ] && [ ! -L "$p" ]; then find "$p" > "$D/snap/tree.$(key "$p")"; fi
    else
      echo "$p" >> "$D/snap/absent"
    fi
  done < "$D/snap/req/paths"
  if [ -s "$D/snap/present" ]; then
    if ! tar -C / -cpf "$D/snap/files.tar" -T "$D/snap/present" 2> "$D/snap/tar.err"; then
      echo "error=snapshot failed: $(head -c 300 "$D/snap/tar.err" | tr '\n' ' ')"; rm -rf "$D/snap"; return 4
    fi
  fi
  if [ "$(cat "$D/snap/req/firewall" 2>/dev/null)" = 1 ]; then
    if command -v nft >/dev/null 2>&1 && nft list ruleset > "$D/snap/fw.nft" 2>/dev/null; then :
    elif command -v iptables-save >/dev/null 2>&1 && iptables-save > "$D/snap/fw.v4" 2>/dev/null; then
      command -v ip6tables-save >/dev/null 2>&1 && ip6tables-save > "$D/snap/fw.v6" 2>/dev/null
    else
      echo "error=firewall snapshot requested but neither nft nor iptables-save works here"; rm -rf "$D/snap"; return 4
    fi
  fi
  if has_systemd; then echo systemd > "$D/backend"; else echo detached > "$D/backend"; fi
  chmod 644 "$D/backend"
  deadline=$(( $(now) + secs ))
  echo "$id $deadline" > "$D/armed"; chmod 644 "$D/armed"
  [ "$(backend)" = systemd ] && install_boot_unit
  if ! schedule "$secs"; then
    rm -f "$D/armed"; rm -rf "$D/snap"; echo "error=could not start the revert timer, nothing armed"; return 5
  fi
  log "armed $id for ${secs}s"
  echo "state=armed"; echo "id=$id"; echo "deadline=$deadline"; echo "deadline_iso=$(iso "$deadline")"
  echo "backend=$(backend)"; echo "timer_alive=$(timer_alive)"
}

confirm() {
  want=$1
  if ! mv "$D/armed" "$D/confirming" 2>/dev/null; then
    if [ -e "$D/reverting" ]; then echo "error=too late: the host is reverting this change"; return 5; fi
    if [ -n "$want" ] && grep -q "^reverted .* $want " "$D/last" 2>/dev/null; then
      echo "error=change $want was already reverted: $(cat "$D/last")"; return 6
    fi
    echo "state=idle"; last_out; return 0
  fi
  set -- $(cat "$D/confirming"); id=$1
  if [ -n "$want" ] && [ "$want" != "$id" ]; then
    mv "$D/confirming" "$D/armed"; echo "error=the armed change is $id, not $want"; return 3
  fi
  unschedule
  rm -rf "$D/snap" "$D/confirming"
  log "confirmed $id"; note "confirmed $(stamp) $id "
  echo "state=confirmed"; echo "id=$id"; last_out
}

revert() {
  why=${1:-manual}; want=$2
  if [ -n "$want" ] && [ -e "$D/armed" ] && [ "$(cut -d' ' -f1 "$D/armed")" != "$want" ]; then
    echo "error=the armed change is $(cut -d' ' -f1 "$D/armed"), not $want"; return 3
  fi
  if ! mv "$D/armed" "$D/reverting" 2>/dev/null; then echo "state=idle"; last_out; return 0; fi
  set -- $(cat "$D/reverting"); id=$1
  [ "$why" = timeout ] || unschedule
  fail=0
  while IFS= read -r p; do [ -n "$p" ] && rm -rf -- "$p"; done < "$D/snap/absent"
  for t in "$D"/snap/tree.*; do
    [ -e "$t" ] || continue
    root=$(head -n 1 "$t")
    find "$root" -depth 2>/dev/null | while IFS= read -r f; do grep -qxF -- "$f" "$t" || rm -rf -- "$f"; done
  done
  if [ -f "$D/snap/files.tar" ]; then tar -C / -xpf "$D/snap/files.tar" || fail=1; fi
  if [ -f "$D/snap/fw.nft" ]; then { echo "flush ruleset"; cat "$D/snap/fw.nft"; } | nft -f - || fail=1; fi
  if [ -f "$D/snap/fw.v4" ]; then iptables-restore < "$D/snap/fw.v4" || fail=1; fi
  if [ -f "$D/snap/fw.v6" ]; then ip6tables-restore < "$D/snap/fw.v6" || fail=1; fi
  has_systemd && systemctl daemon-reload
  while IFS= read -r s; do
    [ -n "$s" ] || continue
    if has_systemd; then systemctl try-reload-or-restart "$s" || fail=1
    elif command -v service >/dev/null 2>&1; then
      service "$s" reload >/dev/null 2>&1 || service "$s" restart >/dev/null 2>&1 || fail=1
    elif [ -x "/etc/init.d/$s" ]; then "/etc/init.d/$s" reload || "/etc/init.d/$s" restart || fail=1
    else fail=1; fi
  done < "$D/snap/req/services"
  if [ "$fail" = 1 ]; then
    log "revert of $id ($why) had errors; snapshot kept in $D/snap"
    note "revert-failed $(stamp) $id ($why): snapshot kept in $D/snap "
    echo "state=revert-failed"; echo "id=$id"; last_out; return 7
  fi
  rm -rf "$D/snap" "$D/reverting" "$D/timer.pid"
  log "reverted $id ($why)"; note "reverted $(stamp) $id ($why) "
  echo "state=reverted"; echo "id=$id"; last_out
}

extend() {
  secs=$1
  case "$secs" in ''|*[!0-9]*) echo "error=extend needs a number of seconds"; return 2;; esac
  [ -e "$D/armed" ] || { echo "error=nothing is armed"; return 3; }
  set -- $(cat "$D/armed"); id=$1
  deadline=$(( $(now) + secs ))
  unschedule
  echo "$id $deadline" > "$D/armed"; chmod 644 "$D/armed"
  schedule "$secs" || { echo "error=could not restart the timer"; return 5; }
  log "extended $id to ${secs}s"
  echo "state=armed"; echo "id=$id"; echo "deadline=$deadline"; echo "deadline_iso=$(iso "$deadline")"
}

boot() {
  [ -e "$D/armed" ] || return 0
  set -- $(cat "$D/armed"); left=$(( $2 - $(now) ))
  if [ "$left" -le 0 ]; then revert reboot
  else schedule "$left" && log "timer restarted after a reboot: ${left}s left" || revert reboot-no-timer; fi
}

status() {
  if [ -e "$D/armed" ]; then
    set -- $(cat "$D/armed")
    echo "state=armed"; echo "id=$1"; echo "deadline=$2"; echo "deadline_iso=$(iso "$2")"
    echo "remaining=$(( $2 - $(now) ))"; echo "backend=$(backend)"; echo "timer_alive=$(timer_alive)"
  elif [ -e "$D/reverting" ]; then echo "state=reverting"
  else echo "state=idle"; fi
  last_out
}

mkdir -p "$D"; chmod 755 "$D"
cmd=$1; shift 2>/dev/null
case "$cmd" in
  arm) arm "$1" "$2" "$3" ;;
  confirm) confirm "$1" ;;
  revert) revert "$1" "$2" ;;
  extend) extend "$1" ;;
  boot) boot ;;
  status) status ;;
  *) echo "error=usage: arm ID SECONDS REQDIR | confirm [ID] | revert WHY [ID] | extend SECONDS | boot | status"; exit 2 ;;
esac
'''

_WINDOW_RE = re.compile(r'^\s*(\d+)\s*([smh]?)\s*$')


def parse_window(value):
    """'10m', '90s', '1h', 600 -> seconds."""
    if isinstance(value, int):
        secs = value
    else:
        m = _WINDOW_RE.match(str(value))
        if not m:
            raise ValueError("window must look like 600, 90s, 10m or 1h, not %r" % (value,))
        secs = int(m.group(1)) * {'': 1, 's': 1, 'm': 60, 'h': 3600}[m.group(2)]
    if not MIN_WINDOW <= secs <= MAX_WINDOW:
        raise ValueError("window must be between %ds and %ds" % (MIN_WINDOW, MAX_WINDOW))
    return secs


def parse_output(out):
    data = {}
    for line in out.splitlines():
        k, sep, v = line.partition('=')
        if sep and k and k.replace('_', '').isalnum():
            data[k] = v
    for k in ('deadline', 'remaining'):
        if k in data:
            try:
                data[k] = int(data[k])
            except ValueError:
                pass
    if 'timer_alive' in data:
        data['timer_alive'] = data['timer_alive'] == 'yes'
    return data


def install(module, state_dir):
    """Write guard.sh into state_dir if it is missing or different. Returns its path."""
    os.makedirs(state_dir, mode=0o755, exist_ok=True)
    os.chmod(state_dir, 0o755)
    path = os.path.join(state_dir, 'guard.sh')
    try:
        with open(path) as f:
            same = f.read() == GUARD_SH
    except OSError:
        same = False
    if not same:
        tmp = path + '.new'
        with open(tmp, 'w') as f:
            f.write(GUARD_SH)
        os.chmod(tmp, 0o700)
        os.rename(tmp, path)
    return path


def run(module, state_dir, *args):
    path = install(module, state_dir)
    rc, out, err = module.run_command(['/bin/sh', path] + [str(a) for a in args],
                                      environ_update={'ANSIBLE_CONFIRMED_DIR': state_dir})
    data = parse_output(out)
    return rc, data, out, err


def read_state(state_dir):
    """Read-only view of the guard state, for any user (the files it reads are 0644)."""
    def read(name):
        try:
            with open(os.path.join(state_dir, name)) as f:
                return f.read().strip()
        except OSError:
            return None
    import time
    st = {'state': 'idle'}
    armed = read('armed')
    if armed:
        parts = armed.split()
        st['state'] = 'armed'
        st['id'] = parts[0]
        if len(parts) > 1 and parts[1].isdigit():
            st['deadline'] = int(parts[1])
            st['remaining'] = st['deadline'] - int(time.time())
            st['deadline_iso'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(st['deadline']))
        st['backend'] = read('backend')
        pid = read('timer.pid')
        if st['backend'] == 'detached':
            st['timer_alive'] = bool(pid and pid.isdigit() and os.path.isdir('/proc/' + pid))
    elif os.path.exists(os.path.join(state_dir, 'reverting')):
        st['state'] = 'reverting'
    last = read('last')
    if last:
        st['last'] = last
    return st
