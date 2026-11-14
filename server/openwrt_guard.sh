# ansible-safe-mcp guard for OpenWrt. POSIX sh for busybox ash; ported from infra-bridge, where it guards real changes.
# The server writes this to /tmp/asm-guard/guard.sh when it arms, so the timer can run it after the SSH session is gone.
#   arm SECONDS   snapshot the guarded files, then revert after SECONDS unless cancelled (refuses if already armed)
#   cancel        keep the change: stop the timer, delete the snapshot
#   revert [WHY]  restore the snapshot now and let reload_config restart what changed
#   status
# Everything lives in /tmp (RAM). A reboot inside the window loses the guard and the change stays, exactly as with
# LuCI's own apply-and-rollback (rpcd keeps its rollback timer in memory too).
R=${R:-}
G="$R/tmp/asm-guard"
GUARDED="etc/config etc/dropbear etc/crontabs etc/rc.local etc/firewall.user etc/hosts etc/ethers etc/sysupgrade.conf etc/passwd etc/shadow etc/group etc/nftables.d"
umask 077

say() { echo "asm-guard: $*"; }
log() {
  logger -t asm-guard "$*" 2>/dev/null
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" >> "$G/guard.log"
}
reload() {
  rc="$R/sbin/reload_config"
  [ -x "$rc" ] || rc=$(command -v reload_config 2>/dev/null)
  if [ -n "$rc" ]; then "$rc" >/dev/null 2>&1 || say "reload_config failed"; else say "reload_config not found"; fi
}
stop_timer() {
  [ -f "$G/timer.pid" ] && kill "$(cat "$G/timer.pid")" 2>/dev/null
  rm -f "$G/timer.pid"
}

arm() {
  secs=$1
  case "$secs" in ''|*[!0-9]*) say "arm needs a number of seconds"; return 2;; esac
  if [ -e "$G/armed" ] || [ -e "$G/reverting" ]; then say "already armed; confirm or revert that change first"; return 3; fi
  [ -f "$G/guard.sh" ] || { say "missing $G/guard.sh"; return 5; }
  present=""
  for p in $GUARDED; do [ -e "$R/$p" ] && present="$present $p"; done
  # shellcheck disable=SC2086
  tar -C "$R/" -czf "$G/snapshot.tgz" $present || { rm -f "$G/snapshot.tgz"; say "snapshot failed"; return 4; }
  ls "$R/etc/config" > "$G/config.list" 2>/dev/null
  echo $(( $(date +%s) + secs )) > "$G/armed"
  # The timer outlives the SSH session: HUP is ignored and no file descriptor of the session is kept open.
  ( trap '' HUP; sleep "$secs"; sh "$G/guard.sh" revert timeout ) </dev/null >/dev/null 2>&1 &
  echo $! > "$G/timer.pid"
  log "armed for ${secs}s"
  say "armed: reverts in ${secs}s unless cancelled (deadline $(cat "$G/armed"))"
}

cancel() {
  if [ ! -e "$G/armed" ]; then say "no guard armed"; [ -f "$G/last" ] && cat "$G/last"; return 0; fi
  rm -f "$G/armed"
  stop_timer
  rm -f "$G/snapshot.tgz" "$G/config.list"
  log "cancelled: change kept"
  echo "confirmed $(date -u +%Y-%m-%dT%H:%M:%SZ): change kept" > "$G/last"
  say "cancelled: the change stays"
}

revert() {
  why=${1:-manual}
  if [ ! -e "$G/armed" ]; then say "no guard armed: nothing to revert"; [ -f "$G/last" ] && cat "$G/last"; return 0; fi
  mv "$G/armed" "$G/reverting" 2>/dev/null || return 0   # one revert at a time
  [ "$why" = timeout ] || stop_timer
  # config files the change created go; everything in the snapshot comes back
  for f in "$R"/etc/config/*; do
    [ -e "$f" ] || continue
    grep -qx "$(basename "$f")" "$G/config.list" 2>/dev/null || rm -f "$f"
  done
  if ! tar -C "$R/" -xzf "$G/snapshot.tgz"; then
    log "restore FAILED ($why)"; say "restore FAILED: the snapshot is kept at $G/snapshot.tgz"; return 6
  fi
  rm -rf "$R/tmp/.uci"
  reload
  rm -f "$G/reverting" "$G/snapshot.tgz" "$G/config.list" "$G/timer.pid"
  log "reverted ($why)"
  echo "reverted $(date -u +%Y-%m-%dT%H:%M:%SZ) ($why)" > "$G/last"
  say "reverted ($why)"
}

status() {
  if [ -e "$G/armed" ]; then
    d=$(cat "$G/armed")
    alive=no
    [ -f "$G/timer.pid" ] && kill -0 "$(cat "$G/timer.pid")" 2>/dev/null && alive=yes
    say "ARMED: reverts in $(( d - $(date +%s) ))s (deadline $d), timer running: $alive"
  elif [ -e "$G/reverting" ]; then
    say "reverting now"
  else
    say "not armed"
  fi
  [ -f "$G/last" ] && echo "last: $(cat "$G/last")"
  [ -f "$G/guard.log" ] && tail -n 5 "$G/guard.log"
  return 0
}

case "$1" in
  arm) arm "$2" ;;
  cancel) cancel ;;
  revert) revert "$2" ;;
  status) status ;;
  *) say "usage: arm SECONDS | cancel | revert [why] | status"; exit 2 ;;
esac
