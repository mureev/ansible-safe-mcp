# Copyright (c) 2026 Constantine Mureev
# MIT License (see LICENSE)
"""RouterOS Safe Mode, held by the server for the length of a change.

MikroTik's console manual: Ctrl+X enters Safe Mode; "all configuration changes that are made (also from other login
sessions) while router is in safe mode are automatically undone if safe mode session terminates abnormally". Ctrl+X
again leaves Safe Mode and keeps the changes; Ctrl+D logs out and undoes them; /quit keeps them; a lost connection
undoes them after the TCP timeout (up to ~9 minutes). The history holds 100 actions: past that the router leaves Safe
Mode by itself and undoes nothing, so changes are kept small and the session is probed afterwards.

The server opens such a session as the change account, runs the playbook over separate connections, and then sends
Ctrl+X (keep) only after a fresh login works, or Ctrl+D (undo). If the server, the app or the Mac goes away, the
session ends abnormally and the router undoes the change: the fail-safe direction.

Console handling follows community.routeros's terminal plugin: answer "ESC Z" with "ESC / Z", apply backspaces,
decline the licence question, press Enter at 'Please press "Enter" to continue!'. The prompt ends "] >" or, in Safe
Mode, "] <SAFE>". Ported from infra-bridge, where it guards real changes.
"""
from __future__ import annotations

import os
import re
import subprocess
import threading
import time

ANSI = re.compile(r'\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]|\x1b[=>]|\x07')
PROMPT = re.compile(r'\[[^\[\]\n]{1,120}\][^\n]{0,120}?(<SAFE>|>)\s*$')
ERROR = re.compile(r'(?im)^\s*(failure:|bad command name|syntax error|expected end of command|input does not match|'
                   r'no such item|invalid value|ambiguous value|missing value|not enough permissions|.*error.*\(line \d+)')


class ConsoleError(Exception):
    pass


def ssh_base(host, user, known_hosts, key=None, tty=False):
    cmd = ['ssh', '-o', 'BatchMode=yes', '-o', 'UserKnownHostsFile=' + known_hosts, '-o', 'StrictHostKeyChecking=yes',
           '-o', 'ConnectTimeout=15', '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=3',
           '-o', 'ControlMaster=no', '-o', 'ControlPath=none', '-p', str(host.get('ansible_port', 22))]
    if tty:
        cmd += ['-tt', '-e', 'none']
    if key:
        cmd += ['-i', os.path.expanduser(key), '-o', 'IdentitiesOnly=yes']
    if host.get('asm_proxy_command'):
        cmd += ['-o', 'ProxyCommand=' + host['asm_proxy_command']]
    return cmd + ['%s@%s' % (user, host['ansible_host'])]


def proxy_command(jump, known_hosts):
    """How to reach a host through a jump host from the inventory: its own address, port, look account, key and
    pinned host key, via ssh -W. Written by the server, never by hand (the inventory check recomputes it)."""
    import shlex
    cmd = ['ssh', '-o', 'BatchMode=yes', '-o', 'UserKnownHostsFile=' + known_hosts, '-o', 'StrictHostKeyChecking=yes',
           '-o', 'ConnectTimeout=15', '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
           '-p', str(jump.get('ansible_port', 22))]
    if jump.get('asm_look_key'):
        cmd += ['-i', os.path.expanduser(jump['asm_look_key']), '-o', 'IdentitiesOnly=yes']
    cmd += ['-W', '%h:%p', '%s@%s' % (jump['asm_look_user'], jump['ansible_host'])]
    return ' '.join(shlex.quote(x) if x != '%h:%p' else x for x in cmd)


def run_command(host, user, known_hosts, command, key=None, timeout=60):
    """One RouterOS command over a brand-new SSH connection. Returns (ok, output)."""
    try:
        p = subprocess.run(ssh_base(host, user, known_hosts, key) + [command], capture_output=True, text=True,
                           timeout=timeout, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return False, 'timed out after %ds' % timeout
    out = ANSI.sub('', (p.stdout or '') + (p.stderr or '')).replace('\r', '')
    return p.returncode == 0 and not ERROR.search(out), out


def ssh_exec(host, user, known_hosts, command, key=None, timeout=60, stdin=None):
    """Any command over a brand-new SSH connection (no terminal). Returns (exit code, output)."""
    try:
        p = subprocess.run(ssh_base(host, user, known_hosts, key) + [command], capture_output=True, text=True,
                           timeout=timeout, input=stdin if stdin is not None else '')
    except subprocess.TimeoutExpired:
        return 124, 'timed out after %ds' % timeout
    return p.returncode, ANSI.sub('', (p.stdout or '') + (p.stderr or '')).replace('\r', '')


def ssh_exec_bytes(host, user, known_hosts, command, key=None, timeout=300):
    """A command over a brand-new SSH connection whose stdout may be binary. Returns (exit code, stdout bytes,
    stderr text)."""
    try:
        p = subprocess.run(ssh_base(host, user, known_hosts, key) + [command], capture_output=True,
                           timeout=timeout, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return 124, b'', 'timed out after %ds' % timeout
    return p.returncode, p.stdout, p.stderr.decode('utf-8', 'replace')


def normalize_export(text):
    """Drop the export's date header and RouterOS's line wrapping, so two exports diff cleanly."""
    lines = []
    for line in text.replace('\r', '').splitlines():
        if line.startswith('# ') and (re.match(r'^# \d{4}-\d{2}-\d{2} ', line) or 'by RouterOS' in line):
            continue
        if lines and lines[-1].endswith('\\'):
            lines[-1] = lines[-1][:-1] + line.lstrip()
        else:
            lines.append(line)
    return '\n'.join(lines).strip() + '\n'


class SafeModeSession:
    def __init__(self, cmd):
        self.cmd = cmd
        self.buf = ''
        self.state = 'new'  # new -> safe -> committed | reverted | lost | failed
        self.cond = threading.Condition()
        self.exited = False
        self.exit_code = None
        self.proc = None
        self.declined = self.entered = False

    def _reader(self):
        fd = self.proc.stdout.fileno()
        while True:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                chunk = b''
            if not chunk:
                break
            raw = chunk.decode('utf-8', 'replace')
            if '\x1bZ' in raw:
                self._send('\x1b/Z')
            with self.cond:
                for ch in ANSI.sub('', raw).replace('\r', ''):
                    if ch != '\x08':
                        self.buf += ch
                    elif self.buf and not self.buf.endswith('\n'):
                        self.buf = self.buf[:-1]
                if len(self.buf) > 256 * 1024:
                    self.buf = self.buf[-128 * 1024:]
                self.cond.notify_all()
        self.exit_code = self.proc.wait()
        with self.cond:
            self.exited = True
            if self.state == 'safe':
                self.state = 'lost'
            self.cond.notify_all()

    def _send(self, s):
        if not self.exited and self.proc and self.proc.stdin:
            try:
                self.proc.stdin.write(s.encode())
                self.proc.stdin.flush()
            except (BrokenPipeError, OSError):
                pass

    def _last(self):
        t = self.buf.rstrip(' \t')
        return t[t.rfind('\n') + 1:]

    def _wait(self, test, timeout, what):
        end = time.time() + timeout
        with self.cond:
            start = len(self.buf)
            while True:
                v = test(self.buf[start:], self._last())
                if v:
                    return v
                if self.exited:
                    raise ConsoleError('the console session ended (exit %s): %s' % (self.exit_code, self.tail()))
                left = end - time.time()
                if left <= 0:
                    raise ConsoleError('timed out after %ds waiting for %s; console said: %s' % (timeout, what,
                                                                                               self.tail()))
                self.cond.wait(min(left, 0.5))

    def tail(self):
        return repr(re.sub(r'\s+', ' ', self.buf).strip()[-160:])

    def open(self, timeout=25):
        """Log in and enter Safe Mode. Raises (and leaves nothing behind) if Safe Mode can't be taken."""
        self.proc = subprocess.Popen(self.cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': os.path.expanduser('~'),
                                          'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TERM': 'dumb',
                                          **({'SSH_AUTH_SOCK': os.environ['SSH_AUTH_SOCK']}
                                             if os.environ.get('SSH_AUTH_SOCK') else {})})
        threading.Thread(target=self._reader, daemon=True).start()
        try:
            def login(fresh, last):
                if re.search(r'\[Y/n\]:?\s*$', last, re.I):
                    if not self.declined:
                        self.declined = True
                        self._send('n')
                    return None
                if re.search(r'Please press "Enter" to continue!\s*$', last):
                    if not self.entered:
                        self.entered = True
                        self._send('\r')
                    return None
                if re.search(r'new password', last, re.I):
                    raise ConsoleError('the router asks this user for a new password; log in once by hand')
                return last if PROMPT.search(last) else None
            self._wait(login, timeout, 'the RouterOS prompt')
            self._send('\x18')

            def safe(fresh, last):
                if re.search(r'Hijacking Safe Mode|\[u/r/d\]', fresh, re.I):
                    return 'taken'
                m = PROMPT.search(last)
                return 'safe' if m and m.group(1) == '<SAFE>' else None
            got = self._wait(safe, 15, 'Safe Mode')
            if got == 'taken':
                self._send('d')
                raise ConsoleError('another session holds Safe Mode on this router (Winbox or a console?); '
                                   'nothing was changed')
            self.state = 'safe'
            return self
        except Exception:
            self.state = 'failed'
            self.kill()
            raise

    def probe(self):
        """Still in Safe Mode? (It leaves by itself past 100 actions, without undoing anything.)"""
        if self.exited:
            return False
        self._send('\r')
        last = self._wait(lambda fresh, l: l if PROMPT.search(l) and fresh else None, 10, 'the prompt')
        return PROMPT.search(last).group(1) == '<SAFE>'

    def commit(self):
        """Keep: Ctrl+X leaves Safe Mode; /quit logs out and keeps changes even if Ctrl+X was missed."""
        if self.exited or self.state != 'safe':
            raise ConsoleError('the Safe Mode session is %s; nothing to confirm' % self.state)
        self._send('\x18')
        released = True
        try:
            self._wait(lambda fresh, l: (PROMPT.search(l) and PROMPT.search(l).group(1) == '>') and l, 15,
                       'Safe Mode to be released')
        except ConsoleError:
            released = False
        self.state = 'committed'
        self._send('/quit\r')
        self._settle(10)
        return released

    def revert(self):
        """Undo: Ctrl+D logs out and undoes; if that doesn't end the session, cutting it does the same."""
        if self.state == 'safe' and not self.exited:
            self.state = 'reverting'
            self._send('\x04')
            self._settle(15)
        else:
            self.kill()
        if self.state in ('reverting', 'lost'):
            self.state = 'reverted'
        return self

    def _settle(self, secs):
        end = time.time() + secs
        while not self.exited and time.time() < end:
            time.sleep(0.2)
        if not self.exited:
            self.kill()

    def kill(self):
        if self.proc and not self.exited:
            try:
                self.proc.terminate()
            except OSError:
                pass
            for _ in range(25):
                if self.exited or self.proc.poll() is not None:
                    break
                time.sleep(0.2)
            if self.proc.poll() is None:
                try:
                    self.proc.kill()
                except OSError:
                    pass
