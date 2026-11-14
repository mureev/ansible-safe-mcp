# Copyright (c) 2026 Constantine Mureev
# MIT License (see LICENSE)
"""PowerShell over SSH to Windows hosts, without ever putting caller text on a command line.

Ported from infra-bridge, where it drives real Windows 11 PCs. Windows' OpenSSH runs every exec request through its
DefaultShell, Windows PowerShell 5.1 (`powershell.exe -c <the exec string>`), so:
  - the script travels as base64 of its UTF-8 bytes inside a fixed wrapper;
  - the wrapper travels as base64 in a one-line `iex (<decode>)`, which is all PowerShell sees on its command line;
  - a wrapper too long for one command line (Windows caps it at 32,767 characters) goes on stdin instead.
A Russian Windows writes in its OEM code page, so the wrapper sends nothing but ASCII: each output line is "~" +
base64 of its UTF-8 bytes, decoded here. Errors become "!! line N: message"; `exit N` ends the run with N.
"""
from __future__ import annotations

import base64
import os
import re
import subprocess

from routeros import ssh_base

EXEC_LIMIT = 30000
RECORDS = '''ForEach-Object {
  if ($_ -is [System.Management.Automation.ErrorRecord]) {
    $l = ''; if ($_.InvocationInfo -and $_.InvocationInfo.ScriptLineNumber) { $l = 'line ' + $_.InvocationInfo.ScriptLineNumber + ': ' }
    '!! ' + $l + $_.Exception.Message
  } elseif ($_ -is [System.Management.Automation.WarningRecord]) { 'WARNING: ' + $_.Message }
  elseif ($_ -is [System.Management.Automation.VerboseRecord]) { 'VERBOSE: ' + $_.Message }
  elseif ($_ -is [System.Management.Automation.DebugRecord]) { 'DEBUG: ' + $_.Message }
  else { $_ }
}'''
WRAPPER = '\n'.join([
    "$ErrorActionPreference = 'Continue'",
    "$ProgressPreference = 'SilentlyContinue'",
    'try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue } catch { }',
    '$__u = New-Object System.Text.UTF8Encoding $false',
    "function __emit([string]$s) { [Console]::Out.WriteLine('~' + [Convert]::ToBase64String($__u.GetBytes($s))); "
    "[Console]::Out.Flush() }",
    "$__src = $__u.GetString([Convert]::FromBase64String('__SRC__'))",
    "try { $__sb = [scriptblock]::Create($__src) } catch { __emit ('!! ' + $_.Exception.Message); exit 1 }",
    '$global:LASTEXITCODE = 0',
    '& $__sb *>&1 | ' + RECORDS.replace('\n', '\n  ') + ' | Out-String -Stream -Width 400 | ForEach-Object { __emit $_ }',
    '[Console]::Out.Flush()',
    'if ($global:LASTEXITCODE) { exit $global:LASTEXITCODE }',
    'exit 0',
])


def b64(s):
    return base64.b64encode(s.encode('utf-8')).decode('ascii')


def ps_quote(s):
    return "'" + str(s).replace("'", "''") + "'"


def exec_for(script):
    """(exec string, stdin) for a PowerShell script."""
    w = WRAPPER.replace('__SRC__', b64(script))
    inline = "iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s')))" % b64(w)
    if len(inline) <= EXEC_LIMIT:
        return inline, ''
    return 'iex ([Console]::In.ReadToEnd())', w + '\n'


def decode_output(stdout):
    out = []
    for raw in (stdout or '').split('\n'):
        line = raw.rstrip('\r')
        if line.startswith('~'):
            body = line[1:]
            if re.match(r'^[A-Za-z0-9+/]*={0,2}$', body) and len(body) % 4 == 0:
                try:
                    out.append(base64.b64decode(body).decode('utf-8', 'replace'))
                    continue
                except ValueError:
                    pass
        if line:
            out.append(line)
    return '\n'.join(out)


def win_exec(host, user, known_hosts, script, key=None, timeout=120):
    """Run a PowerShell script on a Windows host over a brand-new SSH connection. Returns (exit code, text)."""
    command, stdin = exec_for(script)
    try:
        p = subprocess.run(ssh_base(host, user, known_hosts, key) + [command], capture_output=True, text=True,
                           timeout=timeout, input=stdin, errors='replace')
    except subprocess.TimeoutExpired:
        return 124, 'timed out after %ds' % timeout
    text = decode_output(p.stdout)
    if p.returncode != 0 and p.stderr.strip():
        text = (text + '\n' + p.stderr.strip()[-600:]).strip()
    return p.returncode, text


GUARD_PS1 = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'windows_guard.ps1')


def install_guard_script():
    """The script that writes the guard to C:\\ProgramData\\asm-guard and locks the folder to SYSTEM and admins."""
    with open(GUARD_PS1, encoding='utf-8') as f:
        body = f.read()
    return '\n'.join([
        "$D = Join-Path $env:ProgramData 'asm-guard'",
        'New-Item -ItemType Directory -Force $D | Out-Null',
        # SIDs, not names: a Russian Windows calls Administrators "Администраторы"
        "& icacls.exe $D /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "
        "'*S-1-5-32-545:(OI)(CI)RX' | Out-Null",
        "$t = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'))" % b64(body),
        "[IO.File]::WriteAllText((Join-Path $D 'guard.ps1'), $t, (New-Object Text.UTF8Encoding $true))",
        "'guard installed'",
    ])


def guard_call(action, **kw):
    args = ' '.join('-%s %s' % (k, ps_quote(v)) for k, v in kw.items())
    return "& (Join-Path $env:ProgramData 'asm-guard\\guard.ps1') -Action %s %s" % (action, args)
