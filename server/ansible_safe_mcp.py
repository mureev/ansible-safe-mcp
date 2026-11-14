#!/usr/bin/env python3
# Copyright (c) 2026 Constantine Mureev
# MIT License (see LICENSE)
"""ansible-safe-mcp: run Ansible from Claude. Every change undoes itself unless it's confirmed.

A local stdio MCP server. Reads run as an unprivileged account; changes run once their playbook version is
approved, under the mureev.confirmed safety net: a revert timer on the host, cancelled only after a fresh
connection proves the host still works.

Needs Python 3.10+ with ansible-core 2.17+ (and PyYAML, which ansible-core brings) in the same environment.
"""
from __future__ import annotations

import difflib
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import threading
import time

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import lint  # noqa: E402
import routeros  # noqa: E402
import windows  # noqa: E402

VERSION = '0.3.0'
PROTOCOLS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05']
NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$')
ADDR_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9.:_-]{0,252}$')
USER_RE = re.compile(r'^[a-z_][a-z0-9_.-]{0,31}(\+[a-z0-9]{1,16})?$')
PATTERN_RE = re.compile(r'^[A-Za-z0-9_.*:,!&\[\]-]{1,400}$')
SAFE_STR = r'^[A-Za-z0-9 ._@:/+,=-]{0,200}$'
KINDS = ('linux', 'macos', 'routeros', 'openwrt', 'windows', 'jump')
ANSIBLE_KINDS = ('linux', 'macos')  # sudo-capable POSIX hosts
SERVER_GUARDED = ('routeros', 'openwrt', 'windows', 'macos')  # no Python needed: the server drives the guard


def collection_guard_sh(cfg):
    """The collection's guard script, sent as is to macOS hosts (which may have no Python for modules)."""
    import importlib.util
    path = os.path.join(cfg.collections, 'ansible_collections', 'mureev', 'confirmed', 'plugins', 'module_utils',
                        'guard.py')
    spec = importlib.util.spec_from_file_location('asm_guard_module_utils', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.GUARD_SH
OPENWRT_GUARD = os.path.join(HERE, 'openwrt_guard.sh')
MAX_TEXT = 24000


# ------------------------------------------------------------------------------------------------ config & audit

class Config:
    def __init__(self):
        home = os.path.expanduser('~')
        self.project = os.path.abspath(os.path.expanduser(os.environ.get('ASM_PROJECT', os.path.join(home, 'ansible-safe'))))
        self.state = os.path.abspath(os.path.expanduser(os.environ.get(
            'ASM_STATE', os.path.join(home, '.local', 'state', 'ansible-safe-mcp'))))
        self.collections = os.environ.get('ASM_COLLECTIONS', os.path.join(ROOT, 'collections'))
        self.approver = os.environ.get('ASM_APPROVER', '')
        bindir = os.environ.get('ASM_ANSIBLE_BIN', '')
        self.playbook_bin = os.path.join(bindir, 'ansible-playbook') if bindir else (
            shutil.which('ansible-playbook') or os.path.join(os.path.dirname(sys.executable), 'ansible-playbook'))
        self.inventory = os.path.join(self.project, 'inventory', 'hosts.yml')
        self.known_hosts = os.path.join(self.state, 'known_hosts')
        self.ansible_cfg = os.path.join(self.state, 'ansible.cfg')
        self.jobs = os.path.join(self.state, 'jobs')

    def setup(self):
        for d in (self.state, self.jobs, os.path.join(self.state, 'cp'), os.path.join(self.state, 'tmp'),
                  os.path.join(self.state, 'ansible-home')):
            os.makedirs(d, mode=0o700, exist_ok=True)
        os.chmod(self.state, 0o700)
        for d in ('inventory', 'playbooks', 'roles', 'oneoffs'):
            os.makedirs(os.path.join(self.project, d), exist_ok=True)
        if not os.path.exists(self.inventory):
            save_inventory(self, {'all': {'hosts': {}, 'children': {}}})
        if not os.path.exists(self.known_hosts):
            open(self.known_hosts, 'a').close()
            os.chmod(self.known_hosts, 0o600)
        user_cols = os.path.join(os.path.expanduser('~'), '.ansible', 'collections')
        q = shlex.quote
        cfg = f"""# Written by ansible-safe-mcp at every start. Edits are lost; project ansible.cfg files are ignored.
[defaults]
inventory = {self.inventory}
collections_path = {self.collections}:{user_cols}:/usr/share/ansible/collections
roles_path = {os.path.join(self.project, 'roles')}
callback_plugins = {os.path.join(HERE, 'plugins', 'callback')}
stdout_callback = asm_json
host_key_checking = True
retry_files_enabled = False
interpreter_python = auto_silent
deprecation_warnings = False
system_warnings = False
localhost_warning = False
timeout = 20
forks = 10

[inventory]
enable_plugins = yaml

[ssh_connection]
pipelining = True
control_path_dir = {os.path.join(self.state, 'cp')}
ssh_args = -o ControlMaster=auto -o ControlPersist=60s -o BatchMode=yes -o UserKnownHostsFile={q(self.known_hosts)} -o StrictHostKeyChecking=yes -o ServerAliveInterval=10 -o ServerAliveCountMax=3
"""
        with open(self.ansible_cfg, 'w') as f:
            f.write(cfg)
        if shutil.which('git') and not os.path.isdir(os.path.join(self.project, '.git')):
            subprocess.run(['git', 'init', '-q'], cwd=self.project, capture_output=True)


class Audit:
    """Append-only, hash-chained log: each line carries the hash of the one before it."""

    def __init__(self, cfg):
        self.path = os.path.join(cfg.state, 'audit.jsonl')
        self.lock = threading.Lock()
        self.prev = '0' * 64
        try:
            with open(self.path, 'rb') as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - 65536))
                tail = f.read().decode('utf-8', 'replace').strip().splitlines()
            if tail:
                self.prev = json.loads(tail[-1]).get('hash', self.prev)
        except (OSError, ValueError):
            pass

    def write(self, tool, **fields):
        with self.lock:
            rec = {'ts': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'tool': tool, **fields,
                   'prev': self.prev}
            rec['hash'] = hashlib.sha256(json.dumps(rec, sort_keys=True, default=str).encode()).hexdigest()
            self.prev = rec['hash']
            with open(self.path, 'a') as f:
                f.write(json.dumps(rec, default=str) + '\n')
            os.chmod(self.path, 0o600)

    def tail(self, n=10):
        try:
            with open(self.path) as f:
                lines = f.readlines()[-n:]
        except OSError:
            return []
        out = []
        for line in lines:
            try:
                r = json.loads(line)
            except ValueError:
                continue
            out.append('%s %s %s' % (r.get('ts'), r.get('tool'), r.get('summary', '')))
        return out


# ------------------------------------------------------------------------------------------------ inventory

def load_inventory(cfg):
    try:
        with open(cfg.inventory) as f:
            inv = yaml.safe_load(f) or {}
    except OSError:
        inv = {}
    inv.setdefault('all', {})
    inv['all'].setdefault('hosts', {})
    inv['all'].setdefault('children', {})
    if inv['all']['hosts'] is None:
        inv['all']['hosts'] = {}
    if inv['all']['children'] is None:
        inv['all']['children'] = {}
    return inv


def save_inventory(cfg, inv):
    os.makedirs(os.path.dirname(cfg.inventory), exist_ok=True)
    tmp = cfg.inventory + '.new'
    with open(tmp, 'w') as f:
        f.write('# Managed by ansible-safe-mcp (tool: hosts). Hand edits are kept, but add hosts with the tool:\n'
                '# it pins the host key and checks both accounts.\n')
        yaml.safe_dump(inv, f, sort_keys=False, default_flow_style=False)
    os.replace(tmp, cfg.inventory)


HOST_KEYS = {'ansible_host', 'ansible_port', 'ansible_ssh_common_args', 'ansible_network_os', 'asm_kind',
             'ansible_ssh_use_tty',
             'asm_look_user', 'asm_change_user', 'asm_jump', 'asm_look_key', 'asm_change_key', 'asm_proxy_command'}


def migrate_inventory(cfg):
    """0.1 kept one key per host as ansible_ssh_private_key_file; now each account has its own."""
    inv = load_inventory(cfg)
    changed = False
    for name, v in hosts_of(inv).items():
        if v.get('asm_kind') == 'routeros' and v.get('ansible_ssh_use_tty') is not False:
            v['ansible_ssh_use_tty'] = False  # a RouterOS console with a terminal waits for keystrokes
            inv['all']['hosts'][name] = v
            changed = True
        old = v.pop('ansible_ssh_private_key_file', None)
        if old:
            v.setdefault('asm_look_key', old)
            v.setdefault('asm_change_key', old)
            inv['all']['hosts'][name] = v
            changed = True
    if changed:
        save_inventory(cfg, inv)


def check_inventory(cfg):
    """The inventory is the server's: refuse anything in it the hosts tool wouldn't have written (a connection
    variable added by hand or by another tool could make a play run on the Mac)."""
    inv = load_inventory(cfg)
    bad = []
    for extra in ('group_vars', 'host_vars'):
        if os.path.exists(os.path.join(os.path.dirname(cfg.inventory), extra)):
            bad.append('inventory/%s exists; the server does not use it' % extra)
    for k in inv['all']:
        if k not in ('hosts', 'children'):
            bad.append('all.%s: only hosts and children are allowed' % k)
    for name, v in hosts_of(inv).items():
        if not NAME_RE.match(str(name)) or name == 'localhost':
            bad.append('host name %r' % name)
        for k, x in v.items():
            if k not in HOST_KEYS:
                bad.append('%s.%s is not set by the hosts tool' % (name, k))
            elif k in ('ansible_ssh_common_args', 'asm_proxy_command', 'asm_jump'):
                jump = hosts_of(inv).get(v.get('asm_jump'))
                want = routeros.proxy_command(jump, cfg.known_hosts) if jump else None
                if not want or v.get('asm_proxy_command') != want or \
                        v.get('ansible_ssh_common_args') != '-o ProxyCommand=%s' % shlex.quote(want):
                    bad.append('%s: the jump settings are not what the hosts tool writes for jump %r' % (
                        name, v.get('asm_jump')))
            elif k == 'ansible_host' and (not ADDR_RE.match(str(x))):
                bad.append('%s.ansible_host %r' % (name, x))
    for g, v in (inv['all'].get('children') or {}).items():
        for k in (v or {}):
            if k != 'hosts':
                bad.append('group %s.%s: groups may only list hosts' % (g, k))
        for h, hv in ((v or {}).get('hosts') or {}).items():
            if hv:
                bad.append('group %s sets variables on %s' % (g, h))
    if bad:
        raise ToolError('The inventory has entries the hosts tool did not write, so nothing runs:\n- ' +
                        '\n- '.join(bad[:20]))


def hosts_of(inv):
    return {name: (v or {}) for name, v in (inv['all'].get('hosts') or {}).items()}


def groups_of(inv, name):
    return sorted(g for g, v in (inv['all'].get('children') or {}).items() if name in ((v or {}).get('hosts') or {}))


# ------------------------------------------------------------------------------------------------ running ansible

def ansible_env(cfg, progress=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith('ANSIBLE_')}
    env.update({
        'ANSIBLE_CONFIG': cfg.ansible_cfg,
        'ANSIBLE_STDOUT_CALLBACK': 'asm_json',
        'ANSIBLE_NOCOLOR': '1',
        'ANSIBLE_FORCE_COLOR': '0',
        'ANSIBLE_HOME': os.path.join(cfg.state, 'ansible-home'),
        'ANSIBLE_LOCAL_TEMP': os.path.join(cfg.state, 'tmp'),
        'PYTHONDONTWRITEBYTECODE': '1',
    })
    env.pop('ASM_PROGRESS', None)
    if progress:
        env['ASM_PROGRESS'] = progress
    return env


def yaml_val(v):
    """Emit a YAML value; every string is !unsafe so Ansible never templates it."""
    if isinstance(v, bool) or v is None or isinstance(v, (int, float)):
        return json.dumps(v)
    if isinstance(v, str):
        return '!unsafe ' + json.dumps(v)
    if isinstance(v, (list, tuple)):
        return '[' + ', '.join(yaml_val(x) for x in v) + ']'
    if isinstance(v, dict):
        return '{' + ', '.join('%s: %s' % (json.dumps(str(k)), yaml_val(x)) for k, x in v.items()) + '}'
    raise TypeError(type(v))


def unsafe_cmd(cmd):
    """A command as an !unsafe YAML scalar. Ansible resolves the tagged value's type first, so a command like
    `false` or `1` would arrive as a bool or a number: a leading space keeps it a string and changes nothing."""
    try:
        plain = isinstance(yaml.safe_load(cmd), str)
    except yaml.YAMLError:
        plain = True
    return '!unsafe ' + json.dumps(cmd if plain else ' ' + cmd)


def write_vars(path, account, values=None):
    lines = ['ansible_user: "{{ asm_%s_user }}"' % account,
             'ansible_ssh_private_key_file: "{{ asm_%s_key | default(\'\') }}"' % account]
    for k, v in (values or {}).items():
        lines.append('%s: %s' % (k, yaml_val(v)))
    with open(path, 'w') as f:
        f.write('\n'.join(lines) + '\n')


def parse_json_output(out):
    for line in reversed(out.splitlines()):
        if line.startswith('ASM_JSON:'):
            try:
                return json.loads(line[len('ASM_JSON:'):])
            except ValueError:
                return None
    return None


def run_playbook(cfg, playbook, varsfile, limit=None, check=False, timeout=600, extra=()):
    cmd = [cfg.playbook_bin, playbook, '-e', '@' + varsfile]
    if limit:
        cmd += ['--limit', limit]
    if check:
        cmd += ['--check', '--diff']
    cmd += list(extra)
    try:
        p = subprocess.run(cmd, cwd=cfg.project, env=ansible_env(cfg), capture_output=True, text=True,
                           timeout=timeout, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return None, 'ansible-playbook timed out after %ds' % timeout, -1
    doc = parse_json_output(p.stdout)
    err = (p.stderr or '').strip()
    if doc is None:
        err = (err + '\n' + (p.stdout or '').strip()).strip()
    return doc, err, p.returncode


def scratch(cfg, prefix):
    d = os.path.join(cfg.state, 'tmp', '%s-%d-%s' % (prefix, int(time.time()), secrets.token_hex(3)))
    os.makedirs(d, mode=0o700)
    return d


def list_targets(cfg, playbook, limit):
    """Exact hosts a playbook would run on, via ansible-playbook --list-hosts."""
    d = scratch(cfg, 'list')
    vf = os.path.join(d, 'vars.yml')
    write_vars(vf, 'look')
    cmd = [cfg.playbook_bin, playbook, '--list-hosts', '-e', '@' + vf]
    if limit:
        cmd += ['--limit', limit]
    env = ansible_env(cfg)
    env['ANSIBLE_STDOUT_CALLBACK'] = 'default'
    p = subprocess.run(cmd, cwd=cfg.project, env=env, capture_output=True, text=True, timeout=60,
                       stdin=subprocess.DEVNULL)
    shutil.rmtree(d, ignore_errors=True)
    if p.returncode != 0:
        raise ToolError('could not list the hosts: %s' % (p.stderr.strip() or p.stdout.strip())[-1500:])
    hosts, grab = set(), False
    for line in p.stdout.splitlines():
        s = line.strip()
        if s.startswith('hosts ('):
            grab = True
        elif grab and NAME_RE.match(s):
            hosts.add(s)
        else:
            grab = False
    return sorted(hosts)


# ------------------------------------------------------------------------------------------------ approvals

class Approvals:
    """Playbook-version approvals, each signed with a key a sandboxed shell can't read (macOS Keychain)."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.path = os.path.join(cfg.state, 'approvals.json')
        self._key = None

    def key(self):
        if self._key:
            return self._key
        if sys.platform == 'darwin' and not os.environ.get('ASM_APPROVAL_KEYFILE'):
            q = ['security', 'find-generic-password', '-s', 'ansible-safe-mcp', '-a', 'approvals', '-w']
            p = subprocess.run(q, capture_output=True, text=True)
            if p.returncode != 0:
                subprocess.run(['security', 'add-generic-password', '-s', 'ansible-safe-mcp', '-a', 'approvals',
                                '-w', secrets.token_hex(32), '-U'], capture_output=True, text=True)
                p = subprocess.run(q, capture_output=True, text=True)
            if p.returncode == 0 and p.stdout.strip():
                self._key = p.stdout.strip().encode()
                return self._key
        kf = os.environ.get('ASM_APPROVAL_KEYFILE') or os.path.join(self.cfg.state, 'approval.key')
        if not os.path.exists(kf):
            with open(kf, 'w') as f:
                f.write(secrets.token_hex(32))
            os.chmod(kf, 0o600)
        with open(kf) as f:
            self._key = f.read().strip().encode()
        return self._key

    def _mac(self, h, playbook, targets):
        msg = json.dumps([h, playbook, sorted(targets)]).encode()
        return hmac.new(self.key(), msg, hashlib.sha256).hexdigest()

    def _load(self):
        try:
            with open(self.path) as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def approved(self, h, playbook, targets):
        e = self._load().get(h)
        return bool(e) and hmac.compare_digest(e.get('mac', ''), self._mac(h, playbook, targets))

    def add(self, h, playbook, targets):
        data = self._load()
        data[h] = {'playbook': playbook, 'targets': sorted(targets), 'mac': self._mac(h, playbook, targets),
                   'approved_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
        tmp = self.path + '.new'
        with open(tmp, 'w') as f:
            json.dump(data, f, indent=1)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    def count(self):
        return len(self._load())


def ask(cfg, title, text):
    """Ask the person. Returns (approved, how)."""
    if cfg.approver:
        p = subprocess.run(shlex.split(cfg.approver), input=json.dumps({'title': title, 'text': text}), text=True,
                           capture_output=True, timeout=600)
        return p.returncode == 0, 'approver command'
    if sys.platform == 'darwin':
        # display alert is the native NSAlert (bold title, message, standard buttons); Deny is the default and
        # the cancel button, so Return or Esc never approves by accident
        script = ['-e', 'on run argv',
                  '-e', 'display alert (item 2 of argv) message (item 1 of argv) as warning buttons {"Deny", "Approve"} '
                        'default button "Deny" cancel button "Deny" giving up after 300',
                  '-e', 'return button returned of result', '-e', 'end run']
        p = subprocess.run(['osascript'] + script + ['--', text[:2500], title[:120]], capture_output=True, text=True,
                           timeout=330)
        return p.returncode == 0 and p.stdout.strip() == 'Approve', 'dialog'
    return False, 'no way to ask on this machine (set ASM_APPROVER)'


# ------------------------------------------------------------------------------------------------ playbooks

class ToolError(Exception):
    pass


def project_path(cfg, rel, roots=('playbooks', 'roles', 'oneoffs')):
    if not isinstance(rel, str) or not rel or rel.startswith(('/', '~')) or '\\' in rel:
        raise ToolError('path must be relative to the project, under %s/' % '/, '.join(roots))
    norm = os.path.normpath(rel)
    parts = norm.split(os.sep)
    if parts[0] not in roots or '..' in parts or len(parts) < 2:
        raise ToolError('path must be under %s/ in the project' % '/, '.join(roots))
    if any(p in lint.PLUGIN_DIRS or p in ('ansible.cfg', '.git') for p in parts):
        raise ToolError('%s: plugin folders and ansible.cfg are not allowed in the project' % rel)
    return os.path.join(cfg.project, norm), norm


def playbook_path(cfg, rel):
    path, norm = project_path(cfg, rel, roots=('playbooks', 'oneoffs'))
    if not norm.endswith(('.yml', '.yaml')) or norm.count(os.sep) != 1:
        raise ToolError('a playbook is a .yml file directly in playbooks/ or oneoffs/')
    if not os.path.isfile(path):
        raise ToolError('no such playbook: %s' % norm)
    return path, norm


def version_hash(cfg, rel, targets):
    """What an approval binds to: this playbook, everything it can pull in, and the hosts. Not sibling playbooks."""
    h = hashlib.sha256()

    def add(label, data):
        h.update(label.encode() + b'\0' + data + b'\0')

    with open(os.path.join(cfg.project, rel), 'rb') as f:
        add('playbook:' + rel, f.read())
    top = os.path.dirname(rel)
    for base in (top, 'roles'):
        for dirpath, dirnames, filenames in os.walk(os.path.join(cfg.project, base)):
            dirnames.sort()
            reld = os.path.relpath(dirpath, cfg.project)
            if base == top and reld == top:
                continue  # sibling playbooks are not part of this one
            for fn in sorted(filenames):
                with open(os.path.join(dirpath, fn), 'rb') as f:
                    add('file:' + os.path.join(reld, fn), f.read())
    add('targets', json.dumps(sorted(targets)).encode())
    return h.hexdigest()


def params_schema(path):
    """Declared parameters: `asm_params` in the first play's vars. Values passed at apply time are not part of
    the approved version; everything else is."""
    try:
        with open(path) as f:
            docs = yaml.load(f, Loader=lint.Loader)
    except (OSError, yaml.YAMLError):
        return {}
    if isinstance(docs, list) and docs and isinstance(docs[0], dict):
        p = (docs[0].get('vars') or {}).get('asm_params')
        if isinstance(p, dict):
            return p
    return {}


def validate_params(schema, given):
    given = given or {}
    if not isinstance(given, dict):
        raise ToolError('params must be an object')
    out = {}
    for k in given:
        if k not in schema:
            raise ToolError('param %r is not declared in the playbook (asm_params); declared: %s' % (
                k, ', '.join(sorted(schema)) or 'none'))
    for k, spec in schema.items():
        spec = spec if isinstance(spec, dict) else {'type': str(spec)}
        t = spec.get('type', 'str')
        if k not in given:
            if 'default' in spec:
                out[k] = spec['default']
                continue
            if spec.get('required', True):
                raise ToolError('param %r is required (%s)' % (k, t))
            continue
        v = given[k]
        if t == 'int':
            if isinstance(v, bool) or not isinstance(v, int):
                raise ToolError('param %r must be an integer' % k)
            if 'min' in spec and v < spec['min'] or 'max' in spec and v > spec['max']:
                raise ToolError('param %r out of range' % k)
        elif t == 'bool':
            if not isinstance(v, bool):
                raise ToolError('param %r must be true or false' % k)
        elif t == 'choice':
            if v not in (spec.get('values') or []):
                raise ToolError('param %r must be one of %s' % (k, spec.get('values')))
        else:
            if not isinstance(v, str) or not re.match(spec.get('pattern', SAFE_STR), v) or '{' in v or '}' in v:
                raise ToolError('param %r must be a string matching %s (no braces)' % (k, spec.get('pattern',
                                                                                                SAFE_STR)))
        out[k] = v
    return out


# ------------------------------------------------------------------------------------------------ plan reading

FILE_ACTIONS = {'copy', 'template', 'file', 'lineinfile', 'blockinfile', 'replace', 'ini_file', 'assemble',
                'unarchive', 'get_url', 'xml', 'interfaces_file', 'pam_limits', 'sysctl', 'cron', 'hostname',
                'mount', 'apt_repository', 'yum_repository', 'deb822_repository', 'user', 'group', 'known_hosts',
                'locale_gen', 'timezone', 'nmcli', 'systemd', 'systemd_service', 'service'}
PKG_ACTIONS = {'apt', 'dnf', 'dnf5', 'yum', 'package', 'pip', 'snap', 'apk', 'zypper', 'pacman', 'homebrew',
               'npm', 'gem'}
BLIND_ACTIONS = {'command', 'shell', 'raw', 'script', 'expect'}
FW_ACTIONS = {'iptables', 'ufw', 'firewalld', 'nftables', 'iptables_state', 'firewalld_info'}
SERVICE_HINTS = [('/etc/ssh/', ['ssh', 'sshd']), ('/etc/nginx/', ['nginx']), ('/etc/apache2/', ['apache2']),
                 ('/etc/httpd/', ['httpd']), ('/etc/haproxy/', ['haproxy']), ('/etc/wireguard/', []),
                 ('/etc/netplan/', []), ('/etc/sysctl', ['systemd-sysctl']), ('/etc/docker/', ['docker']),
                 ('/etc/caddy/', ['caddy']), ('/etc/unbound/', ['unbound']), ('/etc/dnsmasq', ['dnsmasq'])]


def _short(a):
    return (a or '').rsplit('.', 1)[-1]


def _diff_text(d):
    if isinstance(d, list):
        return '\n'.join(_diff_text(x) for x in d)
    if not isinstance(d, dict):
        return ''
    if d.get('prepared'):
        return str(d['prepared'])[:4000]
    before, after = d.get('before', ''), d.get('after', '')
    if isinstance(before, dict) or isinstance(after, dict):
        return '%s: %s -> %s' % (d.get('before_header') or d.get('after_header') or '', json.dumps(before),
                                 json.dumps(after))[:2000]
    lines = difflib.unified_diff(str(before).splitlines(), str(after).splitlines(),
                                 d.get('before_header', 'before'), d.get('after_header', 'after'), lineterm='', n=2)
    return '\n'.join(list(lines)[:120])


def _effects(action, e, paths, services, flags):
    a = _short(action)
    args = e.get('args') or {}
    for item in e.get('items') or []:
        if item.get('changed'):
            _effects(action, item, paths, services, flags)
    if a in PKG_ACTIONS:
        flags.add('packages')
    if a in FW_ACTIONS:
        flags.add('firewall')
    if a in BLIND_ACTIONS:
        flags.add('blind')
    if a in ('service', 'systemd', 'systemd_service') and args.get('name'):
        services.append(str(args['name']))
    if a == 'user' or a == 'group':
        paths.update(['/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow'])
    if a == 'cron' and args.get('cron_file'):
        cf = str(args['cron_file'])
        paths.add(cf if cf.startswith('/') else '/etc/cron.d/' + cf)
    if a == 'hostname':
        paths.update(['/etc/hostname', '/etc/hosts'])
    if a == 'mount':
        paths.add('/etc/fstab')
    if a == 'sysctl':
        paths.add(str(args.get('sysctl_file') or '/etc/sysctl.conf'))
    if a in FILE_ACTIONS:
        for k in ('dest', 'path'):
            v = args.get(k)
            if isinstance(v, str) and v.startswith('/'):
                if a == 'file' and args.get('state') == 'directory':
                    before = (e.get('diff') or {}).get('before') if isinstance(e.get('diff'), dict) else None
                    if not (isinstance(before, dict) and before.get('state') == 'absent'):
                        continue  # don't tar a whole existing tree for a mode/owner change
                paths.add(os.path.normpath(v))
    d = e.get('diff')
    for x in (d if isinstance(d, list) else [d]):
        if isinstance(x, dict):
            for hk in ('before_header', 'after_header'):
                v = x.get(hk)
                if isinstance(v, str) and v.startswith('/') and ' ' not in v and '\n' not in v:
                    paths.add(os.path.normpath(v))


def summarize_plan(doc):
    """Per host: what would change, which paths to snapshot, which services to restart on a revert."""
    hosts = {}
    for t in (doc or {}).get('tasks', []):
        for h, e in t.get('hosts', {}).items():
            s = hosts.setdefault(h, {'changes': [], 'failed': [], 'unreachable': None, 'paths': set(),
                                     'services': [], 'flags': set()})
            st = e.get('status')
            if st == 'unreachable':
                s['unreachable'] = e.get('msg', 'unreachable')
            elif st == 'failed':
                s['failed'].append('%s: %s' % (t['name'], str(e.get('msg', ''))[:300]))
            elif st == 'changed':
                s['changes'].append({'task': t['name'], 'action': t['action'], 'diff': _diff_text(e.get('diff'))})
                _effects(t['action'], e, s['paths'], s['services'], s['flags'])
            elif st == 'skipped' and _short(t['action']) in BLIND_ACTIONS:
                s['flags'].add('blind')
    for h, s in hosts.items():
        for p in sorted(s['paths']):
            for prefix, svcs in SERVICE_HINTS:
                if p.startswith(prefix) or p == prefix.rstrip('/'):
                    s['services'].extend(svcs)
            m = re.match(r'^/etc/systemd/system/([^/]+)\.(service|socket|timer)$', p)
            if m:
                s['services'].append('%s.%s' % (m.group(1), m.group(2)))
            if p.startswith(('/etc/nftables', '/etc/iptables', '/etc/ufw')):
                s['flags'].add('firewall')
        seen = []
        for x in s['services']:
            if x not in seen:
                seen.append(x)
        s['services'] = seen
    return hosts


def routeros_commands(path):
    """The commands a RouterOS playbook sends (raw or community.routeros.command), for the plan and the dialog."""
    try:
        with open(path) as f:
            docs = yaml.load(f, Loader=lint.Loader) or []
    except (OSError, yaml.YAMLError):
        return []
    out = []

    def walk(tasks):
        for t in tasks or []:
            if not isinstance(t, dict):
                continue
            for key in ('block', 'rescue', 'always'):
                walk(t.get(key))
            for k, v in t.items():
                sk = _short(k)
                if sk == 'raw':
                    out.append((t.get('name') or '', v if isinstance(v, str) else json.dumps(v)))
                elif sk == 'command' and 'routeros' in k and isinstance(v, dict):
                    for c in v.get('commands') or []:
                        out.append((t.get('name') or '', str(c)))
    for play in docs if isinstance(docs, list) else []:
        if isinstance(play, dict):
            for key in ('pre_tasks', 'tasks', 'post_tasks', 'handlers'):
                walk(play.get(key))
    return out


def non_raw_tasks(path):
    """Tasks in a playbook that aren't raw commands (Windows and macOS hosts run raw commands only)."""
    try:
        with open(path) as f:
            docs = yaml.load(f, Loader=lint.Loader) or []
    except (OSError, yaml.YAMLError):
        return []
    out = []
    meta = {'name', 'when', 'tags', 'become', 'become_user', 'changed_when', 'failed_when', 'ignore_errors', 'vars',
            'register', 'no_log', 'environment', 'args'}

    def walk(tasks):
        for t in tasks or []:
            if not isinstance(t, dict):
                continue
            if any(k in t for k in ('block', 'rescue', 'always')):
                for key in ('block', 'rescue', 'always'):
                    walk(t.get(key))
                continue
            mods = [k for k in t if k not in meta]
            if not any(_short(k) == 'raw' for k in mods):
                out.append(t.get('name') or (mods[0] if mods else '?'))
    for play in docs if isinstance(docs, list) else []:
        if isinstance(play, dict):
            for key in ('pre_tasks', 'tasks', 'post_tasks', 'handlers', 'roles'):
                if key == 'roles' and play.get('roles'):
                    out.append('roles')
                else:
                    walk(play.get(key))
    return out


def routeros_plan_text(path, targets):
    cmds = routeros_commands(path)
    lines = ['%s: under Safe Mode, %d command%s:' % (', '.join(targets), len(cmds), '' if len(cmds) == 1 else 's')]
    for name, c in cmds[:60]:
        lines.append('  > %s%s' % (c[:300], ('    # ' + name) if name else ''))
    if len(cmds) > 40:
        lines.append('  ! more than 40 commands: Safe Mode keeps 100 actions, then lets go without undoing; split it')
    lines.append('  · RouterOS has no check mode: these are the commands as written, not a preview of the result')
    return '\n'.join(lines)


def openwrt_plan_text(path, targets):
    cmds = routeros_commands(path)
    lines = ['%s: under the on-device guard (snapshot of /etc/config and friends, revert timer in RAM), %d command%s:'
             % (', '.join(targets), len(cmds), '' if len(cmds) == 1 else 's')]
    for name, c in cmds[:60]:
        lines.append('  > %s%s' % (c[:300], ('    # ' + name) if name else ''))
    lines.append('  · OpenWrt has no Python, so no check mode: these are the commands as written; the result is shown '
                 'as a uci diff afterwards')
    lines.append('  · a reboot inside the window loses the guard (as with LuCI\'s own rollback)')
    return '\n'.join(lines)


def routeros_kv(text):
    out = {}
    for line in (text or '').splitlines():
        k, sep, v = line.strip().partition('=')
        if sep and re.match(r'^[a-z_]+$', k):
            out[k] = v
    return out


def macos_plan_text(path, targets):
    cmds = routeros_commands(path)
    lines = ['%s: under the guard (snapshot of the paths you list + a launchd daemon that restores them at the '
             'deadline, also after a reboot), %d command%s run with sudo:' % (', '.join(targets), len(cmds),
                                                                          '' if len(cmds) == 1 else 's')]
    for name, c in cmds[:60]:
        lines.append('  > %s%s' % (c[:300], ('    # ' + name) if name else ''))
    lines.append('  · apply needs paths=[...]: the files and folders the commands change; only those are restored')
    return '\n'.join(lines)


def windows_plan_text(path, targets):
    cmds = routeros_commands(path)
    lines = ['%s: under the guard (snapshot of the paths you list + a one-time scheduled task as SYSTEM that restores '
             'them), %d PowerShell command%s:' % (', '.join(targets), len(cmds), '' if len(cmds) == 1 else 's')]
    for name, c in cmds[:60]:
        lines.append('  > %s%s' % (c[:300], ('    # ' + name) if name else ''))
    lines.append('  · apply needs paths=[...]: the registry keys (HKLM:\\...) and files the commands change; only those '
                 'are restored on a revert')
    return '\n'.join(lines)


def plan_text(plan, stats=None):
    lines = []
    for h in sorted(plan):
        s = plan[h]
        if s['unreachable']:
            lines.append('%s: UNREACHABLE (%s)' % (h, str(s['unreachable'])[:200]))
            continue
        lines.append('%s: %d change%s%s' % (h, len(s['changes']), '' if len(s['changes']) == 1 else 's',
                                           (', %d failed in check mode' % len(s['failed'])) if s['failed'] else ''))
        for c in s['changes'][:25]:
            lines.append('  ~ %s (%s)' % (c['task'], _short(c['action'])))
            if c['diff']:
                lines.extend('      ' + x for x in c['diff'].splitlines()[:40])
        for f in s['failed'][:5]:
            lines.append('  ! %s' % f)
        notes = []
        if 'blind' in s['flags']:
            notes.append('command/shell tasks: check mode can\'t see what they do; only the paths below are '
                         'snapshotted (add more with apply(paths=...))')
        if 'packages' in s['flags']:
            notes.append('package changes: a revert can remove new packages\' config, not downgrade packages')
        if 'firewall' in s['flags']:
            notes.append('firewall: the whole ruleset is snapshotted')
        if s['paths']:
            notes.append('snapshot: ' + ', '.join(sorted(s['paths'])[:20]))
        if s['services']:
            notes.append('restarted on revert: ' + ', '.join(s['services']))
        lines.extend('  · ' + n for n in notes)
    return '\n'.join(lines) or '(no hosts)'


LOOK_SUDOERS = '/etc/sudoers.d/ansible-safe-look'


def create_look_script(look_user, change_user):
    """Shell (run as root) that creates the look account if it is missing: no password, no sudo, no extra groups,
    logging in with the same keys as the change account."""
    for u in (look_user, change_user):
        if not re.match(r'^[a-z_][a-z0-9_.-]{0,31}$', u):
            raise ToolError('bad account name %r' % u)
    return '\n'.join([
        'set -e', 'U=%s; C=%s' % (look_user, change_user),
        'if id "$U" >/dev/null 2>&1; then echo "look=existed"; else',
        '  command -v useradd >/dev/null 2>&1 || { echo "error=no useradd on this host: create $U by hand"; exit 1; }',
        '  useradd -m -s /bin/sh "$U"; echo "look=created"',
        'fi',
        'if id -nG "$U" | tr " " "\\n" | grep -qxE "sudo|wheel|admin|docker|root"; then',
        '  echo "error=$U is in a privileged group; refusing to use it as the look account"; exit 1; fi',
        'H=$(getent passwd "$U" | cut -d: -f6); CH=$(getent passwd "$C" | cut -d: -f6); G=$(id -gn "$U")',
        'install -d -m 700 -o "$U" -g "$G" "$H/.ssh"',
        'grep -v "^#" "$CH/.ssh/authorized_keys" | grep . > "$H/.ssh/authorized_keys.asm"',
        'install -m 600 -o "$U" -g "$G" "$H/.ssh/authorized_keys.asm" "$H/.ssh/authorized_keys"',
        'rm -f "$H/.ssh/authorized_keys.asm"', 'echo "keys=copied from $C"'])


def look_allowlist_script(look_user):
    """Shell (run as root) that gives the look account a few read commands through sudo: Docker's socket is root
    in disguise, so the look account stays out of the docker group and gets ps/logs/inspect instead. The file is
    checked with visudo before it is installed."""
    if not USER_RE.match(look_user):
        raise ToolError('bad look account name')
    return '\n'.join([
        'set -e', 'umask 077',
        'D=$(command -v docker || true); J=$(command -v journalctl || true)',
        'T=$(mktemp)',
        '{',
        '  echo "# ansible-safe-mcp: read-only commands the look account may run with sudo. Remove to revoke."',
        '  A=""',
        '  if [ -n "$D" ]; then',
        '    echo "Cmnd_Alias ASM_DOCKER = $D ps, $D ps *, $D logs *, $D inspect *, $D images, $D images *, '
        '$D stats --no-stream, $D stats --no-stream *"',
        '    A="ASM_DOCKER"',
        '  fi',
        '  if [ -n "$J" ]; then',
        '    echo "Cmnd_Alias ASM_JOURNAL = $J --no-pager *"',
        '    A="${A:+$A, }ASM_JOURNAL"',
        '  fi',
        '  [ -n "$A" ] && echo "%s ALL=(root) NOPASSWD: $A"' % look_user,
        '} > "$T"',
        'if ! grep -q NOPASSWD "$T"; then rm -f "$T"; echo "allowlist=none (no docker, no journalctl)"; exit 0; fi',
        'visudo -cqf "$T"',
        'install -m 0440 -o root -g 0 "$T" %s' % LOOK_SUDOERS,
        'rm -f "$T"',
        'echo "allowlist=installed"', 'grep -v "^#" %s' % LOOK_SUDOERS])


# ------------------------------------------------------------------------------------------------ the server

READS = {
    'linux': {
        'overview': 'hostname; uptime; echo; df -h -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null | '
                    'head -20; echo; free -h 2>/dev/null; echo; systemctl --failed --no-legend --no-pager 2>/dev/null'
                    ' | head -20',
        'services': 'systemctl list-units --type=service --state=running --no-legend --no-pager | head -150; '
                    'echo "--- failed:"; systemctl --failed --no-legend --no-pager',
        'containers': 'sudo -n docker ps -a --format json 2>/dev/null || docker ps -a --format json',
        'disk': 'df -h -x tmpfs -x devtmpfs -x overlay -x squashfs; echo; '
                'du -xh --max-depth=1 / 2>/dev/null | sort -h | tail -15',
        'updates': '(apt list --upgradable 2>/dev/null | tail -n +2) || dnf -q check-update 2>/dev/null || true',
        'interfaces': 'ip -br addr; echo; ip route',
    },
    'openwrt': {
        'overview': 'cat /etc/openwrt_release; echo; uptime; echo; free; echo; df -h / /overlay /tmp 2>/dev/null',
        'interfaces': 'ip -br addr 2>/dev/null || ifconfig; echo; ip route',
        'services': 'ls /etc/rc.d; echo; ubus call service list 2>/dev/null | head -100',
        'disk': 'df -h; echo; du -sh /overlay/upper 2>/dev/null',
        'updates': '(opkg list-upgradable 2>/dev/null || apk list --upgradable 2>/dev/null) | head -50',
        'logs': 'logread | tail -n 200',
        'guard': 'sh "$R"/tmp/asm-guard/guard.sh status 2>/dev/null || echo "asm-guard: not armed"',
    },
    'macos': {
        'overview': 'scutil --get ComputerName; sw_vers; uptime; echo; df -h / | tail -1; echo; '
                    'vm_stat | head -6; echo; which python3; python3 --version 2>&1',
        'services': 'launchctl list | head -150',
        'disk': 'df -h; echo; du -xhd 1 / 2>/dev/null | sort -h | tail -15',
        'updates': 'softwareupdate --history 2>/dev/null | tail -10',
        'interfaces': 'ifconfig | grep -E "^[a-z]|inet "; echo; netstat -rn -f inet | head -15',
        'logs': 'log show --last 1h --predicate "messageType == error" --style compact 2>/dev/null | tail -n 200',
        'guard': 'D=/var/db/ansible-confirmed; if [ -e $D/armed ]; then echo "state=armed $(cat $D/armed)"; '
                 'else echo state=idle; fi; [ -e $D/last ] && echo "last=$(cat $D/last)"; true',
        'python': 'for p in /usr/bin/python3 /usr/local/bin/python3 /opt/homebrew/bin/python3; do [ -x $p ] && '
                  'echo "$p: $($p --version 2>&1 | head -1)"; done; xcode-select -p 2>&1',
    },
    'windows': {
        'overview': "$o = Get-CimInstance Win32_OperatingSystem; $o.Caption + ' ' + $o.Version + ' build ' + $o.BuildNumber; "
                    "'up since ' + $o.LastBootUpTime; 'memory free ' + [math]::Round($o.FreePhysicalMemory/1MB,1) + "
                    "' of ' + [math]::Round($o.TotalVisibleMemorySize/1MB,1) + ' GB'; "
                    "Get-PSDrive -PSProvider FileSystem | Format-Table Name,@{n='FreeGB';e={[math]::Round($_.Free/1GB,1)}},"
                    "@{n='UsedGB';e={[math]::Round($_.Used/1GB,1)}} -AutoSize",
        'services': "Get-Service | Where-Object Status -eq Running | Sort-Object Name | Format-Table Name,DisplayName "
                    "-AutoSize | Out-String -Width 200",
        'disk': "Get-PSDrive -PSProvider FileSystem | Format-Table Name,Used,Free,Root -AutoSize",
        'interfaces': "Get-NetIPAddress -AddressFamily IPv4 | Format-Table InterfaceAlias,IPAddress,PrefixLength "
                      "-AutoSize; Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Format-Table NextHop,InterfaceAlias -AutoSize",
        'logs': "Get-WinEvent -FilterHashtable @{LogName='System','Application'; Level=1,2} -MaxEvents 50 "
                "-ErrorAction SilentlyContinue | Format-Table TimeCreated,ProviderName,Id,Message -Wrap | "
                "Out-String -Width 200",
        'guard': "$g = Join-Path $env:ProgramData 'asm-guard\\guard.ps1'; if (Test-Path $g) { & $g -Action status } "
                 "else { 'state=never armed' }",
    },
    'routeros': {
        'overview': '/system resource print',
        'interfaces': '/interface print terse',
        'logs': '/log print without-paging',
    },
}
INSTRUCTIONS = """ansible-safe-mcp runs Ansible on the user's hosts. Changes undo themselves unless confirmed.

Workflow: hosts (list) -> look (read state; free, unprivileged) -> playbook (write a .yml under playbooks/) ->
plan (check mode + diff; free) -> apply (asks the user once per playbook version, then runs under an on-host revert
timer and keeps the change only after a fresh connection proves the host works) -> job (follow long runs).
For a genuine one-off, hands writes the steps as a playbook in oneoffs/ and runs it the same way.

Rules: show the user the plan before apply. Declare inputs that change per run as params in the first play's
vars.asm_params (e.g. asm_params: {client: {type: str, pattern: '^[a-z0-9-]+$'}}) so one approval covers them.
Playbooks may not use lookups, delegate_to, localhost, connection/user variables, local plugins or check_mode: false:
the lint guard refuses them because they run on the user's Mac. Never put secrets in playbooks. If apply says NOT
CONFIRMED, the host will put itself back at the deadline: say so plainly, then look again after it."""


class Server:
    def __init__(self):
        self.cfg = Config()
        self.cfg.setup()
        self.audit = Audit(self.cfg)
        self.approvals = Approvals(self.cfg)
        migrate_inventory(self.cfg)
        self.jobs_lock = threading.Lock()

    # ---- tool: hosts
    def t_hosts(self, a):
        action = a.get('action', 'list')
        inv = load_inventory(self.cfg)
        hs = hosts_of(inv)
        if action == 'list':
            if not hs:
                return 'No hosts yet. Add one with hosts(action="add", name, address, look_user, change_user).'
            rows = []
            for n, v in sorted(hs.items()):
                rows.append('%s  %s:%s  kind=%s  look=%s change=%s%s%s' % (
                    n, v.get('ansible_host', n), v.get('ansible_port', 22), v.get('asm_kind', 'linux'),
                    v.get('asm_look_user'), v.get('asm_change_user'),
                    ('  via ' + v['asm_jump']) if v.get('asm_jump') else '',
                    ('  groups=' + ','.join(g for g in groups_of(inv, n) if g not in KINDS)) if groups_of(inv, n)
                    else ''))
            return '\n'.join(rows)
        name = a.get('name', '')
        if not NAME_RE.match(name) or name in ('localhost', 'all', 'ungrouped') or name in KINDS:
            raise ToolError('name: letters, digits, . _ -; not localhost/all or a kind name')
        if action == 'remove':
            if name not in hs:
                raise ToolError('no host %s' % name)
            del inv['all']['hosts'][name]
            for g in inv['all']['children'].values():
                ((g or {}).get('hosts') or {}).pop(name, None)
            save_inventory(self.cfg, inv)
            self.audit.write('hosts', summary='removed %s' % name)
            return 'Removed %s from the inventory (its pinned host key stays in known_hosts).' % name
        if action == 'test':
            if name not in hs:
                raise ToolError('no host %s' % name)
            return self._test_host(name)
        if action == 'setup':
            if name not in hs:
                raise ToolError('no host %s' % name)
            hv = hs[name]
            if hv.get('asm_kind', 'linux') != 'linux' or hv['asm_look_user'] == hv['asm_change_user']:
                raise ToolError('setup is for Linux hosts with separate look and change accounts')
            ok, how = ask(self.cfg, 'Let the look account read Docker and journals on %s?' % name,
                          'Installs %s on %s: the look account %s may run, through sudo and nothing else:\n\n'
                          '  docker ps / logs / inspect / images / stats --no-stream\n  journalctl --no-pager ...\n\n'
                          'It stays out of the docker group (Docker\'s socket is root in disguise). The file is checked '
                          'with visudo first; delete it to revoke.' % (LOOK_SUDOERS, name, hv['asm_look_user']))
            if not ok:
                self.audit.write('hosts', summary='setup %s declined (%s)' % (name, how))
                return 'Not changed: the user declined (%s).' % how
            return self._install_look_allowlist(name)
        if action != 'add':
            raise ToolError('action must be list, add, test, setup or remove')
        address = a.get('address') or name
        port = int(a.get('port') or 22)
        kind = a.get('kind', 'linux')
        look_u, change_u = a.get('look_user', ''), a.get('change_user', '')
        jump = a.get('jump') or ''
        key_file = a.get('key_file') or ''
        look_key = a.get('look_key') or key_file
        change_key = a.get('change_key') or key_file
        groups = a.get('groups') or []
        create_look = bool(a.get('create_look'))
        if create_look and kind != 'linux':
            raise ToolError('create_look is for Linux hosts')
        if not ADDR_RE.match(address) or address.startswith('-'):
            raise ToolError('address: a hostname or IP')
        if kind not in KINDS:
            raise ToolError('kind must be one of %s' % ', '.join(KINDS))
        if kind == 'jump':
            change_u = change_u or look_u
            change_key = look_key
        if not (USER_RE.match(look_u) and USER_RE.match(change_u)):
            raise ToolError('look_user and change_user: account names on the host')
        if kind not in ('openwrt', 'windows', 'macos', 'jump') and (look_u == change_u or look_u == 'root'):
            raise ToolError('look_user and change_user are two different accounts on the host: one that can only '
                            'read, one that can change things (sudo); the look account must not be root')
        jump_host = None
        if jump:
            jump_host = hs.get(jump)
            if not jump_host or jump_host.get('asm_kind') != 'jump':
                raise ToolError('jump: the name of a host added with kind="jump" (add the jump host first)')
        proxy = routeros.proxy_command(jump_host, self.cfg.known_hosts) if jump_host else ''
        if kind == 'jump' and jump:
            raise ToolError('a jump host is reached directly')
        for label, kf in (('key_file', key_file), ('look_key', look_key), ('change_key', change_key)):
            if kf and not os.path.isfile(os.path.expanduser(kf)):
                raise ToolError('%s not found: %s' % (label, kf))
        look_key = os.path.expanduser(look_key) if look_key else ''
        change_key = os.path.expanduser(change_key) if change_key else ''
        if not all(isinstance(g, str) and NAME_RE.match(g) and g not in KINDS + ('all',) for g in groups):
            raise ToolError('groups: names of letters, digits, . _ -')
        # first contact: record the host key in a scratch file, show its fingerprint, ask
        d = scratch(self.cfg, 'add')
        kh = os.path.join(d, 'known_hosts')
        cmd = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=accept-new', '-o', 'UserKnownHostsFile=' + kh,
               '-o', 'ConnectTimeout=15', '-p', str(port)]
        if proxy:
            cmd += ['-o', 'ProxyCommand=' + proxy]
        if look_key:
            cmd += ['-i', look_key, '-o', 'IdentitiesOnly=yes']
        if kind == 'routeros':
            cmd += ['%s@%s' % (look_u, address), '/system identity print']
        elif kind == 'jump':
            # a jump account may only be allowed to forward to certain ports (permitopen): check the login only;
            # forwarding is proven when a host behind it is added
            cmd += ['%s@%s' % (look_u, address), 'true']
        elif kind == 'openwrt':
            cmd += ['%s@%s' % (look_u, address), 'id -un; cat /etc/openwrt_release 2>/dev/null | head -3']
        elif kind == 'windows':
            cmd += ['%s@%s' % (look_u, address), 'whoami']
        elif create_look:
            cmd = [x if x != look_key else change_key for x in cmd]
            cmd += ['%s@%s' % (change_u, address), 'id -un; id %s >/dev/null 2>&1 && echo LOOK-EXISTS; '
                    'sudo -n true 2>/dev/null && echo SUDO-OK || echo NO-SUDO' % shlex.quote(look_u)]
        else:
            cmd += ['%s@%s' % (look_u, address), 'id -un; sudo -n true 2>/dev/null && echo SUDO-OK || echo NO-SUDO']
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=40, stdin=subprocess.DEVNULL)
        if not (os.path.exists(kh) and os.path.getsize(kh) > 0):
            shutil.rmtree(d, ignore_errors=True)
            raise ToolError('could not reach %s as %s: %s' % (address, look_u, (p.stderr.strip() or 'no answer')[-400:]))
        fp = subprocess.run(['ssh-keygen', '-lf', kh], capture_output=True, text=True).stdout.strip()
        if p.returncode != 0:
            shutil.rmtree(d, ignore_errors=True)
            raise ToolError('%s answered but the %s account %s could not log in: %s' % (
                address, 'change' if create_look else 'look', change_u if create_look else look_u,
                p.stderr.strip()[-300:]))
        if create_look and 'SUDO-OK' not in p.stdout:
            shutil.rmtree(d, ignore_errors=True)
            raise ToolError('create_look needs a change account that can sudo without a password; %s cannot' % change_u)
        warn = ''
        if kind in ('windows', 'macos') and look_u == change_u:
            warn = ('\n\nNote: one account (%s) for reads and changes: reads still only read, but the account could '
                    'change things.' % look_u)
        if kind == 'openwrt' and look_u == change_u:
            warn = ('\n\nNote: OpenWrt usually has one account, so reads run as %s too. They still only read, but '
                    'the account could change things.' % look_u)
        if create_look:
            warn = ('\n\nCreates the look account %s (no password, no sudo, no groups; same keys as %s).' % (
                look_u, change_u) if 'LOOK-EXISTS' not in p.stdout else
                    '\n\n%s already exists: it gets the same keys as %s.' % (look_u, change_u))
        elif kind in ANSIBLE_KINDS and look_u != change_u and 'SUDO-OK' in p.stdout:
            warn = '\n\nWARNING: the look account can sudo without a password, so it is not read-only.'
        allow = ''
        if kind == 'linux' and look_u != change_u:
            allow = ('\n\nAlso installs %s: the look account may run docker ps/logs/inspect and journalctl '
                     'through sudo, nothing else.' % LOOK_SUDOERS)
        text = ('Add host %s\n\n%s port %d%s\nkind: %s\nlook account: %s\nchange account: %s\n\nHost key:\n%s%s%s' % (
            name, address, port, (' via ' + jump) if jump else '', kind, look_u, change_u, fp, warn, allow))
        ok, how = ask(self.cfg, 'Add %s to ansible-safe-mcp?' % name, text)
        if not ok:
            shutil.rmtree(d, ignore_errors=True)
            self.audit.write('hosts', summary='add %s declined (%s)' % (name, how))
            return 'Not added: the user declined (%s).' % how
        with open(kh) as f:
            new_keys = f.read()
        host_tag = address if port == 22 else '[%s]:%d' % (address, port)
        with open(self.cfg.known_hosts) as f:
            kept = [line for line in f if line.split(' ', 1)[0] not in (address, host_tag)]
        with open(self.cfg.known_hosts, 'w') as f:
            f.writelines(kept)
            f.write(new_keys)
        shutil.rmtree(d, ignore_errors=True)
        entry = {'ansible_host': address, 'ansible_port': port, 'asm_kind': kind, 'asm_look_user': look_u,
                 'asm_change_user': change_u}
        if look_key:
            entry['asm_look_key'] = look_key
        if change_key:
            entry['asm_change_key'] = change_key
        if jump:
            entry['asm_jump'] = jump
            entry['asm_proxy_command'] = proxy
            entry['ansible_ssh_common_args'] = '-o ProxyCommand=%s' % shlex.quote(proxy)
        if kind == 'routeros':
            entry['ansible_network_os'] = 'community.routeros.routeros'
            entry['ansible_ssh_use_tty'] = False
        inv['all']['hosts'][name] = entry
        for g in [kind] + list(groups):
            grp = inv['all']['children'].setdefault(g, {}) or {}
            grp.setdefault('hosts', {})
            if grp['hosts'] is None:
                grp['hosts'] = {}
            grp['hosts'][name] = None
            inv['all']['children'][g] = grp
        save_inventory(self.cfg, inv)
        self.audit.write('hosts', summary='added %s %s:%d kind=%s' % (name, address, port, kind), fingerprint=fp)
        extra = ''
        if create_look:
            rc, out = routeros.ssh_exec(entry, change_u, self.cfg.known_hosts, 'sudo -n /bin/sh -s', key=change_key or None,
                                        timeout=60, stdin=create_look_script(look_u, change_u) + '\n')
            kv = routeros_kv(out)
            self.audit.write('hosts', summary='look account on %s: %s' % (name, kv.get('look') or kv.get('error')))
            if rc != 0 or not kv.get('look'):
                return 'Added %s, but the look account could not be set up: %s' % (name, (kv.get('error') or
                                                                                        out.strip()[-300:]))
        if kind == 'linux' and look_u != change_u:
            extra = '\n' + self._install_look_allowlist(name)
        return 'Added %s (%s).\n\n%s%s' % (name, fp.split(' ')[1] if ' ' in fp else fp, self._test_host(name), extra)

    def _install_look_allowlist(self, name):
        hv = hosts_of(load_inventory(self.cfg))[name]
        rc, out = routeros.ssh_exec(hv, hv['asm_change_user'], self.cfg.known_hosts, 'sudo -n /bin/sh -s',
                                    key=hv.get('asm_change_key'), timeout=60,
                                    stdin=look_allowlist_script(hv['asm_look_user']) + '\n')
        state = routeros_kv(out).get('allowlist')
        self.audit.write('hosts', summary='look allowlist on %s: %s' % (name, state or 'failed rc=%s' % rc))
        if rc != 0 or not state:
            return 'look allowlist: FAILED: %s' % out.strip()[-300:]
        if state == 'none':
            return 'look allowlist: not needed (no docker, no journalctl on the host)'
        return 'look allowlist: installed (%s): docker ps/logs/inspect/images/stats and journalctl through sudo' % (
            LOOK_SUDOERS)

    def _test_host(self, name):
        check_inventory(self.cfg)
        hv = hosts_of(load_inventory(self.cfg))[name]
        kind = hv.get('asm_kind', 'linux')
        if kind == 'jump':
            rc, txt = routeros.ssh_exec(hv, hv['asm_look_user'], self.cfg.known_hosts, 'true',
                                        key=hv.get('asm_look_key'), timeout=30)
            return 'jump account: %s' % ('logs in (forwarding is checked when a host behind it is added)' if rc == 0
                                         else 'FAILED: %s' % txt.strip()[-300:])
        if kind == 'windows':
            out = []
            admin = ('([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())'
                     '.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)')
            for account in ('look', 'change'):
                rc, txt = windows.win_exec(hv, hv['asm_%s_user' % account], self.cfg.known_hosts,
                                           'whoami; ' + admin, key=hv.get('asm_%s_key' % account), timeout=60)
                ok = rc == 0 and (account == 'look' or txt.strip().endswith('True'))
                what = 'logs in' + (' as an administrator' if account == 'change' else '')
                out.append('%s account: %s' % (account, what if ok else 'FAILED: %s' % txt.strip()[-300:]))
            return '\n'.join(out)
        if kind == 'macos':
            out = []
            for account in ('look', 'change'):
                rc, txt = routeros.ssh_exec(hv, hv['asm_%s_user' % account], self.cfg.known_hosts,
                                            'id -un && sudo -n true' if account == 'change' else 'id -un',
                                            key=hv.get('asm_%s_key' % account), timeout=30)
                what = 'logs in' + (' and can sudo' if account == 'change' else '')
                out.append('%s account: %s' % (account, what if rc == 0 else 'FAILED: %s' % txt.strip()[-300:]))
            rc, py = routeros.ssh_exec(hv, hv['asm_look_user'], self.cfg.known_hosts,
                                       '/usr/bin/xcode-select -p >/dev/null 2>&1 && /usr/bin/python3 --version',
                                       key=hv.get('asm_look_key'), timeout=30)
            out.append('python: %s' % (py.strip() if rc == 0 else 'none (not needed: reads, the guard and changes go '
                                                                 'over plain SSH)'))
            return '\n'.join(out)
        if kind == 'openwrt':
            out = []
            for account in ('look', 'change'):
                rc, txt = routeros.ssh_exec(hv, hv['asm_%s_user' % account], self.cfg.known_hosts,
                                            'id -un && test -w "$R/etc/config"' if account == 'change' else 'id -un',
                                            key=hv.get('asm_%s_key' % account), timeout=30)
                what = 'logs in' + (' and can write /etc/config' if account == 'change' else '')
                out.append('%s account: %s' % (account, what if rc == 0 else 'FAILED: %s' % txt.strip()[-300:]))
            return '\n'.join(out)
        if kind == 'routeros':
            out = []
            for account in ('look', 'change'):
                ok, txt = routeros.run_command(hv, hv['asm_%s_user' % account], self.cfg.known_hosts,
                                               '/system identity print', key=hv.get('asm_%s_key' % account), timeout=30)
                out.append('%s account: %s' % (account, 'logs in' if ok else 'FAILED: %s' % txt.strip()[-300:]))
            return '\n'.join(out)
        d = scratch(self.cfg, 'test')
        pb = os.path.join(d, 'test.yml')
        out = []
        for account, become in (('look', False), ('change', True)):
            if kind == 'routeros':
                task = '    - ansible.builtin.raw: /system identity print\n'
            else:
                task = '    - ansible.builtin.ping:\n'
            with open(pb, 'w') as f:
                f.write('- hosts: %s\n  gather_facts: false\n  become: %s\n  tasks:\n%s' % (
                    name, 'true' if become and kind in ANSIBLE_KINDS else 'false', task))
            vf = os.path.join(d, 'vars.yml')
            write_vars(vf, account)
            doc, err, rc = run_playbook(self.cfg, pb, vf, timeout=90)
            st = ((doc or {}).get('tasks') or [{}])[-1].get('hosts', {}).get(name, {}) if doc else {}
            okay = st.get('status') in ('ok', 'changed')
            what = 'logs in' + (' and can sudo' if become and kind in ANSIBLE_KINDS else '')
            out.append('%s account: %s' % (account, what if okay else 'FAILED: %s' % (st.get('msg') or err)[-300:]))
        shutil.rmtree(d, ignore_errors=True)
        return '\n'.join(out)

    # ---- tool: look
    def t_look(self, a):
        pattern = a.get('hosts', '')
        if not PATTERN_RE.match(pattern or '') or re.search(r'localhost|127\.|::1', pattern):
            raise ToolError('hosts: a host name, group or Ansible pattern from the inventory (not localhost)')
        check_inventory(self.cfg)
        inv = load_inventory(self.cfg)
        if not hosts_of(inv):
            raise ToolError('no hosts in the inventory yet')
        read = a.get('read')
        command = a.get('command')
        if bool(read) == bool(command):
            raise ToolError('give either read (%s) or command' % ', '.join(sorted(set(READS['linux']) |
                                                                                {'logs', 'guard'})))
        lines = int(a.get('lines') or 200)
        lines = max(1, min(lines, 2000))
        tasks = []
        if command:
            if not isinstance(command, str) or len(command) > 4000:
                raise ToolError('command: a string up to 4000 characters')
            tasks.append(('linux', command))
            tasks.append(('macos', command))
            tasks.append(('routeros', command))
        elif read == 'guard':
            pass
        elif read == 'logs':
            unit, container, since, grep = a.get('unit'), a.get('container'), a.get('since'), a.get('grep')
            for v, rx in ((unit, r'^[A-Za-z0-9@._:-]{1,120}$'), (container, r'^[A-Za-z0-9_.-]{1,120}$'),
                          (since, r'^[A-Za-z0-9 :.-]{1,40}$')):
                if v and not re.match(rx, v):
                    raise ToolError('bad unit, container or since value')
            q = shlex.quote
            if container:
                c = 'sudo -n docker logs --tail %d %s%s 2>&1' % (lines, ('--since %s ' % q(since)) if since else '',
                                                                  q(container))
            else:
                jargs = '-n %d %s%s' % (lines, ('-u %s ' % q(unit)) if unit else '-p warning ',
                                         ('--since %s' % q(since)) if since else '')
                c = '{ sudo -n journalctl --no-pager %s 2>/dev/null || journalctl --no-pager %s; }' % (jargs, jargs)
            if grep:
                c += ' | grep -i -- %s' % q(str(grep)[:200])
            tasks.append(('linux', c + ' | tail -n %d' % lines))
            tasks.append(('routeros', READS['routeros']['logs']))
        else:
            for kind in KINDS:
                if read in READS.get(kind, {}):
                    tasks.append((kind, READS[kind][read]))
            if not tasks:
                raise ToolError('unknown read %r' % read)
        # RouterOS hosts are read over plain SSH, one connection each, no Ansible in between
        hs = hosts_of(inv)
        per = {}
        ow_hosts = [h for h in self._resolve(pattern) if hs.get(h, {}).get('asm_kind') == 'openwrt']
        if ow_hosts:
            ow_cmd = command or READS['openwrt'].get(read or '')
            if read == 'logs':
                ow_cmd = 'logread | tail -n %d' % lines + (' | grep -i -- %s' % shlex.quote(str(a['grep'])[:200])
                                                          if a.get('grep') else '')
            for h in ow_hosts:
                hv = hs[h]
                if not ow_cmd:
                    per[h] = '(no %s read for OpenWrt)' % read
                    continue
                rc, txt = routeros.ssh_exec(hv, hv['asm_look_user'], self.cfg.known_hosts, ow_cmd,
                                            key=hv.get('asm_look_key'), timeout=int(a.get('timeout') or 120))
                per[h] = txt.rstrip() + ('' if rc == 0 else '\n[exit %s]' % rc)
        mac_hosts = [h for h in self._resolve(pattern) if hs.get(h, {}).get('asm_kind') == 'macos']
        if mac_hosts:
            mac_cmd = command or READS['macos'].get(read or '')
            for h in mac_hosts:
                hv = hs[h]
                if not mac_cmd:
                    per[h] = '(no %s read for macOS)' % read
                    continue
                rc, txt = routeros.ssh_exec(hv, hv['asm_look_user'], self.cfg.known_hosts, mac_cmd,
                                            key=hv.get('asm_look_key'), timeout=int(a.get('timeout') or 120))
                per[h] = txt.rstrip() + ('' if rc == 0 else '\n[exit %s]' % rc)
        win_hosts = [h for h in self._resolve(pattern) if hs.get(h, {}).get('asm_kind') == 'windows']
        if win_hosts:
            win_cmd = command or READS['windows'].get(read or '')
            for h in win_hosts:
                hv = hs[h]
                if not win_cmd:
                    per[h] = '(no %s read for Windows)' % read
                    continue
                rc, txt = windows.win_exec(hv, hv['asm_look_user'], self.cfg.known_hosts, win_cmd,
                                           key=hv.get('asm_look_key'), timeout=int(a.get('timeout') or 120))
                per[h] = txt.rstrip() + ('' if rc == 0 else '\n[exit %s]' % rc)
        ros_hosts = [h for h in self._resolve(pattern) if hs.get(h, {}).get('asm_kind') == 'routeros']
        ros_cmd = next((c for k, c in tasks if k == 'routeros'), None)
        if ros_hosts and ros_cmd:
            threads = []

            def read_one(h):
                hv = hs[h]
                ok, txt = routeros.run_command(hv, hv['asm_look_user'], self.cfg.known_hosts, ros_cmd,
                                               key=hv.get('asm_look_key'), timeout=int(a.get('timeout') or 120))
                per[h] = txt.rstrip() + ('' if ok else '\n[failed]')
            for h in ros_hosts:
                t = threading.Thread(target=read_one, args=(h,))
                t.start()
                threads.append(t)
            for t in threads:
                t.join()
        tasks = [(k, c) for k, c in tasks if k == 'linux']
        linux_left = [h for h in self._resolve(pattern) if hs.get(h, {}).get('asm_kind', 'linux') == 'linux']
        if linux_left and (read == 'guard' or tasks):
            per.update(self._look_ansible(pattern, read, tasks, a))
        self.audit.write('look', summary='%s %s' % (pattern, read or ('command: ' + command[:200])))
        if not per:
            return 'No hosts matched %r.' % pattern
        return '\n\n'.join('== %s\n%s' % (h, per[h]) for h in sorted(per))

    def _resolve(self, pattern):
        """Host names a pattern matches, from the inventory (ansible-inventory would do it too, but slower)."""
        inv = load_inventory(self.cfg)
        hs = hosts_of(inv)
        groups = {g: set(((v or {}).get('hosts') or {}).keys()) for g, v in (inv['all'].get('children') or {}).items()}
        groups['all'] = set(hs)
        out = set()
        import fnmatch
        for part in re.split(r'[,:]', pattern):
            if not part or part.startswith(('!', '&')):
                continue
            if part in groups:
                out |= groups[part]
            else:
                out |= {h for h in hs if fnmatch.fnmatch(h, part)}
        for part in re.split(r'[,:]', pattern):
            if part.startswith('!'):
                p = part[1:]
                out -= groups.get(p, {h for h in hs if fnmatch.fnmatch(h, p)})
            elif part.startswith('&'):
                p = part[1:]
                out &= groups.get(p, {h for h in hs if fnmatch.fnmatch(h, p)})
        return sorted(out)

    def _look_ansible(self, pattern, read, tasks, a):
        d = scratch(self.cfg, 'look')
        pb = os.path.join(d, 'look.yml')
        body = ['- hosts: %s' % json.dumps(pattern), '  gather_facts: false', '  tasks:']
        if read == 'guard':
            body += ['    - mureev.confirmed.status:', '      when: asm_kind | default("linux") in ["linux", "macos"]']
        for kind, c in tasks:
            mod = 'ansible.builtin.shell' if kind in ANSIBLE_KINDS else 'ansible.builtin.raw'
            body += ['    - name: %s' % kind, '      %s: %s' % (mod, unsafe_cmd(c)),
                     '      changed_when: false', '      failed_when: false',
                     '      when: asm_kind | default("linux") == "%s"' % kind]
        with open(pb, 'w') as f:
            f.write('\n'.join(body) + '\n')
        vf = os.path.join(d, 'vars.yml')
        write_vars(vf, 'look')
        doc, err, rc = run_playbook(self.cfg, pb, vf, timeout=int(a.get('timeout') or 120))
        shutil.rmtree(d, ignore_errors=True)
        if doc is None:
            raise ToolError('ansible failed: %s' % err[-2000:])
        per = {}
        for t in doc.get('tasks', []):
            for h, e in t['hosts'].items():
                if e.get('status') == 'skipped':
                    continue
                if e.get('status') == 'unreachable':
                    per[h] = 'UNREACHABLE: %s' % str(e.get('msg', ''))[:300]
                    continue
                if t['action'].endswith('status'):
                    per[h] = 'guard: %s%s%s' % (e.get('state', '?'),
                                                (' (%s, reverts at %s)' % (e.get('id'), e.get('deadline_iso')))
                                                if e.get('state') == 'armed' else '',
                                                ('; last: ' + e['last']) if e.get('last') else '')
                    continue
                txt = (e.get('stdout') or '').rstrip()
                if e.get('stderr'):
                    txt += '\n[stderr] ' + e['stderr'].strip()
                if e.get('rc') not in (0, None):
                    txt += '\n[exit %s]' % e.get('rc')
                if e.get('status') == 'failed' and e.get('msg'):
                    txt += '\n[failed] ' + str(e['msg'])
                per[h] = txt
        return per

    # ---- tool: playbook
    def t_playbook(self, a):
        action = a.get('action', 'list')
        cfg = self.cfg
        if action == 'list':
            out = []
            for root in ('playbooks', 'oneoffs', 'roles'):
                base = os.path.join(cfg.project, root)
                for dirpath, dirnames, filenames in os.walk(base):
                    dirnames[:] = sorted(x for x in dirnames if not x.startswith('.'))
                    for fn in sorted(filenames):
                        out.append(os.path.relpath(os.path.join(dirpath, fn), cfg.project))
            findings = lint.lint_tree(cfg.project, ('playbooks', 'roles', 'oneoffs'))
            return ('\n'.join(out) or '(no playbooks yet)') + (
                '\n\nLint: clean' if not findings else '\n\nLint REFUSES:\n' + lint.format_findings(findings))
        path, rel = project_path(cfg, a.get('path', ''))
        if action == 'read':
            if not os.path.isfile(path):
                raise ToolError('no such file: %s' % rel)
            with open(path, encoding='utf-8', errors='replace') as f:
                return f.read()[:MAX_TEXT]
        if action == 'delete':
            if not os.path.isfile(path):
                raise ToolError('no such file: %s' % rel)
            os.remove(path)
            self._commit('delete %s' % rel)
            self.audit.write('playbook', summary='deleted %s' % rel)
            return 'Deleted %s.' % rel
        if action == 'lint':
            findings = lint.lint_tree(cfg.project, ('playbooks', 'roles', 'oneoffs'))
            return 'Lint: clean' if not findings else 'Lint REFUSES:\n' + lint.format_findings(findings)
        if action != 'write':
            raise ToolError('action must be list, read, write, delete or lint')
        content = a.get('content')
        if not isinstance(content, str) or len(content) > 1_000_000:
            raise ToolError('content: the file text')
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + '.new'
        with open(tmp, 'w', encoding='utf-8') as f:
            f.write(content)
        os.replace(tmp, path)
        self._commit('write %s' % rel)
        self.audit.write('playbook', summary='wrote %s' % rel, sha256=hashlib.sha256(content.encode()).hexdigest())
        findings = lint.lint_tree(cfg.project, ('playbooks', 'roles', 'oneoffs'))
        mine = [f for f in findings if f['file'] == rel]
        msg = ['Wrote %s.' % rel]
        if mine:
            msg.append('Lint REFUSES this file (plan and apply will not run it):\n' + lint.format_findings(mine))
        elif findings:
            msg.append('This file is clean, but other files in the project are refused, so nothing runs until they '
                       'are fixed:\n' + lint.format_findings(findings))
        else:
            msg.append('Lint: clean.')
            if rel.endswith(('.yml', '.yaml')) and rel.count(os.sep) == 1:
                d = scratch(cfg, 'syntax')
                vf = os.path.join(d, 'vars.yml')
                write_vars(vf, 'look')
                env = ansible_env(cfg)
                env['ANSIBLE_STDOUT_CALLBACK'] = 'default'
                p = subprocess.run([cfg.playbook_bin, path, '--syntax-check', '-e', '@' + vf], cwd=cfg.project,
                                   env=env, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
                shutil.rmtree(d, ignore_errors=True)
                msg.append('Syntax: ok.' if p.returncode == 0 else 'Syntax check failed:\n' +
                           (p.stderr.strip() or p.stdout.strip())[-1500:])
                schema = params_schema(path)
                if schema:
                    msg.append('Declared params: %s' % ', '.join('%s (%s)' % (k, (v or {}).get('type', 'str')
                                                                              if isinstance(v, dict) else v)
                                                                 for k, v in schema.items()))
        return '\n'.join(msg)

    def _commit(self, what):
        if shutil.which('git') and os.path.isdir(os.path.join(self.cfg.project, '.git')):
            subprocess.run(['git', 'add', '-A', 'playbooks', 'roles', 'oneoffs', 'inventory'], cwd=self.cfg.project,
                           capture_output=True)
            subprocess.run(['git', '-c', 'user.name=ansible-safe-mcp', '-c', 'user.email=ansible-safe-mcp@localhost',
                            'commit', '-q', '-m', 'ansible-safe-mcp: ' + what], cwd=self.cfg.project,
                           capture_output=True)

    # ---- shared: lint, targets, plan
    def _prepare(self, a):
        path, rel = playbook_path(self.cfg, a.get('playbook', ''))
        findings = lint.lint_tree(self.cfg.project, ('playbooks', 'roles', 'oneoffs'))
        if findings:
            raise ToolError('Lint refuses the project, so nothing runs:\n' + lint.format_findings(findings))
        check_inventory(self.cfg)
        limit = a.get('limit') or ''
        if limit and (not PATTERN_RE.match(limit) or re.search(r'localhost|127\.|::1', limit)):
            raise ToolError('limit: an Ansible host pattern from the inventory')
        params = validate_params(params_schema(path), a.get('params'))
        targets = list_targets(self.cfg, path, limit)
        if not targets:
            raise ToolError('the playbook matches no hosts%s' % (' with limit %s' % limit if limit else ''))
        hs = hosts_of(load_inventory(self.cfg))
        unknown = [t for t in targets if t not in hs]
        if unknown:
            raise ToolError('not in the inventory: %s' % ', '.join(unknown))
        jumps = [t for t in targets if hs[t].get('asm_kind') == 'jump']
        if jumps:
            raise ToolError('%s: jump hosts only carry connections; limit the playbook to other hosts' %
                            ', '.join(jumps))
        return path, rel, limit, params, targets

    def _plan(self, path, limit, params):
        d = scratch(self.cfg, 'plan')
        vf = os.path.join(d, 'vars.yml')
        write_vars(vf, 'change', params)
        doc, err, rc = run_playbook(self.cfg, path, vf, limit=limit, check=True, timeout=600)
        shutil.rmtree(d, ignore_errors=True)
        if doc is None:
            raise ToolError('the plan could not run: %s' % err[-2500:])
        return summarize_plan(doc)

    # ---- tool: plan
    def t_plan(self, a):
        path, rel, limit, params, targets = self._prepare(a)
        kind = self._kind_of(targets)
        if kind in SERVER_GUARDED:
            h = version_hash(self.cfg, rel, targets)
            approved = self.approvals.approved(h, rel, targets)
            self.audit.write('plan', summary='%s on %s' % (rel, ','.join(targets)), version=h[:12])
            return '%s on %s\nversion %s: %s\n\n%s' % (
                rel, ', '.join(targets), h[:12],
                'approved before, apply runs without asking' if approved else 'not approved yet, apply will ask',
                {'routeros': routeros_plan_text, 'openwrt': openwrt_plan_text, 'macos': macos_plan_text,
                 'windows': windows_plan_text}[kind](path, targets))
        plan = self._plan(path, limit, params)
        h = version_hash(self.cfg, rel, targets)
        approved = self.approvals.approved(h, rel, targets)
        self.audit.write('plan', summary='%s on %s' % (rel, ','.join(targets)), version=h[:12])
        return '%s on %s\nversion %s: %s\n\n%s' % (
            rel, ', '.join(targets), h[:12],
            'approved before, apply runs without asking' if approved else 'not approved yet, apply will ask the user',
            plan_text(plan))

    # ---- tool: apply
    def t_apply(self, a):
        """Starts the change as a job and answers within wait_s (below the ~80 s a remote client waits), whether
        it is still planning, waiting for the user's approval, running, or done."""
        path, rel, limit, params, targets = self._prepare(a)
        kind = self._kind_of(targets)
        try:
            window = parse_window(a.get('window', '10m'))
        except ValueError as e:
            raise ToolError(str(e))
        checks = a.get('checks') or ['ssh']
        if not isinstance(checks, list) or not all(isinstance(c, str) and len(c) < 500 for c in checks):
            raise ToolError('checks: a list of strings')
        extra_paths = a.get('paths') or []
        extra_services = a.get('services') or []
        for p in extra_paths:
            if not isinstance(p, str) or '\n' in p or not (p.startswith('/') or re.match(
                    r'^([A-Za-z]:\\|(HKLM|HKCU|HKCR|HKU|HKCC):?\\)', p)):
                raise ToolError('paths: absolute paths on the hosts (/etc/..., C:\\..., HKLM:\\...)')
        for s in extra_services:
            if not isinstance(s, str) or not re.match(r'^[A-Za-z0-9@._-]{1,120}$', s):
                raise ToolError('services: unit names')
        if kind in ('macos', 'windows'):
            other = non_raw_tasks(path)
            if other:
                raise ToolError('%s hosts run raw commands only (no Python needed there); these tasks are not: %s. '
                                'Write them as ansible.builtin.raw commands.' % (
                                    'macOS' if kind == 'macos' else 'Windows', ', '.join(map(str, other[:8]))))
        if kind == 'macos' and not extra_paths:
            raise ToolError('macOS changes need paths=[...]: the files and folders the commands change. Only those are '
                            'snapshotted and restored on a revert.')
        if kind == 'windows':
            if not extra_paths:
                raise ToolError('Windows changes need paths=[...]: the registry keys (HKLM:\\SOFTWARE\\...) and files '
                                'or folders the commands change. Only those are snapshotted and restored on a revert.')
            if any('{{' in c or '{%' in c for _, c in routeros_commands(path)):
                raise ToolError('Windows playbooks run their raw commands as written (no templating): remove {{ }}')
        h = version_hash(self.cfg, rel, targets)
        job_id = time.strftime('%m%d%H%M') + secrets.token_hex(2)
        os.makedirs(os.path.join(self.cfg.jobs, job_id), mode=0o700)
        job = {'id': job_id, 'playbook': rel, 'targets': targets, 'version': h, 'params': params, 'window': window,
               'started': time.time(), 'status': 'planning', 'asked': False, 'kind': kind}
        self._save_job(job)
        args = (job_id, path, rel, limit, params, targets, window, checks, extra_paths, extra_services, h)
        t = threading.Thread(target=self._apply_flow, args=args, daemon=True)
        t.start()
        t.join(timeout=max(0, min(int(a.get('wait_s', 55)), 70)))
        return self._job_text(job_id)

    def _set(self, job_id, **kw):
        job = self._load_job(job_id)
        job.update(kw)
        self._save_job(job)
        return job

    def _apply_flow(self, job_id, path, rel, limit, params, targets, window, checks, extra_paths, extra_services, h):
        try:
            kind = self._load_job(job_id)['kind']
            if kind == 'routeros':
                plan, plan_txt = None, routeros_plan_text(path, targets)
            elif kind == 'openwrt':
                plan, plan_txt = None, openwrt_plan_text(path, targets)
            elif kind == 'windows':
                plan, plan_txt = None, windows_plan_text(path, targets)
            elif kind == 'macos':
                plan, plan_txt = None, macos_plan_text(path, targets)
            else:
                plan = self._plan(path, limit, params)
                unreachable = [x for x in targets if (plan.get(x) or {}).get('unreachable')]
                if unreachable:
                    self._set(job_id, status='failed', error='the plan could not reach %s; nothing was changed.\n\n%s'
                              % (', '.join(unreachable), plan_text(plan)))
                    return
                plan_txt = plan_text(plan)
            if not self.approvals.approved(h, rel, targets):
                self._set(job_id, status='awaiting-approval', plan=plan_txt[:6000])
            ok, asked, how = self._approve(rel, targets, h, params, window, plan_txt)
            if not ok:
                self._set(job_id, status='declined', asked=True, error=how)
                self.audit.write('apply', summary='%s declined (%s)' % (rel, how), version=h[:12])
                return
            self._set(job_id, status='running', asked=asked)
            self.audit.write('apply', summary='%s on %s (job %s)' % (rel, ','.join(targets), job_id), version=h[:12],
                             asked=asked, params=params)
            jd = os.path.join(self.cfg.jobs, job_id)
            vf = os.path.join(jd, 'vars.yml')
            if plan is None:
                write_vars(vf, 'change', params)
                if kind == 'openwrt':
                    self._run_openwrt(job_id, path, vf, targets, checks, window)
                elif kind == 'windows':
                    self._run_windows(job_id, path, targets, checks, window, extra_paths)
                elif kind == 'macos':
                    self._run_macos(job_id, path, vf, targets, checks, window, extra_paths, extra_services)
                else:
                    self._run_routeros(job_id, path, vf, targets, checks, window)
                return
            snap = {t: {'paths': sorted(set(plan.get(t, {}).get('paths', set())) | set(extra_paths)),
                        'services': list(dict.fromkeys(plan.get(t, {}).get('services', []) + extra_services)),
                        'firewall': 'firewall' in plan.get(t, {}).get('flags', set())} for t in targets}
            self._set(job_id, snapshot=snap)
            write_vars(vf, 'change', dict(params, asm_snapshot=snap))
            hosts_pat = ':'.join(targets)
            wrapper = os.path.join(jd, 'run.yml')
            with open(wrapper, 'w') as f:
                f.write('\n'.join([
                    '- name: "safety net: arm"',
                    '  hosts: %s' % json.dumps(hosts_pat),
                    '  gather_facts: false',
                    '  become: true',
                    '  tasks:',
                    '    - mureev.confirmed.arm:',
                    '        id: %s' % json.dumps(job_id),
                    '        window: %d' % window,
                    '        paths: "{{ asm_snapshot[inventory_hostname].paths }}"',
                    '        services: "{{ asm_snapshot[inventory_hostname].services }}"',
                    '        firewall: "{{ asm_snapshot[inventory_hostname].firewall }}"',
                    '- import_playbook: %s' % json.dumps(path),
                    '- name: "safety net: confirm"',
                    '  hosts: %s' % json.dumps(hosts_pat),
                    '  gather_facts: false',
                    '  become: true',
                    '  tasks:',
                    '    - mureev.confirmed.confirm:',
                    '        id: %s' % json.dumps(job_id),
                    '        checks: %s' % yaml_val(checks),
                    '']))
            progress = os.path.join(jd, 'progress.log')
            cmd = [self.cfg.playbook_bin, wrapper, '-e', '@' + vf, '--limit', hosts_pat]
            proc = subprocess.Popen(cmd, cwd=self.cfg.project, env=ansible_env(self.cfg, progress),
                                    stdout=open(os.path.join(jd, 'stdout.log'), 'w'),
                                    stderr=open(os.path.join(jd, 'stderr.log'), 'w'),
                                    stdin=subprocess.DEVNULL, start_new_session=True)
            self._set(job_id, pid=proc.pid)
            self._finish(job_id, proc)
        except Exception as e:
            self._set(job_id, status='failed', error='%s: %s' % (type(e).__name__, e))

    def _kind_of(self, targets):
        hs = hosts_of(load_inventory(self.cfg))
        kinds = {hs[t].get('asm_kind', 'linux') for t in targets}
        if len(kinds) > 1:
            raise ToolError('one apply changes one kind of host; this one would touch %s. Use limit.' %
                            ' and '.join(sorted(kinds)))
        return kinds.pop()

    def _approve(self, rel, targets, h, params, window, plan_txt):
        if self.approvals.approved(h, rel, targets):
            return True, False, ''
        text = ('Run %s on %s\n\nversion %s%s\nIf the change can\'t be confirmed over a fresh connection it is undone '
                '(window %s).\n\n%s' % (rel, ', '.join(targets), h[:12],
                                         ('\nparams: ' + json.dumps(params)) if params else '', fmt_window(window),
                                         plan_txt[:1800]))
        ok, how = ask(self.cfg, 'Run %s on %s?' % (rel, ', '.join(targets)[:60]), text)
        if ok:
            self.approvals.add(h, rel, targets)
        return ok, True, how

    def _run_macos(self, job_id, path, vf, targets, checks, window, paths, services):
        """macOS: the collection's guard script (launchd backend) installed over SSH; no Python needed."""
        jd = os.path.join(self.cfg.jobs, job_id)
        progress = os.path.join(jd, 'progress.log')

        def note(msg):
            with open(progress, 'a') as f:
                f.write('%s %s\n' % (time.strftime('%H:%M:%S'), msg))
        D = '/var/db/ansible-confirmed'
        G = 'sudo -n env ANSIBLE_CONFIRMED_DIR=%s /bin/sh %s/guard.sh' % (D, D)
        guard_sh = collection_guard_sh(self.cfg)
        q = shlex.quote
        req = '%s/req.%s' % (D, job_id)
        arm_script = '\n'.join([
            'set -e', 'umask 077', 'mkdir -p %s && chmod 755 %s' % (D, D),
            "cat > %s/guard.sh <<'ASM_GUARD_EOF'" % D, guard_sh.rstrip('\n'), 'ASM_GUARD_EOF',
            'chmod 700 %s/guard.sh' % D, 'mkdir -p %s' % req,
            ': > %s/paths' % req] + ['printf "%%s\\n" %s >> %s/paths' % (q(p), req) for p in paths] + [
            ': > %s/services' % req] + ['printf "%%s\\n" %s >> %s/services' % (q(x), req) for x in services] + [
            'echo 0 > %s/firewall' % req,
            'ANSIBLE_CONFIRMED_DIR=%s /bin/sh %s/guard.sh arm %s %d %s' % (D, D, job_id, window, req)])
        results = {}
        hs = hosts_of(load_inventory(self.cfg))
        kh = self.cfg.known_hosts
        for host in targets:
            hv = hs[host]
            lu, cu = hv['asm_look_user'], hv['asm_change_user']
            lk, ck = hv.get('asm_look_key'), hv.get('asm_change_key')
            r = results[host] = {'outcome': 'unknown', 'changed': 0}
            rc, out = routeros.ssh_exec(hv, cu, kh, 'sudo -n /bin/sh -s', key=ck, timeout=90, stdin=arm_script + '\n')
            data = routeros_kv(out)
            if rc != 0 or data.get('state') != 'armed':
                r.update(outcome='not-armed', detail='the guard did not arm, so nothing was changed: %s' % (
                    data.get('error') or out.strip()[-300:]))
                note('%s: %s' % (host, r['detail']))
                continue
            r['deadline'] = data.get('deadline_iso')
            note('%s: guard armed (%s)' % (host, data.get('backend')))
            failed = None
            for name, c in routeros_commands(path):
                crc, cout = routeros.ssh_exec(hv, cu, kh, 'sudo -n /bin/sh -c %s' % q(c), key=ck,
                                              timeout=max(30, min(window, 600)))
                if crc != 0:
                    failed = '%s: exit %s%s' % (name or c[:60], crc, (': ' + cout.strip()[-400:]) if cout.strip() else '')
                    break
                r['changed'] += 1

            def guard_cmd(action):
                return routeros.ssh_exec(hv, cu, kh, '%s %s' % (G, action), key=ck, timeout=60)
            if failed:
                rc, out = guard_cmd('revert failed %s' % job_id)
                r.update(outcome='reverted-now' if routeros_kv(out).get('state') == 'reverted' else 'not-confirmed',
                         failed_task=failed.split(':', 1)[0], detail=failed)
            else:
                rc, fresh = routeros.ssh_exec(hv, lu, kh, 'true', key=lk, timeout=30)
                r['checks'] = [{'check': 'ssh', 'ok': rc == 0, 'detail': 'fresh login as %s' % lu if rc == 0
                                else fresh.strip()[-200:]}]
                bad = rc != 0
                for c in checks:
                    if c in ('ssh', 'ping') or bad:
                        continue
                    crc, cout = routeros.ssh_exec(hv, cu, kh, c, key=ck, timeout=60)
                    r['checks'].append({'check': c, 'ok': crc == 0, 'detail': cout.strip()[-200:]})
                    bad = bad or crc != 0
                if bad:
                    rc, out = guard_cmd('revert check-failed %s' % job_id)
                    ok = routeros_kv(out).get('state') == 'reverted'
                    r.update(outcome='reverted-now' if ok else 'not-confirmed',
                             detail='a check failed after the change' + ('' if ok else '; launchd reverts at the '
                                                                                         'deadline'))
                else:
                    rc, out = guard_cmd('confirm %s' % job_id)
                    if routeros_kv(out).get('state') == 'confirmed':
                        r['outcome'] = 'confirmed'
                    else:
                        r.update(outcome='not-confirmed', detail='could not confirm: %s' % out.strip()[-200:])
            note('%s: %s' % (host, r['outcome']))
        job = self._load_job(job_id)
        job.update(status='done', finished=time.time(), results=results)
        self._save_job(job)
        self.audit.write('job', summary='%s %s' % (job_id, ', '.join('%s=%s' % (h, r['outcome'])
                                                                    for h, r in sorted(results.items()))))

    def _run_windows(self, job_id, path, targets, checks, window, paths):
        """Windows: a snapshot of the listed paths and a one-time SYSTEM scheduled task that restores it."""
        jd = os.path.join(self.cfg.jobs, job_id)
        progress = os.path.join(jd, 'progress.log')

        def note(msg):
            with open(progress, 'a') as f:
                f.write('%s %s\n' % (time.strftime('%H:%M:%S'), msg))
        cmds = routeros_commands(path)
        regs = [p for p in paths if re.match(r'^(HKLM|HKCU|HKCR|HKU|HKCC):?\\', p)]
        look_regs = '; '.join("& reg.exe query %s /s 2>$null" % windows.ps_quote(re.sub(r'^(\w+):', r'\1', p))
                              for p in regs) or "''"
        results = {}
        hs = hosts_of(load_inventory(self.cfg))
        kh = self.cfg.known_hosts
        paths_b64 = windows.b64(json.dumps(paths))
        for host in targets:
            hv = hs[host]
            lu, cu = hv['asm_look_user'], hv['asm_change_user']
            lk, ck = hv.get('asm_look_key'), hv.get('asm_change_key')
            r = results[host] = {'outcome': 'unknown', 'changed': 0}

            def ex(script, user=cu, key=ck, timeout=180):
                return windows.win_exec(hv, user, kh, script, key=key, timeout=timeout)
            rc, before = ex(look_regs, lu, lk, 60)
            rc, out = ex(windows.install_guard_script())
            if rc != 0:
                r.update(outcome='not-armed', detail='could not install the guard: %s' % out[-300:])
                continue
            rc, out = ex(windows.guard_call('arm', Id=job_id, Seconds=window, PathsB64=paths_b64))
            data = routeros_kv(out)
            if rc != 0 or data.get('state') != 'armed':
                r.update(outcome='not-armed', detail='the guard did not arm, so nothing was changed: %s' % (
                    data.get('error') or out.strip()[-300:]))
                note('%s: %s' % (host, r['detail']))
                continue
            r['deadline'] = data.get('deadline_iso')
            note('%s: guard armed (scheduled task until %s)' % (host, r['deadline']))
            failed = None
            for name, c in cmds:
                crc, cout = ex("$ErrorActionPreference = 'Stop'\n" + c, timeout=max(30, min(window, 600)))
                if crc != 0:
                    failed = '%s: exit %s%s' % (name or c[:60], crc, (': ' + cout.strip()[-400:]) if cout.strip() else '')
                    break
                r['changed'] += 1
            if failed:
                rc, out = ex(windows.guard_call('revert', Why='failed'))
                r.update(outcome='reverted-now' if routeros_kv(out).get('state') == 'reverted' else 'not-confirmed',
                         failed_task=failed.split(':', 1)[0], detail=failed)
            else:
                rc, fresh = ex('whoami', lu, lk, 60)
                r['checks'] = [{'check': 'ssh', 'ok': rc == 0, 'detail': 'fresh login as %s' % lu if rc == 0
                                else fresh.strip()[-200:]}]
                bad = rc != 0
                for c in checks:
                    if c in ('ssh', 'ping') or bad:
                        continue
                    crc, cout = ex("$ErrorActionPreference = 'Stop'\n" + c, timeout=120)
                    r['checks'].append({'check': c, 'ok': crc == 0, 'detail': cout.strip()[-200:]})
                    bad = bad or crc != 0
                if bad:
                    rc, out = ex(windows.guard_call('revert', Why='check-failed'))
                    ok = routeros_kv(out).get('state') == 'reverted'
                    r.update(outcome='reverted-now' if ok else 'not-confirmed',
                             detail='a check failed after the change' + ('' if ok else '; the scheduled task reverts '
                                                                                         'at the deadline'))
                else:
                    rc, out = ex(windows.guard_call('confirm', Id=job_id))
                    if routeros_kv(out).get('state') == 'confirmed':
                        r['outcome'] = 'confirmed'
                    else:
                        r.update(outcome='not-confirmed', detail='could not confirm: %s' % out.strip()[-200:])
            note('%s: %s' % (host, r['outcome']))
            if regs:
                rc, after = ex(look_regs, lu, lk, 60)
                import difflib as _d
                diff = list(_d.unified_diff(before.splitlines(), after.splitlines(), 'before', 'after', lineterm='', n=0))
                r['export_diff'] = '\n'.join(diff[:80]) if diff else '(no difference)'
        job = self._load_job(job_id)
        job.update(status='done', finished=time.time(), results=results)
        self._save_job(job)
        self.audit.write('job', summary='%s %s' % (job_id, ', '.join('%s=%s' % (h, r['outcome'])
                                                                    for h, r in sorted(results.items()))))

    def _run_openwrt(self, job_id, path, vf, targets, checks, window):
        """OpenWrt: the guard is a snapshot + timer on the device (openwrt_guard.sh, sent at arm time)."""
        jd = os.path.join(self.cfg.jobs, job_id)
        progress = os.path.join(jd, 'progress.log')

        def note(msg):
            with open(progress, 'a') as f:
                f.write('%s %s\n' % (time.strftime('%H:%M:%S'), msg))
        with open(OPENWRT_GUARD) as f:
            guard = f.read()
        G = 'sh /tmp/asm-guard/guard.sh'
        results = {}
        hs = hosts_of(load_inventory(self.cfg))
        kh = self.cfg.known_hosts
        for host in targets:
            hv = hs[host]
            lu, cu = hv['asm_look_user'], hv['asm_change_user']
            lk, ck = hv.get('asm_look_key'), hv.get('asm_change_key')
            r = results[host] = {'outcome': 'unknown', 'changed': 0}
            rc, before = routeros.ssh_exec(hv, lu, kh, 'uci show 2>/dev/null | sort', key=lk, timeout=60)
            before = before if rc == 0 else None
            rc, out = routeros.ssh_exec(hv, cu, kh, 'mkdir -p "$R/tmp/asm-guard" && cat > "$R/tmp/asm-guard/guard.sh" '
                                                    '&& %s arm %d' % (G.replace('/tmp', '"$R"/tmp'), window),
                                        key=ck, timeout=60, stdin=guard)
            if rc != 0 or 'armed:' not in out:
                r.update(outcome='not-armed', detail='the guard did not arm, so nothing was changed: %s' %
                         out.strip()[-300:])
                note('%s: %s' % (host, r['detail']))
                continue
            r['deadline'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() + window))
            note('%s: guard armed' % host)
            doc, err, prc = run_playbook(self.cfg, path, vf, limit=host, timeout=window)
            failed = None
            for task in (doc or {}).get('tasks', []):
                e = task.get('hosts', {}).get(host)
                if not e:
                    continue
                if e.get('status') == 'changed' or (task['action'].endswith('raw') and e.get('status') == 'ok'):
                    r['changed'] += 1
                if e.get('status') in ('failed', 'unreachable'):
                    out = ((e.get('stdout') or '') + (e.get('stderr') or '')).strip() or (e.get('msg') or '').strip()
                    out = re.sub(r'Shared connection to \S+ closed\.?', '', out).strip()
                    rc = e.get('rc')
                    failed = '%s: %s' % (task['name'], ('exit %s%s' % (rc, (': ' + out[:400]) if out else ''))
                                         if rc not in (None, 0) else str(e.get('msg') or out).strip()[:400])
                    break
            if doc is None and not failed:
                failed = 'ansible did not finish: %s' % err[-400:]
            gx = G.replace('/tmp', '"$R"/tmp')

            def guard_cmd(action):
                return routeros.ssh_exec(hv, cu, kh, '%s %s' % (gx, action), key=ck, timeout=60)
            if failed:
                rc, out = guard_cmd('revert failed')
                r.update(outcome='reverted-now' if 'reverted' in out else 'not-confirmed',
                         failed_task=failed.split(':', 1)[0], detail=failed)
            else:
                rc, fresh = routeros.ssh_exec(hv, lu, kh, 'true', key=lk, timeout=30)
                r['checks'] = [{'check': 'ssh', 'ok': rc == 0, 'detail': 'fresh login as %s' % lu if rc == 0
                                else fresh.strip()[-200:]}]
                bad = rc != 0
                for c in checks:
                    if c in ('ssh', 'ping') or bad:
                        continue
                    crc, cout = routeros.ssh_exec(hv, cu, kh, c, key=ck, timeout=60)
                    r['checks'].append({'check': c, 'ok': crc == 0, 'detail': cout.strip()[-200:]})
                    bad = bad or crc != 0
                if bad:
                    rc, out = guard_cmd('revert check-failed')
                    if 'reverted' in out:
                        r.update(outcome='reverted-now', detail='a check failed after the change')
                    else:
                        r.update(outcome='not-confirmed', detail='a check failed and the device could not be reached '
                                                                 'to revert now; it reverts at its deadline')
                else:
                    rc, out = guard_cmd('cancel')
                    if 'cancelled' in out:
                        r['outcome'] = 'confirmed'
                    else:
                        r.update(outcome='not-confirmed', detail='could not cancel the guard: %s' % out.strip()[-200:])
            note('%s: %s' % (host, r['outcome']))
            if before is not None:
                time.sleep(2 if r['outcome'] == 'reverted-now' else 0)
                rc, after = routeros.ssh_exec(hv, lu, kh, 'uci show 2>/dev/null | sort', key=lk, timeout=60)
                if rc == 0:
                    import difflib as _d
                    diff = list(_d.unified_diff(before.splitlines(), after.splitlines(), 'before', 'after',
                                                lineterm='', n=0))
                    r['export_diff'] = '\n'.join(diff[:80]) if diff else '(no difference)'
        job = self._load_job(job_id)
        job.update(status='done', finished=time.time(), results=results)
        self._save_job(job)
        self.audit.write('job', summary='%s %s' % (job_id, ', '.join('%s=%s' % (h, r['outcome'])
                                                                    for h, r in sorted(results.items()))))

    def _run_routeros(self, job_id, path, vf, targets, checks, window):
        jd = os.path.join(self.cfg.jobs, job_id)
        progress = os.path.join(jd, 'progress.log')

        def note(msg):
            with open(progress, 'a') as f:
                f.write('%s %s\n' % (time.strftime('%H:%M:%S'), msg))
        results = {}
        hs = hosts_of(load_inventory(self.cfg))
        kh = self.cfg.known_hosts
        for host in targets:
            hv = hs[host]
            lu, cu = hv['asm_look_user'], hv['asm_change_user']
            lk, ck = hv.get('asm_look_key'), hv.get('asm_change_key')
            r = results[host] = {'outcome': 'unknown', 'changed': 0}
            ok, before = routeros.run_command(hv, lu, kh, '/export terse', key=lk, timeout=120)
            before = routeros.normalize_export(before) if ok else None
            note('%s: export before %s' % (host, 'ok' if ok else 'FAILED'))
            sess = routeros.SafeModeSession(routeros.ssh_base(hv, cu, kh, ck, tty=True))
            try:
                sess.open()
            except Exception as e:
                r.update(outcome='not-armed', detail='could not enter Safe Mode, so nothing was changed: %s' % e)
                note('%s: %s' % (host, r['detail']))
                continue
            note('%s: Safe Mode held' % host)
            deadline = time.time() + window
            r['deadline'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(deadline))
            stop = threading.Event()

            def watchdog(sess=sess, stop=stop, host=host):
                while not stop.wait(1):
                    if time.time() >= deadline and sess.state == 'safe':
                        note('%s: window over: Ctrl+D' % host)
                        sess.revert()
                        return
            threading.Thread(target=watchdog, daemon=True).start()
            doc, err, rc = run_playbook(self.cfg, path, vf, limit=host, timeout=window)
            failed = None
            for task in (doc or {}).get('tasks', []):
                e = task.get('hosts', {}).get(host)
                if not e:
                    continue
                if e.get('status') == 'changed' or (task['action'].endswith('raw') and e.get('status') == 'ok'):
                    r['changed'] += 1
                out = (e.get('stdout') or '') + (e.get('stderr') or '')
                if e.get('status') in ('failed', 'unreachable') or routeros.ERROR.search(out):
                    failed = '%s: %s' % (task['name'], (e.get('msg') or routeros.ANSI.sub('', out)).strip()[:400])
                    break
            if doc is None and not failed:
                failed = 'ansible did not finish: %s' % err[-400:]
            try:
                in_safe = sess.probe()
            except Exception:
                in_safe = False
            if sess.state == 'reverted':
                r.update(outcome='reverted-now', detail='the window ran out before the change finished')
            elif not in_safe and sess.exited:
                r.update(outcome='lost', detail='the Safe Mode session dropped: the router undoes the change by '
                                                'itself (at once, or after its TCP timeout of up to ~9 minutes)')
            elif not in_safe:
                r.update(outcome='unprotected', detail='the router left Safe Mode by itself (its history holds 100 '
                                                       'actions): the change is applied and was NOT protected')
                sess.kill()
            elif failed:
                sess.revert()
                r.update(outcome='reverted-now', failed_task=failed.split(':', 1)[0],
                         detail=failed + ' — undone (Ctrl+D)')
            else:
                fresh_ok, fresh = routeros.run_command(hv, lu, kh, '/system identity print', key=lk, timeout=30)
                r['checks'] = [{'check': 'ssh', 'ok': fresh_ok, 'detail': 'fresh login as %s' % lu if fresh_ok
                                else fresh.strip()[-200:]}]
                bad = not fresh_ok
                for c in checks:
                    if c in ('ssh', 'ping') or bad:
                        continue
                    cok, cout = routeros.run_command(hv, cu, kh, c, key=ck, timeout=60)
                    r['checks'].append({'check': c, 'ok': cok, 'detail': cout.strip()[-200:]})
                    bad = bad or not cok
                if bad:
                    sess.revert()
                    r.update(outcome='reverted-now', detail='a check failed after the change — undone (Ctrl+D)')
                else:
                    released = sess.commit()
                    r.update(outcome='confirmed', released=released)
            stop.set()
            note('%s: %s' % (host, r['outcome']))
            if before is not None:
                # an undo takes the router a moment: after a revert, wait (up to ~12 s) until the export settles
                for attempt in range(7 if r['outcome'] in ('reverted-now', 'lost') else 1):
                    if attempt:
                        time.sleep(2)
                    ok, after = routeros.run_command(hv, lu, kh, '/export terse', key=lk, timeout=120)
                    if not ok or routeros.normalize_export(after) == before:
                        break
                if ok and r['outcome'] in ('reverted-now', 'lost') and routeros.normalize_export(after) == before:
                    r['export_diff'] = '(identical to before: the router is back where it was)'
                elif ok:
                    import difflib as _d
                    diff = list(_d.unified_diff(before.splitlines(), routeros.normalize_export(after).splitlines(),
                                                'before', 'after', lineterm='', n=0))
                    r['export_diff'] = '\n'.join(diff[:80]) if diff else '(no difference)'
        job = self._load_job(job_id)
        job.update(status='done', finished=time.time(), results=results)
        self._save_job(job)
        self.audit.write('job', summary='%s %s' % (job_id, ', '.join('%s=%s' % (h, r['outcome'])
                                                                    for h, r in sorted(results.items()))))

    def _save_job(self, job):
        jd = os.path.join(self.cfg.jobs, job['id'])
        with self.jobs_lock:
            tmp = os.path.join(jd, 'job.json.new')
            with open(tmp, 'w') as f:
                json.dump(job, f, indent=1, default=str)
            os.replace(tmp, os.path.join(jd, 'job.json'))

    def _load_job(self, job_id):
        if not re.match(r'^[0-9a-f]{8,16}$', job_id or ''):
            raise ToolError('no such job')
        try:
            with open(os.path.join(self.cfg.jobs, job_id, 'job.json')) as f:
                return json.load(f)
        except (OSError, ValueError):
            raise ToolError('no such job: %s' % job_id)

    def _finish(self, job_id, proc):
        proc.wait()
        jd = os.path.join(self.cfg.jobs, job_id)
        job = self._load_job(job_id)
        with open(os.path.join(jd, 'stdout.log')) as f:
            doc = parse_json_output(f.read())
        results = {}
        for t in job['targets']:
            results[t] = {'outcome': 'unknown', 'changed': 0}
        failed_mid = []
        for task in (doc or {}).get('tasks', []):
            for h, e in task.get('hosts', {}).items():
                r = results.setdefault(h, {'outcome': 'unknown', 'changed': 0})
                act = task['action']
                if act.endswith('confirmed.arm'):
                    if e.get('status') in ('changed', 'ok'):
                        r['outcome'] = 'armed'
                        r['deadline'] = e.get('deadline_iso')
                    else:
                        r['outcome'] = 'not-armed'
                        r['detail'] = e.get('msg')
                elif act.endswith('confirmed.confirm'):
                    if e.get('status') in ('changed', 'ok') and e.get('confirmed', True):
                        r['outcome'] = 'confirmed'
                        r['checks'] = e.get('checks')
                    else:
                        msg = str(e.get('msg', ''))
                        r['outcome'] = ('reverted-now' if e.get('reverted') else
                                        'reverted-by-host' if 'already reverted' in msg else 'not-confirmed')
                        r['detail'] = msg
                        r['checks'] = e.get('checks')
                else:
                    if e.get('status') == 'changed':
                        r['changed'] += 1
                    elif e.get('status') == 'failed':
                        r['failed_task'] = task['name']
                        r['detail'] = str(e.get('msg', ''))[:500]
                    elif e.get('status') == 'unreachable':
                        r['unreachable_at'] = task['name']
                        r['detail'] = str(e.get('msg', ''))[:300]
        for h, r in results.items():
            if r['outcome'] == 'armed':
                if r.get('failed_task'):
                    failed_mid.append(h)
                else:
                    r['outcome'] = 'not-confirmed'
        if failed_mid:
            # the change failed partway on a reachable host: put it back now instead of waiting for the deadline
            d = scratch(self.cfg, 'revert')
            pb = os.path.join(d, 'revert.yml')
            with open(pb, 'w') as f:
                f.write('- hosts: %s\n  gather_facts: false\n  become: true\n  tasks:\n'
                        '    - mureev.confirmed.revert:\n        id: %s\n        why: "apply failed"\n' % (
                            json.dumps(':'.join(failed_mid)), json.dumps(job_id)))
            vf = os.path.join(d, 'vars.yml')
            write_vars(vf, 'change')
            rdoc, err, rc = run_playbook(self.cfg, pb, vf, timeout=120)
            shutil.rmtree(d, ignore_errors=True)
            for h in failed_mid:
                e = ((rdoc or {}).get('tasks') or [{}])[-1].get('hosts', {}).get(h, {}) if rdoc else {}
                results[h]['outcome'] = 'reverted-now' if e.get('state') == 'reverted' else 'not-confirmed'
        job['status'] = 'done'
        job['rc'] = proc.returncode
        job['finished'] = time.time()
        job['results'] = results
        if doc is None:
            with open(os.path.join(jd, 'stderr.log')) as f:
                job['error'] = f.read()[-3000:]
        self._save_job(job)
        self.audit.write('job', summary='%s %s' % (job_id, ', '.join('%s=%s' % (h, r['outcome'])
                                                                    for h, r in sorted(results.items()))))

    def _job_text(self, job_id):
        job = self._load_job(job_id)
        jd = os.path.join(self.cfg.jobs, job_id)
        v = job.get('version', '')[:12]
        st = job['status']
        if st == 'planning':
            return 'Job %s: planning %s on %s. Follow it with job(id="%s", wait_s=50).' % (
                job_id, job['playbook'], ', '.join(job['targets']), job_id)
        if st == 'awaiting-approval':
            return ('Job %s: waiting for the user to approve %s (version %s) in the dialog on the Mac; it waits up '
                    'to 5 minutes. Tell the user, then follow with job(id="%s", wait_s=50).\n\n%s' % (
                        job_id, job['playbook'], v, job_id, job.get('plan', '')))
        if st == 'declined':
            return 'Job %s: not run: the user declined %s (version %s; %s). Nothing changed.' % (
                job_id, job['playbook'], v, job.get('error', ''))
        if st == 'failed':
            return 'Job %s: %s did not run. %s' % (job_id, job['playbook'], job.get('error', ''))
        head = ('Approved by the user (version %s). ' % v) if job.get('asked') else (
            'Version %s was approved before: ran without asking. ' % v)
        lines = [head + 'Job %s: %s on %s, window %s.' % (job_id, job['playbook'], ', '.join(job['targets']),
                                                           fmt_window(job['window']))]
        if job['status'] != 'done':
            try:
                with open(os.path.join(jd, 'progress.log')) as f:
                    prog = f.read().splitlines()[-12:]
            except OSError:
                prog = []
            lines.append('Still running. Latest:')
            lines.extend('  ' + x for x in prog)
            lines.append('Follow it with job(id="%s").' % job_id)
            return '\n'.join(lines)
        words = {
            'confirmed': 'CONFIRMED: changed, checked over a fresh connection, kept',
            'not-confirmed': 'NOT CONFIRMED: the host will undo the change by itself',
            'reverted-now': 'REVERTED: the change failed or a check failed, and the host was put back now',
            'reverted-by-host': 'REVERTED BY THE HOST: the window ran out before the change was confirmed',
            'not-armed': 'NOT ARMED: nothing was changed',
            'lost': 'SESSION LOST: the router undoes the change by itself',
            'unprotected': 'APPLIED, NOT PROTECTED: the router left Safe Mode on its own',
            'unknown': 'UNKNOWN: see the log',
        }
        for h, r in sorted(job.get('results', {}).items()):
            s = '%s: %s' % (h, words.get(r['outcome'], r['outcome']))
            if r.get('changed'):
                s += ' (%d task%s changed)' % (r['changed'], '' if r['changed'] == 1 else 's')
            if r['outcome'] == 'not-confirmed' and r.get('deadline'):
                s += ' at %s' % r['deadline']
            if r.get('failed_task'):
                s += '\n    failed at "%s": %s' % (r['failed_task'], r.get('detail', ''))
            elif r.get('detail'):
                s += '\n    %s' % str(r['detail'])[:500]
            for c in r.get('checks') or []:
                s += '\n    check %s: %s' % (c.get('check'), 'ok' if c.get('ok') else 'FAILED (%s)' % c.get('detail'))
            if r.get('export_diff'):
                s += '\n    config now vs before:\n' + '\n'.join('      ' + x for x in r['export_diff'].splitlines())
            lines.append(s)
        if job.get('error'):
            lines.append('Ansible error:\n' + job['error'][-1500:])
        return '\n'.join(lines)

    # ---- tool: hands
    def t_hands(self, a):
        """A one-off change: the steps become a playbook in oneoffs/, then run like apply (asks, guarded)."""
        pattern = a.get('hosts', '')
        if not PATTERN_RE.match(pattern or '') or re.search(r'localhost|127\.|::1', pattern):
            raise ToolError('hosts: a host, group or pattern from the inventory')
        steps = a.get('steps') or []
        if not isinstance(steps, list) or not steps or not all(isinstance(x, str) and 0 < len(x) <= 4000
                                                               for x in steps):
            raise ToolError('steps: a list of shell commands (RouterOS commands for routers), one per step')
        if len(steps) > 40:
            raise ToolError('at most 40 steps in a one-off; write a playbook for more')
        why = str(a.get('why') or '').strip()
        if not why:
            raise ToolError('why: one line saying what this fixes (it becomes the playbook name and the commit)')
        hs = hosts_of(load_inventory(self.cfg))
        kinds = {v.get('asm_kind', 'linux') for v in hs.values()}
        slug = re.sub(r'[^a-z0-9]+', '-', why.lower()).strip('-')[:40] or 'oneoff'
        rel = 'oneoffs/%s-%s.yml' % (time.strftime('%Y%m%d-%H%M'), slug)
        routeros_task = a.get('kind') == 'routeros' or (kinds == {'routeros'})
        mod = 'ansible.builtin.raw' if routeros_task else 'ansible.builtin.shell'
        body = ['# One-off (hands): %s' % why.replace('\n', ' '), '- name: %s' % json.dumps(why[:120]),
                '  hosts: %s' % json.dumps(pattern), '  gather_facts: false']
        if not routeros_task:
            body.append('  become: true')
        body.append('  tasks:')
        for i, step in enumerate(steps, 1):
            body += ['    - name: %s' % json.dumps('step %d: %s' % (i, step.splitlines()[0][:80])),
                     '      %s: %s' % (mod, unsafe_cmd(step))]
        path = os.path.join(self.cfg.project, rel)
        with open(path, 'w') as f:
            f.write('\n'.join(body) + '\n')
        self._commit('one-off %s' % rel)
        if not routeros_task and not a.get('paths'):
            return ('Wrote %s, but did not run it: shell steps are invisible to the plan, so tell me what they '
                    'touch: paths=[...] (files and folders they create, change or delete; they are snapshotted and '
                    'put back on a revert) and services=[...] to restart. Then call hands again or apply %s.' %
                    (rel, rel))
        return self.t_apply({'playbook': rel, 'window': a.get('window', '10m'), 'checks': a.get('checks'),
                             'paths': a.get('paths'), 'services': a.get('services'), 'wait_s': a.get('wait_s', 60)})

    # ---- tool: job
    def t_job(self, a):
        job_id = a.get('id', '')
        action = a.get('action', 'status')
        if action == 'list' or not job_id:
            rows = []
            for jid in sorted(os.listdir(self.cfg.jobs), reverse=True)[:15]:
                try:
                    j = self._load_job(jid)
                except ToolError:
                    continue
                res = j.get('results') or {}
                rows.append('%s  %s  %s  %s' % (jid, j['playbook'], j['status'],
                                                ', '.join('%s=%s' % (h, r['outcome']) for h, r in sorted(res.items()))))
            return '\n'.join(rows) or 'No jobs yet.'
        job = self._load_job(job_id)
        if action == 'status':
            wait = max(0, min(int(a.get('wait_s', 0)), 110))
            end = time.time() + wait
            while job['status'] in ('planning', 'awaiting-approval', 'running') and time.time() < end:
                time.sleep(1)
                job = self._load_job(job_id)
            return self._job_text(job_id)
        if action in ('extend', 'revert'):
            if job.get('kind') in SERVER_GUARDED:
                raise ToolError('RouterOS changes are confirmed or undone within the apply itself (Safe Mode); there is '
                                'no open window to extend or revert afterwards.')
            if action == 'extend':
                try:
                    secs = parse_window(a.get('window', '10m'))
                except ValueError as e:
                    raise ToolError(str(e))
                task = '    - mureev.confirmed.extend:\n        window: %d\n' % secs
            else:
                task = ('    - mureev.confirmed.revert:\n        id: %s\n        why: "reverted on request"\n' %
                        json.dumps(job_id))
            hosts = [h for h, r in (job.get('results') or {h: {} for h in job['targets']}).items()
                     if r.get('outcome') in (None, 'armed', 'not-confirmed', 'unknown')] or job['targets']
            d = scratch(self.cfg, action)
            pb = os.path.join(d, 'x.yml')
            with open(pb, 'w') as f:
                f.write('- hosts: %s\n  gather_facts: false\n  become: true\n  tasks:\n%s' % (
                    json.dumps(':'.join(hosts)), task))
            vf = os.path.join(d, 'vars.yml')
            write_vars(vf, 'change')
            doc, err, rc = run_playbook(self.cfg, pb, vf, timeout=120)
            shutil.rmtree(d, ignore_errors=True)
            self.audit.write('job', summary='%s %s on %s' % (action, job_id, ','.join(hosts)))
            if doc is None:
                raise ToolError(err[-1500:])
            out = []
            for h, e in ((doc.get('tasks') or [{}])[-1].get('hosts') or {}).items():
                out.append('%s: %s' % (h, e.get('msg') or e.get('state') or e.get('deadline_iso') or e.get('status')))
            return '\n'.join(out)
        raise ToolError('action must be status, list, extend or revert')

    # ---- tool: status
    def t_backup(self, a):
        """Pull a copy of config and files from hosts into the state folder (never the project repo). Reads only."""
        pattern = a.get('hosts', '')
        if not PATTERN_RE.match(pattern or '') or re.search(r'localhost|127\.|::1', pattern):
            raise ToolError('hosts: a host name, group or Ansible pattern from the inventory (not localhost)')
        check_inventory(self.cfg)
        hs = hosts_of(load_inventory(self.cfg))
        targets = [h for h in sorted(self._resolve(pattern)) if hs.get(h, {}).get('asm_kind', 'linux') != 'jump']
        if not targets:
            return 'No hosts matched %r.' % pattern
        label = a.get('label') or ''
        if label and not re.match(r'^[A-Za-z0-9_.-]{1,40}$', label):
            raise ToolError('label: letters, digits, dot, dash or underscore, up to 40')
        paths = a.get('paths') or []
        if not isinstance(paths, list) or len(paths) > 50 or not all(isinstance(p, str) for p in paths):
            raise ToolError('paths: a list of up to 50 absolute paths')
        for p in paths:
            win = re.match(r'^(HKLM|HKCU|HKCR|HKU|HKCC):?\\', p) or re.match(r'^[A-Za-z]:\\', p)
            if not (p.startswith('/') or win) or re.search(r'(^|[\\/])\.\.([\\/]|$)', p) or \
                    re.search(r'[\x00-\x1f]', p) or len(p) > 1000:
                raise ToolError('paths: absolute paths only (/etc/x, C:\\x or HKLM:\\x), no "..": %r' % p)
        kinds = {h: hs[h].get('asm_kind', 'linux') for h in targets}
        need = [h for h in targets if kinds[h] in ('linux', 'macos', 'windows')]
        if need and not paths:
            raise ToolError('paths=[...] is needed for %s (Linux, macOS and Windows hosts back up the paths you '
                            'list; routers back up their whole config)' % ', '.join(need))
        root = os.path.join(self.cfg.state, 'backups')
        os.makedirs(root, mode=0o700, exist_ok=True)
        os.chmod(root, 0o700)
        stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + ('-' + label if label else '')
        kh = self.cfg.known_hosts
        q = shlex.quote
        out = []
        for h in targets:
            hv, kind = hs[h], kinds[h]
            lu, cu = hv['asm_look_user'], hv['asm_change_user']
            lk, ck = hv.get('asm_look_key'), hv.get('asm_change_key')
            files, errors = [], []
            if kind == 'routeros':
                ok, txt = routeros.run_command(hv, lu, kh, '/export terse', key=lk, timeout=180)
                if ok and txt.strip():
                    files.append(('export.rsc', txt.encode('utf-8'), True))
                else:
                    errors.append('/export terse failed: %s' % txt.strip()[-300:])
            elif kind == 'openwrt':
                tmp = '/tmp/asm-backup.tar.gz'
                rc, data, err = routeros.ssh_exec_bytes(
                    hv, cu, kh, 'sysupgrade -b %s >/dev/null 2>&1 && cat %s; rc=$?; rm -f %s; exit $rc' % (tmp, tmp, tmp),
                    key=ck)
                if rc == 0 and data:
                    files.append(('sysupgrade.tar.gz', data, False))
                else:
                    errors.append('sysupgrade -b: exit %s %s' % (rc, err.strip()[-300:]))
                rc, data, err = routeros.ssh_exec_bytes(hv, cu, kh, 'uci export', key=ck)
                if rc == 0 and data.strip():
                    files.append(('uci-export.txt', data, True))
                else:
                    errors.append('uci export: exit %s %s' % (rc, err.strip()[-300:]))
            elif kind in ('linux', 'macos') and not [p for p in paths if p.startswith('/')]:
                errors.append('no POSIX paths (/...) given for this host')
            elif kind in ('linux', 'macos'):
                rc, data, err = routeros.ssh_exec_bytes(
                    hv, cu, kh, 'sudo -n tar -czf - -- %s' % ' '.join(q(p) for p in paths if p.startswith('/')),
                    key=ck)
                if rc == 0 and data:
                    files.append(('files.tar.gz', data, False))
                else:
                    errors.append('tar: exit %s %s' % (rc, err.strip()[-300:]))
            elif kind == 'windows' and not [p for p in paths if not p.startswith('/')]:
                errors.append('no Windows paths (C:\\... or HKLM:\\...) given for this host')
            elif kind == 'windows':
                lst = windows.b64(json.dumps([p for p in paths if not p.startswith('/')]))
                script = r"""$ErrorActionPreference = 'Stop'
$t = Join-Path $env:TEMP ('asm-backup-' + [guid]::NewGuid().ToString('N'))
$d = Join-Path $t 'backup'
New-Item -ItemType Directory -Path $d | Out-Null
try {
  $paths = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s')) | ConvertFrom-Json
  $i = 0
  foreach ($p in $paths) {
    $i++
    if ($p -match '^(HKLM|HKCU|HKCR|HKU|HKCC):?\\') {
      $k = $p -replace '^(\w+):', '$1'
      $out = & reg.exe export $k (Join-Path $d ('%%02d.reg' -f $i)) /y 2>&1
      if ($LASTEXITCODE -ne 0) { throw ('reg export ' + $p + ': ' + ($out -join ' ')) }
    } else {
      Copy-Item -LiteralPath $p -Destination (Join-Path $d ('%%02d-' -f $i) + (Split-Path $p -Leaf)) -Recurse
    }
  }
  $z = Join-Path $t 'backup.zip'
  Compress-Archive -Path (Join-Path $d '*') -DestinationPath $z
  'ASMB64:' + [Convert]::ToBase64String([IO.File]::ReadAllBytes($z))
} finally { Remove-Item -LiteralPath $t -Recurse -Force -ErrorAction SilentlyContinue }
""" % lst
                rc, txt = windows.win_exec(hv, cu, kh, script, key=ck, timeout=300)
                m = re.search(r'ASMB64:([A-Za-z0-9+/=]+)', txt.replace('\n', ''))
                if rc == 0 and m:
                    import base64 as _b64
                    files.append(('backup.zip', _b64.b64decode(m.group(1)), False))
                else:
                    errors.append('exit %s %s' % (rc, txt.strip()[-300:]))
            else:
                errors.append('no backup for kind %s' % kind)
            lines = ['== %s' % h]
            if files:
                d = os.path.join(root, h, stamp)
                os.makedirs(d, mode=0o700, exist_ok=True)
                for x in (os.path.join(root, h), d):
                    os.chmod(x, 0o700)
                for name, data, text in files:
                    fp = os.path.join(d, name)
                    fd = os.open(fp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                    with os.fdopen(fd, 'wb') as f:
                        f.write(data)
                    os.chmod(fp, 0o600)
                    digest = hashlib.sha256(data).hexdigest()
                    extra = ', %d lines' % data.decode('utf-8', 'replace').count('\n') if text else ''
                    lines.append('saved %s (%d bytes%s, sha256 %s)' % (fp, len(data), extra, digest[:16]))
                    self.audit.write('backup', summary='%s %s %d bytes sha256 %s' % (h, name, len(data), digest))
            for e in errors:
                lines.append('FAILED: ' + e)
                self.audit.write('backup', summary='%s failed: %s' % (h, e[:200]))
            out.append('\n'.join(lines))
        return '\n\n'.join(out)

    def t_status(self, a):
        lines = ['ansible-safe-mcp %s' % VERSION, 'project: %s' % self.cfg.project,
                 'hosts: %d, approved playbook versions: %d' % (len(hosts_of(load_inventory(self.cfg))),
                                                                self.approvals.count())]
        findings = lint.lint_tree(self.cfg.project, ('playbooks', 'roles', 'oneoffs'))
        lines.append('lint: clean' if not findings else 'lint REFUSES %d thing(s):\n%s' % (
            len(findings), lint.format_findings(findings, 10)))
        running = []
        for jid in sorted(os.listdir(self.cfg.jobs), reverse=True)[:30]:
            try:
                j = self._load_job(jid)
            except ToolError:
                continue
            if j['status'] != 'done':
                running.append('%s %s on %s' % (jid, j['playbook'], ','.join(j['targets'])))
        lines.append('running jobs: ' + ('; '.join(running) if running else 'none'))
        broot = os.path.join(self.cfg.state, 'backups')
        if os.path.isdir(broot):
            sets = [(h, s) for h in sorted(os.listdir(broot)) for s in sorted(os.listdir(os.path.join(broot, h)))]
            if sets:
                lines.append('backups: %d in %s (latest %s %s)' % (len(sets), broot, *max(sets, key=lambda x: x[1])))
        if a.get('hosts'):
            lines.append('\nSafety net on the hosts:\n' + self.t_look({'hosts': a['hosts'], 'read': 'guard'}))
        lines.append('\nRecent activity:')
        lines.extend('  ' + x for x in self.audit.tail(10))
        return '\n'.join(lines)


def parse_window(v):
    m = re.match(r'^\s*(\d+)\s*([smh]?)\s*$', str(v))
    if not m:
        raise ValueError('window: 600, 90s, 10m or 1h')
    secs = int(m.group(1)) * {'': 1, 's': 1, 'm': 60, 'h': 3600}[m.group(2)]
    if not 30 <= secs <= 86400 and not os.environ.get('ASM_TEST_SHORT_WINDOWS'):
        raise ValueError('window: between 30s and 24h')
    return secs


def fmt_window(s):
    return '%dm' % (s // 60) if s % 60 == 0 and s >= 60 else '%ds' % s


# ------------------------------------------------------------------------------------------------ MCP plumbing

STR = {'type': 'string'}
TOOLS = [
    {'name': 'hosts', 'title': 'Hosts',
     'description': 'List, add, test or remove hosts in the inventory. Adding connects once as the look account, '
                    'pins the host key, asks the user (shows the fingerprint), then checks both accounts: look (can '
                    'only read) and change (can sudo). On Linux, adding also gives the look account docker ps/logs/inspect and '
                    'journalctl through sudo (nothing else; it stays out of the docker group); setup re-installs that '
                    'on a host added before.',
     'inputSchema': {'type': 'object', 'properties': {
         'action': {'type': 'string', 'enum': ['list', 'add', 'test', 'setup', 'remove']},
         'name': STR, 'address': STR, 'port': {'type': 'integer'}, 'kind': {'type': 'string', 'enum': list(KINDS)},
         'look_user': STR, 'change_user': STR, 'key_file': STR,
         'look_key': {'type': 'string', 'description': 'key for the look account, if not key_file'},
         'change_key': {'type': 'string', 'description': 'key for the change account, if not key_file'},
         'jump': {'type': 'string', 'description': 'name of a host added with kind="jump" (a bastion, or the server '
                                                   'a reverse tunnel ends on) to reach this host through'},
         'groups': {'type': 'array', 'items': STR},
         'create_look': {'type': 'boolean', 'description': 'Linux: log in as the change account first and create the '
                         'look account if missing (no password, no sudo, no groups, the change account\'s keys)'}},
        'required': ['action']},
     'annotations': {'readOnlyHint': False, 'destructiveHint': False}},
    {'name': 'look', 'title': 'Look',
     'description': 'Read state on hosts as the unprivileged look account. Never changes anything and never asks. '
                    'Either read= one of overview, services, containers, logs (unit/container/since/grep/lines), '
                    'disk, updates, interfaces, guard (is a change armed; was one reverted) or command= any '
                    'read-only shell command (it runs as an account that cannot change the system).',
     'inputSchema': {'type': 'object', 'properties': {
         'hosts': {'type': 'string', 'description': 'host, group or pattern, e.g. web-1 or web:&prod'},
         'read': {'type': 'string', 'enum': ['overview', 'services', 'containers', 'logs', 'disk', 'updates',
                                             'interfaces', 'guard', 'python']},
         'command': STR, 'unit': STR, 'container': STR, 'since': STR, 'grep': STR,
         'lines': {'type': 'integer'}, 'timeout': {'type': 'integer'}}, 'required': ['hosts']},
     'annotations': {'readOnlyHint': True}},
    {'name': 'backup', 'title': 'Backup',
     'description': 'Pull a copy of hosts\' configuration into the server\'s state folder (never the project repo): '
                    'RouterOS /export terse, OpenWrt sysupgrade -b plus uci export, and on Linux, macOS and Windows '
                    'the paths you list (a tar.gz, or a zip with registry exports). Changes nothing and never asks; '
                    'returns where each file went, its size and sha256, never its contents.',
     'inputSchema': {'type': 'object', 'properties': {
         'hosts': {'type': 'string', 'description': 'host, group or pattern'},
         'paths': {'type': 'array', 'items': STR,
                   'description': 'absolute paths: /etc/x, C:\\x or HKLM:\\SOFTWARE\\x (needed for Linux, macOS, '
                                  'Windows)'},
         'label': {'type': 'string', 'description': 'optional tag for the folder name, e.g. before-upgrade'}},
         'required': ['hosts']},
     'annotations': {'readOnlyHint': True}},
    {'name': 'playbook', 'title': 'Playbooks',
     'description': 'List, read, write, delete or lint files in the project: playbooks/*.yml, roles/..., '
                    'oneoffs/*.yml. Every write is linted (and committed to the project\'s git). Declare per-run '
                    'inputs in the first play\'s vars.asm_params so one approval covers them, e.g. asm_params: '
                    '{client: {type: str, pattern: "^[a-z0-9-]+$"}, days: {type: int, min: 1, max: 90}}.',
     'inputSchema': {'type': 'object', 'properties': {
         'action': {'type': 'string', 'enum': ['list', 'read', 'write', 'delete', 'lint']},
         'path': {'type': 'string', 'description': 'e.g. playbooks/updates.yml'}, 'content': STR},
         'required': ['action']},
     'annotations': {'readOnlyHint': False, 'destructiveHint': False}},
    {'name': 'plan', 'title': 'Plan',
     'description': 'Check mode with diff: what a playbook would change on each host, what would be snapshotted, '
                    'and whether this playbook version is already approved. Changes nothing.',
     'inputSchema': {'type': 'object', 'properties': {
         'playbook': STR, 'limit': STR, 'params': {'type': 'object'}}, 'required': ['playbook']},
     'annotations': {'readOnlyHint': True}},
    {'name': 'apply', 'title': 'Apply',
     'description': 'Run a playbook for real under the safety net: each host arms a revert timer, the change runs, '
                    'then a fresh connection and the checks must pass before the change is kept; otherwise the host '
                    'puts itself back. Asks the user the first time a playbook version (content + roles + hosts) is '
                    'run; unchanged versions rerun without asking. Waits up to wait_s, then returns a job id.',
     'inputSchema': {'type': 'object', 'properties': {
         'playbook': STR, 'limit': STR, 'params': {'type': 'object'},
         'window': {'type': 'string', 'description': 'time to confirm before the host reverts: 10m (default), 90s'},
         'checks': {'type': 'array', 'items': STR,
                    'description': 'ssh (default), service:NAME, port:N, url:URL, or a command that must exit 0'},
         'paths': {'type': 'array', 'items': STR, 'description': 'extra paths to snapshot (absolute)'},
         'services': {'type': 'array', 'items': STR, 'description': 'extra units to restart on a revert'},
         'wait_s': {'type': 'integer'}}, 'required': ['playbook']},
     'annotations': {'readOnlyHint': False, 'destructiveHint': True}},
    {'name': 'hands', 'title': 'Remote hands',
     'description': 'A one-off change, for jobs that don\'t deserve a playbook yet: give the shell steps (RouterOS '
                    'commands on routers), why, and on Linux the paths they touch and services to restart. They are '
                    'saved as a playbook in oneoffs/ and run like apply: the user approves, the host arms a revert, '
                    'the change must be confirmed over a fresh connection. Prefer a real playbook for anything '
                    'repeated.',
     'inputSchema': {'type': 'object', 'properties': {
         'hosts': STR, 'why': {'type': 'string', 'description': 'one line: what this fixes'},
         'steps': {'type': 'array', 'items': STR},
         'paths': {'type': 'array', 'items': STR, 'description': 'Linux: files/folders the steps create, change or '
                                                                 'delete (snapshotted, restored on a revert)'},
         'services': {'type': 'array', 'items': STR}, 'window': STR,
         'checks': {'type': 'array', 'items': STR}, 'wait_s': {'type': 'integer'}},
         'required': ['hosts', 'why', 'steps']},
     'annotations': {'readOnlyHint': False, 'destructiveHint': True}},
    {'name': 'job', 'title': 'Jobs',
     'description': 'Follow an apply: status (optionally wait_s), list, extend (window) or revert (undo it now, '
                    'while the window is open).',
     'inputSchema': {'type': 'object', 'properties': {
         'id': STR, 'action': {'type': 'string', 'enum': ['status', 'list', 'extend', 'revert']},
         'window': STR, 'wait_s': {'type': 'integer'}}},
     'annotations': {'readOnlyHint': False}},
    {'name': 'status', 'title': 'Status',
     'description': 'Server state: hosts, approvals, lint, running jobs, recent activity; with hosts=, the safety '
                    'net on those hosts (armed changes, last revert).',
     'inputSchema': {'type': 'object', 'properties': {'hosts': STR}},
     'annotations': {'readOnlyHint': True}},
]


def main():
    server = Server()
    handlers = {t['name']: getattr(server, 't_' + t['name']) for t in TOOLS}
    out_lock = threading.Lock()

    def send(msg):
        with out_lock:
            sys.stdout.write(json.dumps(msg) + '\n')
            sys.stdout.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError:
            send({'jsonrpc': '2.0', 'id': None, 'error': {'code': -32700, 'message': 'parse error'}})
            continue
        rid, method, params = req.get('id'), req.get('method'), req.get('params') or {}
        if rid is None:
            continue  # notifications
        if method == 'initialize':
            want = params.get('protocolVersion')
            send({'jsonrpc': '2.0', 'id': rid, 'result': {
                'protocolVersion': want if want in PROTOCOLS else PROTOCOLS[0],
                'capabilities': {'tools': {}},
                'serverInfo': {'name': 'ansible-safe-mcp', 'version': VERSION},
                'instructions': INSTRUCTIONS}})
        elif method == 'ping':
            send({'jsonrpc': '2.0', 'id': rid, 'result': {}})
        elif method == 'tools/list':
            send({'jsonrpc': '2.0', 'id': rid, 'result': {'tools': TOOLS}})
        elif method == 'tools/call':
            name = params.get('name')
            args = params.get('arguments') or {}

            def call(rid=rid, name=name, args=args):
                try:
                    if name not in handlers:
                        raise ToolError('unknown tool %s' % name)
                    text, err = handlers[name](args), False
                except ToolError as e:
                    text, err = str(e), True
                except Exception as e:  # report, don't die
                    text, err = 'internal error: %s: %s' % (type(e).__name__, e), True
                if len(text) > MAX_TEXT:
                    text = text[:MAX_TEXT] + '\n[... cut at %d characters]' % MAX_TEXT
                send({'jsonrpc': '2.0', 'id': rid, 'result': {'content': [{'type': 'text', 'text': text}],
                                                              'isError': err}})
            threading.Thread(target=call, daemon=True).start()
        else:
            send({'jsonrpc': '2.0', 'id': rid, 'error': {'code': -32601, 'message': 'method not found: %s' % method}})


if __name__ == '__main__':
    main()
