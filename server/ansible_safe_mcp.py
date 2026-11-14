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

VERSION = '0.1.0'
PROTOCOLS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05']
NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$')
ADDR_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9.:_-]{0,252}$')
USER_RE = re.compile(r'^[a-z_][a-z0-9_.-]{0,31}(\+[a-z0-9]{1,16})?$')
PATTERN_RE = re.compile(r'^[A-Za-z0-9_.*:,!&\[\]-]{1,400}$')
SAFE_STR = r'^[A-Za-z0-9 ._@:/+,=-]{0,200}$'
KINDS = ('linux', 'routeros')
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
             'asm_look_user', 'asm_change_user', 'asm_jump', 'asm_look_key', 'asm_change_key'}


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
            elif k == 'ansible_ssh_common_args' and not re.match(r'^-o ProxyJump=[A-Za-z0-9_.@:,-]+$', str(x)):
                bad.append('%s.ansible_ssh_common_args may only hold a ProxyJump' % name)
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


def routeros_plan_text(path, targets):
    cmds = routeros_commands(path)
    lines = ['%s: under Safe Mode, %d command%s:' % (', '.join(targets), len(cmds), '' if len(cmds) == 1 else 's')]
    for name, c in cmds[:60]:
        lines.append('  > %s%s' % (c[:300], ('    # ' + name) if name else ''))
    if len(cmds) > 40:
        lines.append('  ! more than 40 commands: Safe Mode keeps 100 actions, then lets go without undoing; split it')
    lines.append('  · RouterOS has no check mode: these are the commands as written, not a preview of the result')
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
        if action != 'add':
            raise ToolError('action must be list, add, test or remove')
        address = a.get('address') or name
        port = int(a.get('port') or 22)
        kind = a.get('kind', 'linux')
        look_u, change_u = a.get('look_user', ''), a.get('change_user', '')
        jump = a.get('proxy_jump') or ''
        key_file = a.get('key_file') or ''
        look_key = a.get('look_key') or key_file
        change_key = a.get('change_key') or key_file
        groups = a.get('groups') or []
        if not ADDR_RE.match(address) or address.startswith('-'):
            raise ToolError('address: a hostname or IP')
        if kind not in KINDS:
            raise ToolError('kind must be one of %s' % ', '.join(KINDS))
        if not (USER_RE.match(look_u) and USER_RE.match(change_u)) or look_u == change_u:
            raise ToolError('look_user and change_user are two different accounts on the host: one that can only '
                            'read, one that can change things (sudo)')
        if look_u == 'root':
            raise ToolError('the look account must not be root')
        if jump and not re.match(r'^[A-Za-z0-9_.@:-]{1,200}(,[A-Za-z0-9_.@:-]{1,200})*$', jump):
            raise ToolError('proxy_jump: user@host[:port][,...]')
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
        if jump:
            cmd += ['-J', jump]
        if look_key:
            cmd += ['-i', look_key, '-o', 'IdentitiesOnly=yes']
        if kind == 'routeros':
            cmd += ['%s@%s' % (look_u, address), '/system identity print']
        else:
            cmd += ['%s@%s' % (look_u, address), 'id -un; sudo -n true 2>/dev/null && echo SUDO-OK || echo NO-SUDO']
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=40, stdin=subprocess.DEVNULL)
        if not (os.path.exists(kh) and os.path.getsize(kh) > 0):
            shutil.rmtree(d, ignore_errors=True)
            raise ToolError('could not reach %s as %s: %s' % (address, look_u, (p.stderr.strip() or 'no answer')[-400:]))
        fp = subprocess.run(['ssh-keygen', '-lf', kh], capture_output=True, text=True).stdout.strip()
        if p.returncode != 0:
            shutil.rmtree(d, ignore_errors=True)
            raise ToolError('%s answered but the look account %s could not log in: %s' % (
                address, look_u, p.stderr.strip()[-300:]))
        warn = ''
        if kind == 'linux' and 'SUDO-OK' in p.stdout:
            warn = '\n\nWARNING: the look account can sudo without a password, so it is not read-only.'
        text = ('Add host %s\n\n%s port %d%s\nkind: %s\nlook account: %s\nchange account: %s\n\nHost key:\n%s%s' % (
            name, address, port, (' via ' + jump) if jump else '', kind, look_u, change_u, fp, warn))
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
            entry['ansible_ssh_common_args'] = '-o ProxyJump=%s' % jump
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
        return 'Added %s (%s).\n\n%s' % (name, fp.split(' ')[1] if ' ' in fp else fp, self._test_host(name))

    def _test_host(self, name):
        hv = hosts_of(load_inventory(self.cfg))[name]
        kind = hv.get('asm_kind', 'linux')
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
                    name, 'true' if become and kind == 'linux' else 'false', task))
            vf = os.path.join(d, 'vars.yml')
            write_vars(vf, account)
            doc, err, rc = run_playbook(self.cfg, pb, vf, timeout=90)
            st = ((doc or {}).get('tasks') or [{}])[-1].get('hosts', {}).get(name, {}) if doc else {}
            okay = st.get('status') in ('ok', 'changed')
            what = 'logs in' + (' and can sudo' if become and kind == 'linux' else '')
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
                c = 'journalctl --no-pager -n %d %s%s%s' % (lines, ('-u %s ' % q(unit)) if unit else '-p warning ',
                                                           ('--since %s ' % q(since)) if since else '', '')
            if grep:
                c += ' | grep -i -- %s' % q(str(grep)[:200])
            tasks.append(('linux', c + ' | tail -n %d' % lines))
            tasks.append(('routeros', READS['routeros']['logs']))
        else:
            for kind in KINDS:
                if read in READS[kind]:
                    tasks.append((kind, READS[kind][read]))
            if not tasks:
                raise ToolError('unknown read %r' % read)
        # RouterOS hosts are read over plain SSH, one connection each, no Ansible in between
        hs = hosts_of(inv)
        ros_hosts = [h for h in self._resolve(pattern) if hs.get(h, {}).get('asm_kind') == 'routeros']
        ros_cmd = next((c for k, c in tasks if k == 'routeros'), None)
        per = {}
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
        tasks = [(k, c) for k, c in tasks if k != 'routeros']
        if read == 'guard' or tasks:
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
            body += ['    - mureev.confirmed.status:', '      when: asm_kind | default("linux") == "linux"']
        for kind, c in tasks:
            mod = 'ansible.builtin.shell' if kind == 'linux' else 'ansible.builtin.raw'
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
        if kind == 'routeros':
            h = version_hash(self.cfg, rel, targets)
            approved = self.approvals.approved(h, rel, targets)
            self.audit.write('plan', summary='%s on %s' % (rel, ','.join(targets)), version=h[:12])
            return '%s on %s\nversion %s: %s\n\n%s' % (
                rel, ', '.join(targets), h[:12],
                'approved before, apply runs without asking' if approved else 'not approved yet, apply will ask',
                routeros_plan_text(path, targets))
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
            if not isinstance(p, str) or not p.startswith('/') or '\n' in p:
                raise ToolError('paths: absolute paths on the hosts')
        for s in extra_services:
            if not isinstance(s, str) or not re.match(r'^[A-Za-z0-9@._-]{1,120}$', s):
                raise ToolError('services: unit names')
        if kind == 'routeros':
            return self._apply_routeros(path, rel, params, targets, window, checks, a)
        plan = self._plan(path, limit, params)
        unreachable = [h for h in targets if (plan.get(h) or {}).get('unreachable')]
        if unreachable:
            raise ToolError('plan could not reach %s; nothing was changed.\n\n%s' % (', '.join(unreachable),
                                                                                    plan_text(plan)))
        h = version_hash(self.cfg, rel, targets)
        asked = False
        if not self.approvals.approved(h, rel, targets):
            text = ('Run %s on %s\n\nversion %s%s\nEach host reverts in %s unless Claude confirms it over a fresh '
                    'connection.\n\n%s' % (rel, ', '.join(targets), h[:12],
                                          ('\nparams: ' + json.dumps(params)) if params else '',
                                          fmt_window(window), plan_text(plan)[:1800]))
            ok, how = ask(self.cfg, 'Run %s on %s?' % (rel, ', '.join(targets)[:60]), text)
            asked = True
            if not ok:
                self.audit.write('apply', summary='%s declined (%s)' % (rel, how), version=h[:12])
                return 'Not run: the user declined this playbook version (%s). Nothing changed.' % how
            self.approvals.add(h, rel, targets)
        job_id = time.strftime('%m%d%H%M') + secrets.token_hex(2)
        jd = os.path.join(self.cfg.jobs, job_id)
        os.makedirs(jd, mode=0o700)
        snap = {t: {'paths': sorted(set(plan.get(t, {}).get('paths', set())) | set(extra_paths)),
                    'services': list(dict.fromkeys(plan.get(t, {}).get('services', []) + extra_services)),
                    'firewall': 'firewall' in plan.get(t, {}).get('flags', set())} for t in targets}
        vf = os.path.join(jd, 'vars.yml')
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
        job = {'id': job_id, 'playbook': rel, 'targets': targets, 'version': h, 'params': params, 'window': window,
               'started': time.time(), 'status': 'running', 'asked': asked, 'snapshot': snap}
        self._save_job(job)
        progress = os.path.join(jd, 'progress.log')
        cmd = [self.cfg.playbook_bin, wrapper, '-e', '@' + vf, '--limit', hosts_pat]
        proc = subprocess.Popen(cmd, cwd=self.cfg.project, env=ansible_env(self.cfg, progress),
                                stdout=open(os.path.join(jd, 'stdout.log'), 'w'),
                                stderr=open(os.path.join(jd, 'stderr.log'), 'w'),
                                stdin=subprocess.DEVNULL, start_new_session=True)
        job['pid'] = proc.pid
        self._save_job(job)
        self.audit.write('apply', summary='%s on %s (job %s)' % (rel, ','.join(targets), job_id), version=h[:12],
                         asked=asked, params=params)
        t = threading.Thread(target=self._finish, args=(job_id, proc), daemon=True)
        t.start()
        t.join(timeout=max(0, min(int(a.get('wait_s', 50)), 110)))
        head = ('Approved by the user just now (version %s). ' % h[:12]) if asked else (
            'Version %s was approved before: ran without asking. ' % h[:12])
        return head + self._job_text(job_id)

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

    def _apply_routeros(self, path, rel, params, targets, window, checks, a):
        h = version_hash(self.cfg, rel, targets)
        ok, asked, how = self._approve(rel, targets, h, params, window, routeros_plan_text(path, targets))
        if not ok:
            self.audit.write('apply', summary='%s declined (%s)' % (rel, how), version=h[:12])
            return 'Not run: the user declined this playbook version (%s). Nothing changed.' % how
        job_id = time.strftime('%m%d%H%M') + secrets.token_hex(2)
        jd = os.path.join(self.cfg.jobs, job_id)
        os.makedirs(jd, mode=0o700)
        vf = os.path.join(jd, 'vars.yml')
        write_vars(vf, 'change', params)
        job = {'id': job_id, 'playbook': rel, 'targets': targets, 'version': h, 'params': params, 'window': window,
               'started': time.time(), 'status': 'running', 'asked': asked, 'kind': 'routeros'}
        self._save_job(job)
        self.audit.write('apply', summary='%s on %s (job %s, Safe Mode)' % (rel, ','.join(targets), job_id),
                         version=h[:12], asked=asked, params=params)
        t = threading.Thread(target=self._run_routeros, args=(job_id, path, vf, targets, checks, window), daemon=True)
        t.start()
        t.join(timeout=max(0, min(int(a.get('wait_s', 80)), 110)))
        head = ('Approved by the user just now (version %s). ' % h[:12]) if asked else (
            'Version %s was approved before: ran without asking. ' % h[:12])
        return head + self._job_text(job_id)

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
        lines = ['Job %s: %s on %s, window %s.' % (job_id, job['playbook'], ', '.join(job['targets']),
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
            while job['status'] != 'done' and time.time() < end:
                time.sleep(1)
                job = self._load_job(job_id)
            return self._job_text(job_id)
        if action in ('extend', 'revert'):
            if job.get('kind') == 'routeros':
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
                    'only read) and change (can sudo).',
     'inputSchema': {'type': 'object', 'properties': {
         'action': {'type': 'string', 'enum': ['list', 'add', 'test', 'remove']},
         'name': STR, 'address': STR, 'port': {'type': 'integer'}, 'kind': {'type': 'string', 'enum': list(KINDS)},
         'look_user': STR, 'change_user': STR, 'key_file': STR,
         'look_key': {'type': 'string', 'description': 'key for the look account, if not key_file'},
         'change_key': {'type': 'string', 'description': 'key for the change account, if not key_file'},
         'proxy_jump': {'type': 'string', 'description': 'user@jumphost[:port], for hosts behind a bastion'},
         'groups': {'type': 'array', 'items': STR}}, 'required': ['action']},
     'annotations': {'readOnlyHint': False, 'destructiveHint': False}},
    {'name': 'look', 'title': 'Look',
     'description': 'Read state on hosts as the unprivileged look account. Never changes anything and never asks. '
                    'Either read= one of overview, services, containers, logs (unit/container/since/grep/lines), '
                    'disk, updates, interfaces, guard (is a change armed; was one reverted) or command= any '
                    'read-only shell command (it runs as an account that cannot change the system).',
     'inputSchema': {'type': 'object', 'properties': {
         'hosts': {'type': 'string', 'description': 'host, group or pattern, e.g. web-1 or web:&prod'},
         'read': {'type': 'string', 'enum': ['overview', 'services', 'containers', 'logs', 'disk', 'updates',
                                             'interfaces', 'guard']},
         'command': STR, 'unit': STR, 'container': STR, 'since': STR, 'grep': STR,
         'lines': {'type': 'integer'}, 'timeout': {'type': 'integer'}}, 'required': ['hosts']},
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
