# Copyright (c) 2026 Constantine Mureev
# MIT License (see LICENSE)
"""The lint guard: refuse playbook content that would run code or read files on the machine running Ansible.

Ansible runs playbooks on the hosts, but several constructs execute on the controller (the user's Mac): lookups,
local connections, delegation to localhost, plugins next to the playbook, connection variables, and Jinja reaching
into Python internals. Claude writes the playbooks, so these are refused in anything under playbooks/ and roles/.
This is defense in depth; running Ansible itself inside a macOS sandbox comes next.
"""
from __future__ import annotations

import os
import re

import yaml

PLUGIN_DIRS = {'library', 'module_utils', 'action_plugins', 'cache_plugins', 'callback_plugins', 'connection_plugins',
               'filter_plugins', 'inventory_plugins', 'lookup_plugins', 'strategy_plugins', 'test_plugins',
               'vars_plugins', 'terminal_plugins', 'cliconf_plugins', 'httpapi_plugins', 'netconf_plugins',
               'become_plugins', 'shell_plugins', 'doc_fragments', 'collections', 'plugins'}
CONNECTION_VARS = {'ansible_connection', 'ansible_host', 'ansible_ssh_host', 'ansible_user', 'ansible_ssh_user',
                   'ansible_ssh_common_args', 'ansible_ssh_extra_args', 'ansible_ssh_args', 'ansible_ssh_executable',
                   'ansible_scp_extra_args', 'ansible_sftp_extra_args', 'ansible_ssh_private_key_file',
                   'ansible_private_key_file', 'ansible_paramiko_proxy_command', 'ansible_libssh_proxy_command',
                   'ansible_network_os', 'ansible_httpapi_host'}
SAFE_LOOPS = {'with_items', 'with_list', 'with_dict', 'with_together', 'with_nested', 'with_sequence',
              'with_subelements', 'with_indexed_items', 'with_flattened', 'with_random_choice', 'with_cartesian'}
LOCAL_SRC_MODULES = {'copy', 'template', 'script', 'unarchive', 'assemble', 'win_copy', 'win_template',
                     'patch', 'authorized_key', 'include_vars', 'import_tasks', 'include_tasks', 'import_playbook',
                     'import_role', 'include_role', 'vars_files'}
REFUSED_MODULES = {'fetch', 'local_action', 'pause', 'add_host', 'win_fetch'}
OK_CONNECTIONS = {'ssh', 'ansible.builtin.ssh', 'paramiko', 'ansible.builtin.paramiko', 'network_cli',
                  'ansible.netcommon.network_cli', 'psrp', 'winrm', 'ansible.builtin.winrm', 'ansible.builtin.psrp'}
LOCAL_HOSTS = re.compile(r'(^|[\s,:!&])(localhost|127\.\d+\.\d+\.\d+|::1)($|[\s,:])')
STRING_RULES = [
    (re.compile(r'\b(lookup|query)\s*\('), 'lookups run on your Mac (they read its files and run its commands)'),
    (re.compile(r'(^|[^\w.])q\s*\('), 'q() is a lookup: it runs on your Mac'),
    (re.compile(r'\{%-?\s*(include|import|extends|from)\b'), 'Jinja include/import reads files on your Mac'),
    (re.compile(r'(\{\{|\{%)[^}]*__'), 'Jinja reaching into Python internals runs code on your Mac'),
    (re.compile(r'ansible-confirmed|mureev\.confirmed'), 'playbooks may not touch the safety net itself'),
]
TEXT_SUFFIXES = ('.j2', '.jinja', '.jinja2', '.tmpl', '.tpl')


class Loader(yaml.SafeLoader):
    pass


def _tagged(loader, node):
    return loader.construct_scalar(node)


Loader.add_constructor('!unsafe', _tagged)
Loader.add_constructor('!vault', _tagged)
Loader.add_constructor('!vault-encrypted', _tagged)


def _short(name):
    return name.rsplit('.', 1)[-1] if isinstance(name, str) else name


def _bad_path(v):
    if not isinstance(v, str):
        return False
    v = v.strip()
    return v.startswith('/') or v.startswith('~') or '..' in v.replace('\\', '/').split('/') or v.startswith('$')


class Finding(dict):
    pass


def _scan(node, file, where, out):
    if isinstance(node, dict):
        for k, v in node.items():
            kw = '%s.%s' % (where, k) if where else str(k)
            ks = str(k)
            short = _short(ks)
            if ks == 'delegate_to':
                out.append(Finding(file=file, where=kw, rule='delegate_to runs the task somewhere other than the '
                                                             'host (often your Mac); not allowed'))
            elif ks == 'local_action' or short in REFUSED_MODULES:
                out.append(Finding(file=file, where=kw, rule='%s is not allowed: it acts on your Mac or needs a '
                                                             'person at the keyboard' % ks))
            elif ks == 'connection' and isinstance(v, str) and v not in OK_CONNECTIONS:
                out.append(Finding(file=file, where=kw, rule='connection: %s is not allowed (only the server picks '
                                                             'how to connect)' % v))
            elif ks == 'check_mode' and v is not True:
                out.append(Finding(file=file, where=kw, rule='check_mode other than true makes "plan" change things'))
            elif ks == 'hosts' and isinstance(v, str) and LOCAL_HOSTS.search(v):
                out.append(Finding(file=file, where=kw, rule='plays may not target localhost: that is your Mac'))
            elif ks == 'hosts' and isinstance(v, list) and any(isinstance(x, str) and LOCAL_HOSTS.search(x)
                                                               for x in v):
                out.append(Finding(file=file, where=kw, rule='plays may not target localhost: that is your Mac'))
            elif ks.startswith('with_') and ks not in SAFE_LOOPS:
                out.append(Finding(file=file, where=kw, rule='%s is a lookup: it runs on your Mac' % ks))
            elif ks in CONNECTION_VARS or ks in ('remote_user', 'vars_prompt'):
                out.append(Finding(file=file, where=kw, rule='%s is set by the server, not by playbooks' % ks))
            elif short in LOCAL_SRC_MODULES or ks == 'vars_files':
                for bad in _paths_in(v):
                    out.append(Finding(file=file, where=kw, rule='%s reads %r from your Mac: only relative paths '
                                                                 'inside the project are allowed' % (ks, bad)))
            if isinstance(k, str):
                _scan_str(k, file, kw, out)
            _scan(v, file, kw, out)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _scan(v, file, '%s[%d]' % (where, i), out)
    elif isinstance(node, str):
        _scan_str(node, file, where, out)


def _paths_in(v):
    """Local paths a src-taking module or include would read."""
    found = []
    if isinstance(v, str):
        # free-form: "include_tasks: x.yml" / "copy: src=/etc/x dest=..."
        m = re.search(r'(?:^|\s)(?:src|file|dir)=(\S+)', v)
        cand = m.group(1) if m else (v if '=' not in v else None)
        if cand and _bad_path(cand):
            found.append(cand)
    elif isinstance(v, dict):
        remote = str(v.get('remote_src', '')).lower() in ('true', 'yes', '1')
        for key in ('src', 'file', 'name', 'dir', 'key'):
            if remote and key == 'src':
                continue
            x = v.get(key)
            if key == 'key' and isinstance(x, str) and not x.startswith(('/', '~')):
                continue  # authorized_key's key is usually the key text or a URL
            if key == 'name' and 'tasks_from' not in v and not any(s in v for s in ('file', 'src')):
                # include_role name is a role name, not a path; include_tasks name may be a path
                if isinstance(x, str) and '/' not in x:
                    continue
            if _bad_path(x):
                found.append(x)
    elif isinstance(v, list):
        for x in v:
            if _bad_path(x):
                found.append(x)
    return found


def _scan_str(s, file, where, out):
    for rx, rule in STRING_RULES:
        if rx.search(s):
            out.append(Finding(file=file, where=where, rule=rule, text=s[:160]))


def lint_tree(project, roots=('playbooks', 'roles')):
    """Lint every file under the given project folders. Returns a list of findings (empty means clean)."""
    out = []
    for root in roots:
        base = os.path.join(project, root)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            rel_dir = os.path.relpath(dirpath, project)
            for d in list(dirnames):
                if d in PLUGIN_DIRS:
                    out.append(Finding(file=os.path.join(rel_dir, d), where='', rule='plugin folders next to '
                                       'playbooks or in roles run as code on your Mac; not allowed'))
            for fn in filenames:
                rel = os.path.join(rel_dir, fn)
                path = os.path.join(dirpath, fn)
                if fn in ('ansible.cfg', '.ansible.cfg'):
                    out.append(Finding(file=rel, where='', rule='a project ansible.cfg could load plugins; the '
                                                               'server uses its own'))
                    continue
                if os.path.islink(path):
                    target = os.path.realpath(path)
                    if not target.startswith(os.path.realpath(project) + os.sep):
                        out.append(Finding(file=rel, where='', rule='symlink pointing outside the project'))
                    continue
                if fn.endswith(('.yml', '.yaml')):
                    out.extend(lint_yaml_file(path, rel))
                elif fn.endswith(TEXT_SUFFIXES) or '/templates' in '/' + rel_dir:
                    try:
                        with open(path, encoding='utf-8', errors='replace') as f:
                            text = f.read(2_000_000)
                    except OSError:
                        continue
                    for lineno, line in enumerate(text.splitlines(), 1):
                        _scan_str(line, rel, 'line %d' % lineno, out)
    return out


def lint_yaml_file(path, rel):
    try:
        with open(path, encoding='utf-8') as f:
            text = f.read()
    except (OSError, UnicodeDecodeError) as e:
        return [Finding(file=rel, where='', rule='unreadable: %s' % e)]
    return lint_yaml_text(text, rel)


def lint_yaml_text(text, rel):
    try:
        docs = list(yaml.load_all(text, Loader=Loader))
    except yaml.YAMLError as e:
        return [Finding(file=rel, where='', rule='not valid YAML: %s' % str(e).splitlines()[0])]
    out = []
    for doc in docs:
        _scan(doc, rel, '', out)
    return out


def format_findings(findings, limit=30):
    lines = []
    for f in findings[:limit]:
        loc = f['file'] + ((' at ' + f['where']) if f.get('where') else '')
        lines.append('- %s: %s%s' % (loc, f['rule'], (' — %r' % f['text']) if f.get('text') else ''))
    if len(findings) > limit:
        lines.append('- ... and %d more' % (len(findings) - limit))
    return '\n'.join(lines)
