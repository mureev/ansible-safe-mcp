#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2026 Constantine Mureev
# MIT License (see LICENSE)
from __future__ import annotations

DOCUMENTATION = r'''
module: arm
short_description: Snapshot what a change will touch and start a revert timer on the host
description:
  - Commit-confirmed for Linux hosts. Takes a snapshot of O(paths) (and the firewall ruleset with O(firewall)), then
    starts a timer on the host itself. Unless M(mureev.confirmed.confirm) runs before the deadline, the host restores
    the snapshot and restarts O(services) on its own, even if Ansible, the SSH connection or the controller is gone.
  - Uses a C(systemd-run) timer plus a boot check when systemd is running; otherwise a detached process (which a reboot
    inside the window loses; RV(survives_reboot) says which).
  - Fails, and arms nothing, if another change is already armed on the host or the timer can't be started.
    Put it before the change, so a failed arm stops the play before anything changes.
version_added: 0.1.0
options:
  id:
    description: Name for this change (letters, digits, C(.-_)). Generated when omitted.
    type: str
  window:
    description: How long the change may stay unconfirmed. Seconds, or C(90s), C(10m), C(1h). 5s to 24h.
    type: raw
    default: 10m
  paths:
    description:
      - Absolute paths the change may create, modify or delete. Paths that don't exist yet are removed on revert;
        directories get back exactly their old contents.
    type: list
    elements: path
    default: []
  services:
    description: Units to reload or restart after a revert, in this order (systemd, else C(service)).
    type: list
    elements: str
    default: []
  firewall:
    description: Also snapshot and restore the whole firewall ruleset (nft, else iptables-save).
    type: bool
    default: false
  state_dir:
    description: Where the guard keeps its script, snapshot and notes on the host.
    type: path
    default: /var/lib/ansible-confirmed
notes:
  - Needs root (C(become)). Check mode reports what it would arm and arms nothing.
  - A revert restores files and firewall rules. It can't bring back deleted data outside O(paths), undo calls to
    other systems, or downgrade packages.
author: Constantine Mureev (@mureev)
'''

EXAMPLES = r'''
- name: Change sshd under a 10-minute safety net
  hosts: web
  become: true
  tasks:
    - mureev.confirmed.arm:
        window: 10m
        paths: [/etc/ssh/sshd_config.d/50-hardening.conf]
        services: [ssh]
    - ansible.builtin.copy:
        src: 50-hardening.conf
        dest: /etc/ssh/sshd_config.d/50-hardening.conf
    - ansible.builtin.service:
        name: ssh
        state: reloaded
    - mureev.confirmed.confirm:
        checks: [ssh]
'''

RETURN = r'''
id:
  description: The change's id.
  type: str
  returned: always
deadline:
  description: Unix time at which the host reverts unless confirmed.
  type: int
  returned: success
deadline_iso:
  description: The deadline in UTC, ISO 8601.
  type: str
  returned: success
backend:
  description: C(systemd) or C(detached).
  type: str
  returned: success
survives_reboot:
  description: Whether the guard still reverts if the host reboots inside the window.
  type: bool
  returned: success
'''

import os
import uuid

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.mureev.confirmed.plugins.module_utils import guard


def main():
    module = AnsibleModule(
        argument_spec=dict(
            id=dict(type='str'),
            window=dict(type='raw', default='10m'),
            paths=dict(type='list', elements='path', default=[]),
            services=dict(type='list', elements='str', default=[]),
            firewall=dict(type='bool', default=False),
            state_dir=dict(type='path', default=guard.DEFAULT_DIR),
        ),
        supports_check_mode=True,
    )
    p = module.params
    try:
        secs = guard.parse_window(p['window'])
    except ValueError as e:
        module.fail_json(msg=str(e))
    cid = p['id'] or uuid.uuid4().hex[:8]
    sd = p['state_dir'].rstrip('/')
    paths = []
    for path in p['paths']:
        norm = os.path.normpath(path)
        if not os.path.isabs(norm) or '\n' in norm:
            module.fail_json(msg='paths must be absolute: %r' % path)
        if norm == '/' or norm == sd or norm.startswith(sd + '/') or sd.startswith(norm + '/'):
            module.fail_json(msg='refusing to snapshot %s: it is / or overlaps the guard state %s' % (norm, sd))
        paths.append(norm)
    for s in p['services']:
        if not s or '\n' in s or '/' in s:
            module.fail_json(msg='bad service name: %r' % s)

    if module.check_mode:
        module.exit_json(changed=True, id=cid, armed=False, window=secs,
                         msg='would arm %s for %ds over %d paths' % (cid, secs, len(paths)))

    os.makedirs(sd, mode=0o755, exist_ok=True)
    req = os.path.join(sd, 'req.' + cid)
    os.makedirs(req, mode=0o700, exist_ok=True)
    with open(os.path.join(req, 'paths'), 'w') as f:
        f.write(''.join(x + '\n' for x in paths))
    with open(os.path.join(req, 'services'), 'w') as f:
        f.write(''.join(x + '\n' for x in p['services']))
    with open(os.path.join(req, 'firewall'), 'w') as f:
        f.write('1\n' if p['firewall'] else '0\n')

    rc, data, out, err = guard.run(module, sd, 'arm', cid, secs, req)
    if rc != 0 or data.get('state') != 'armed':
        module.fail_json(msg='not armed: %s' % (data.get('error') or err.strip() or out.strip()), id=cid, rc=rc)
    data['survives_reboot'] = data.get('backend') == 'systemd'
    data['window'] = secs
    module.exit_json(changed=True, armed=True, **data)


if __name__ == '__main__':
    main()
