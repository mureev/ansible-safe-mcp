#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2026 Constantine Mureev
# MIT License (see LICENSE)
from __future__ import annotations

DOCUMENTATION = r'''
module: confirm
short_description: Keep an armed change, after proving the host still works over a fresh connection
description:
  - Ends the safety window opened by M(mureev.confirmed.arm). First it drops the connection Ansible is holding open
    and opens a new one, because an old connection can survive a change (a firewall rule, sshd config) that blocks
    every new one. Then it runs O(checks). Only if all of that works does it stop the timer and keep the change.
  - If the host can't be reached over the new connection, the task fails and the host reverts at its deadline.
    If the host is reachable but a check fails, the change is reverted right away (O(revert_on_failure)).
version_added: 0.1.0
options:
  id:
    description: Confirm only this change. Default is whatever is armed.
    type: str
  checks:
    description:
      - What must work before the change is kept. C(ssh) or C(ping) (the fresh connection itself, always done),
        C(service:NAME) (the unit is active), C(port:N) (something listens on N on the host), C(url:URL) (the host
        gets HTTP 2xx from URL), or any other string, run as a shell command on the host that must exit 0.
    type: list
    elements: str
    default: [ssh]
  revert_on_failure:
    description: When the host is reachable but a check fails, revert now instead of waiting for the deadline.
    type: bool
    default: true
  fresh_connection:
    description: Drop the persistent connection before checking. Leave it on unless you know why.
    type: bool
    default: true
  state_dir:
    description: The guard's state folder on the host.
    type: path
    default: /var/lib/ansible-confirmed
notes:
  - Needs root (C(become)). Skipped in check mode.
author: Constantine Mureev (@mureev)
'''

EXAMPLES = r'''
- mureev.confirmed.confirm:
    checks: [ssh, service:nginx, url:http://127.0.0.1/health]
'''

RETURN = r'''
state:
  description: C(confirmed), or C(idle) when nothing was armed.
  type: str
  returned: success
id:
  description: The change kept.
  type: str
  returned: when a change was confirmed
checks:
  description: Each check and whether it passed.
  type: list
  returned: always
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.mureev.confirmed.plugins.module_utils import guard


def main():
    # The action plugin does the fresh connection and the checks, then calls this module to stop the timer.
    module = AnsibleModule(
        argument_spec=dict(
            id=dict(type='str'),
            checks=dict(type='list', elements='str', default=['ssh']),
            revert_on_failure=dict(type='bool', default=True),
            fresh_connection=dict(type='bool', default=True),
            state_dir=dict(type='path', default=guard.DEFAULT_DIR),
        ),
        supports_check_mode=True,
    )
    if module.check_mode:
        module.exit_json(changed=False, skipped=True, msg='check mode: nothing confirmed')
    rc, data, out, err = guard.run(module, module.params['state_dir'], 'confirm', module.params['id'] or '')
    if rc != 0:
        module.fail_json(msg=data.get('error') or err.strip() or out.strip(), **data)
    module.exit_json(changed=data.get('state') == 'confirmed', **data)


if __name__ == '__main__':
    main()
