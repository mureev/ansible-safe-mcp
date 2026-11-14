#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2026 Constantine Mureev
# MIT License (see LICENSE)
from __future__ import annotations

DOCUMENTATION = r'''
module: revert
short_description: Undo an armed change now
description:
  - Restores the snapshot taken by M(mureev.confirmed.arm), restarts its services and stops the timer. Does nothing
    when no change is armed.
version_added: 0.1.0
options:
  id:
    description: Revert only if this change is the armed one.
    type: str
  why:
    description: Reason written to the host's note and log.
    type: str
    default: manual
  state_dir:
    description: The guard's state folder on the host.
    type: path
    default: /var/lib/ansible-confirmed
author: Constantine Mureev (@mureev)
'''

EXAMPLES = r'''
- mureev.confirmed.revert:
    why: the app's health check failed
'''

RETURN = r'''
state:
  description: C(reverted), C(idle) (nothing armed) or C(revert-failed) (snapshot kept on the host).
  type: str
  returned: always
'''

import re

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.mureev.confirmed.plugins.module_utils import guard


def main():
    module = AnsibleModule(
        argument_spec=dict(
            id=dict(type='str'),
            why=dict(type='str', default='manual'),
            state_dir=dict(type='path', default=guard.DEFAULT_DIR),
        ),
        supports_check_mode=True,
    )
    p = module.params
    why = re.sub(r'[^A-Za-z0-9 .,:/_=-]', '', p['why'])[:80] or 'manual'
    if module.check_mode:
        st = guard.read_state(p['state_dir'])
        module.exit_json(changed=st['state'] == 'armed', **st)
    rc, data, out, err = guard.run(module, p['state_dir'], 'revert', why, p['id'] or '')
    if rc != 0:
        module.fail_json(msg=data.get('error') or err.strip() or out.strip(), **data)
    module.exit_json(changed=data.get('state') == 'reverted', **data)


if __name__ == '__main__':
    main()
