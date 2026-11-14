#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2026 Constantine Mureev
# MIT License (see LICENSE)
from __future__ import annotations

DOCUMENTATION = r'''
module: extend
short_description: Move an armed change's deadline
description:
  - Restarts the revert timer so the host reverts O(window) from now instead. For changes that need longer to prove
    themselves (a service warming up, a slow reboot).
version_added: 0.1.0
options:
  window:
    description: New time left, from now. Seconds, or C(90s), C(10m), C(1h).
    type: raw
    required: true
  state_dir:
    description: The guard's state folder on the host.
    type: path
    default: /var/lib/ansible-confirmed
author: Constantine Mureev (@mureev)
'''

EXAMPLES = r'''
- mureev.confirmed.extend:
    window: 20m
'''

RETURN = r'''
deadline_iso:
  description: The new deadline, UTC.
  type: str
  returned: success
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.mureev.confirmed.plugins.module_utils import guard


def main():
    module = AnsibleModule(
        argument_spec=dict(window=dict(type='raw', required=True),
                           state_dir=dict(type='path', default=guard.DEFAULT_DIR)),
        supports_check_mode=True,
    )
    try:
        secs = guard.parse_window(module.params['window'])
    except ValueError as e:
        module.fail_json(msg=str(e))
    if module.check_mode:
        module.exit_json(changed=True, msg='would extend to %ds' % secs)
    rc, data, out, err = guard.run(module, module.params['state_dir'], 'extend', secs)
    if rc != 0:
        module.fail_json(msg=data.get('error') or err.strip() or out.strip())
    module.exit_json(changed=True, **data)


if __name__ == '__main__':
    main()
