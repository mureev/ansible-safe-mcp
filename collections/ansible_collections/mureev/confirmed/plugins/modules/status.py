#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2026 Constantine Mureev
# MIT License (see LICENSE)
from __future__ import annotations

DOCUMENTATION = r'''
module: status
short_description: Is a change armed on this host, and what happened to the last one
description:
  - Reads the guard's state. Works without root, so an unprivileged account can see that a change was reverted.
version_added: 0.1.0
options:
  state_dir:
    description: The guard's state folder on the host.
    type: path
    default: /var/lib/ansible-confirmed
author: Constantine Mureev (@mureev)
'''

EXAMPLES = r'''
- mureev.confirmed.status:
  register: guard
- ansible.builtin.debug:
    msg: "{{ guard.last | default('no change recorded') }}"
'''

RETURN = r'''
state:
  description: C(idle), C(armed) or C(reverting).
  type: str
  returned: always
last:
  description: The last outcome, for example C(reverted 2026-11-14T18:14:02Z 7f3a (timeout)).
  type: str
  returned: when there is one
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.mureev.confirmed.plugins.module_utils import guard


def main():
    module = AnsibleModule(argument_spec=dict(state_dir=dict(type='path', default=guard.DEFAULT_DIR)),
                           supports_check_mode=True)
    module.exit_json(changed=False, **guard.read_state(module.params['state_dir']))


if __name__ == '__main__':
    main()
