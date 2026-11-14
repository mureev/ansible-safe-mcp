# -*- coding: utf-8 -*-
# Copyright (c) 2026 Constantine Mureev
# MIT License (see LICENSE)
"""Action plugin for mureev.confirmed.confirm: fresh connection, checks, then keep the change."""
from __future__ import annotations

from ansible.errors import AnsibleConnectionFailure, AnsibleError
from ansible.plugins.action import ActionBase

DEFAULT_DIR = '/var/lib/ansible-confirmed'


class ActionModule(ActionBase):
    TRANSFERS_FILES = False
    _VALID_ARGS = frozenset(('id', 'checks', 'revert_on_failure', 'fresh_connection', 'state_dir'))

    def _module(self, name, args, task_vars):
        return self._execute_module(module_name=name, module_args=args, task_vars=task_vars)

    def _check(self, check, task_vars):
        """Run one check on the host. Returns (ok, detail)."""
        if check in ('ssh', 'ping'):
            return True, 'fresh connection works'
        if check.startswith('service:'):
            name = check.split(':', 1)[1]
            cmd = 'systemctl is-active --quiet %s 2>/dev/null || service %s status >/dev/null 2>&1' % (
                _q(name), _q(name))
            r = self._module('ansible.builtin.command', {'_raw_params': cmd, '_uses_shell': True}, task_vars)
            return r.get('rc') == 0, 'service %s %s' % (name, 'active' if r.get('rc') == 0 else 'not active')
        if check.startswith('port:'):
            port = check.split(':', 1)[1]
            r = self._module('ansible.builtin.wait_for', {'port': int(port), 'host': '127.0.0.1', 'timeout': 5},
                             task_vars)
            return not r.get('failed'), 'port %s %s' % (port, 'open' if not r.get('failed') else 'closed')
        if check.startswith('url:'):
            url = check.split(':', 1)[1]
            r = self._module('ansible.builtin.uri', {'url': url, 'timeout': 10, 'status_code': list(range(200, 300))},
                             task_vars)
            return not r.get('failed'), 'url %s -> %s' % (url, r.get('status', r.get('msg', '?')))
        r = self._module('ansible.builtin.command', {'_raw_params': check, '_uses_shell': True}, task_vars)
        return r.get('rc') == 0, 'command exited %s' % r.get('rc', r.get('msg', '?'))

    def run(self, tmp=None, task_vars=None):
        result = super().run(tmp, task_vars)
        del tmp
        args = dict(self._task.args)
        sd = args.get('state_dir') or DEFAULT_DIR
        checks = args.get('checks') or ['ssh']
        if isinstance(checks, str):
            checks = [checks]
        want = args.get('id') or ''
        if self._task.check_mode:
            result.update(changed=False, skipped=True, msg='check mode: nothing confirmed')
            return result

        st = self._module('mureev.confirmed.status', {'state_dir': sd}, task_vars)
        if st.get('state') != 'armed':
            last = st.get('last', '')
            if want and last.startswith('confirmed ') and (' %s ' % want) in last + ' ':
                result.update(changed=False, state='confirmed', id=want, last=last, msg='already confirmed')
                return result
            result.update(failed=True, state=st.get('state'), last=last,
                          msg='nothing is armed on this host to confirm' + (' (last: %s)' % last if last else ''))
            return result
        if want and st.get('id') != want:
            result.update(failed=True, msg='the armed change is %s, not %s' % (st.get('id'), want))
            return result
        deadline = st.get('deadline_iso', 'its deadline')

        if args.get('fresh_connection', True):
            try:
                self._connection.reset()
            except Exception as e:  # a connection that can't reset still gets the ping below
                self._display.vvv('confirm: reset failed: %s' % e)
        try:
            ping = self._module('ansible.builtin.ping', {}, task_vars)
        except (AnsibleConnectionFailure, AnsibleError) as e:
            result.update(failed=True, confirmed=False, deadline_iso=deadline,
                          msg='NOT CONFIRMED: a fresh connection to the host failed (%s). '
                              'The host will undo change %s at %s.' % (str(e).splitlines()[0][:200], st.get('id'),
                                                                       deadline))
            return result
        if ping.get('failed') or ping.get('unreachable'):
            result.update(failed=True, confirmed=False, deadline_iso=deadline,
                          msg='NOT CONFIRMED: the host did not answer over a fresh connection (%s). '
                              'It will undo change %s at %s.' % (ping.get('msg', ''), st.get('id'), deadline))
            return result

        results, failed = [], []
        for c in checks:
            try:
                ok, detail = self._check(str(c), task_vars)
            except (AnsibleConnectionFailure, AnsibleError) as e:
                ok, detail = False, 'error: %s' % str(e).splitlines()[0][:200]
            results.append({'check': c, 'ok': ok, 'detail': detail})
            if not ok:
                failed.append(c)
        result['checks'] = results

        if failed:
            if args.get('revert_on_failure', True):
                r = self._module('mureev.confirmed.revert',
                                 {'id': st.get('id'), 'why': 'check failed: %s' % failed[0], 'state_dir': sd},
                                 task_vars)
                if r.get('state') == 'reverted':
                    outcome = 'reverted now'
                else:
                    outcome = 'could not be reverted now (%s); the host reverts at %s' % (r.get('msg', ''), deadline)
                result.update(failed=True, confirmed=False, reverted=r.get('state') == 'reverted',
                              msg='NOT CONFIRMED: check %s failed; change %s %s.' % (', '.join(failed), st.get('id'),
                                                                                     outcome))
            else:
                result.update(failed=True, confirmed=False, deadline_iso=deadline,
                              msg='NOT CONFIRMED: check %s failed. The host will undo change %s at %s.' % (
                                  ', '.join(failed), st.get('id'), deadline))
            return result

        r = self._module('mureev.confirmed.confirm', {'id': st.get('id'), 'state_dir': sd}, task_vars)
        if r.get('failed'):
            result.update(failed=True, confirmed=False, msg='NOT CONFIRMED: %s' % r.get('msg'))
            return result
        result.update(changed=True, confirmed=True, state='confirmed', id=st.get('id'), last=r.get('last'),
                      msg='confirmed %s: %s' % (st.get('id'), '; '.join(x['detail'] for x in results)))
        return result


def _q(s):
    import shlex
    return shlex.quote(s)
