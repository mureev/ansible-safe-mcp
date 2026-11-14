# Copyright (c) 2026 Constantine Mureev
# MIT License (see LICENSE)
"""stdout callback for ansible-safe-mcp: one JSON document at the end, progress lines to a file as it runs."""
from __future__ import annotations

import json
import os
import time

from ansible.plugins.callback import CallbackBase

DOCUMENTATION = '''
    name: asm_json
    type: stdout
    short_description: JSON results for ansible-safe-mcp
    description: Prints one JSON document (prefixed ASM_JSON:) when the run ends; writes progress lines to $ASM_PROGRESS.
'''

KEEP = ('msg', 'rc', 'stdout', 'stderr', 'state', 'id', 'deadline', 'deadline_iso', 'backend', 'confirmed',
        'checks', 'last', 'reverted', 'armed', 'survives_reboot', 'window', 'skip_reason', 'cmd', 'remaining',
        'timer_alive', 'ping')
LIMIT = 6000


def _cut(v):
    if isinstance(v, str) and len(v) > LIMIT:
        return v[:LIMIT] + '\n[... %d more characters]' % (len(v) - LIMIT)
    return v


def _slim(r, no_log):
    out = {'changed': bool(r.get('changed'))}
    if no_log:
        out['no_log'] = True
        return out
    for k in KEEP:
        if k in r:
            out[k] = _cut(r[k])
    if r.get('diff'):
        out['diff'] = r['diff']
    inv = (r.get('invocation') or {}).get('module_args')
    if isinstance(inv, dict):
        out['args'] = {k: v for k, v in inv.items() if k in ('dest', 'path', 'name', 'src', 'state', 'cron_file',
                                                                'service', 'unit', 'daemon_reload', 'enabled')}
    if isinstance(r.get('results'), list):
        out['items'] = [_slim(x, x.get('_ansible_no_log')) for x in r['results'] if isinstance(x, dict)]
    return out


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'stdout'
    CALLBACK_NAME = 'asm_json'

    def __init__(self):
        super().__init__()
        self.tasks = []
        self.cur = None
        self.play = ''
        self.progress = os.environ.get('ASM_PROGRESS')

    def _p(self, line):
        if self.progress:
            with open(self.progress, 'a') as f:
                f.write('%s %s\n' % (time.strftime('%H:%M:%S'), line))

    def v2_playbook_on_play_start(self, play):
        self.play = play.get_name()
        self._p('PLAY %s' % self.play)

    def v2_playbook_on_task_start(self, task, is_conditional):
        self.cur = {'play': self.play, 'name': task.get_name(), 'action': task.action, 'hosts': {}}
        self.tasks.append(self.cur)

    def v2_playbook_on_handler_task_start(self, task):
        self.v2_playbook_on_task_start(task, False)
        self.cur['handler'] = True

    def _record(self, result, status):
        r = result._result
        host = result._host.get_name()
        e = _slim(r, result._task.no_log or r.get('_ansible_no_log'))
        e['status'] = status
        if self.cur is not None:
            self.cur['hosts'][host] = e
        self._p('%-11s %s | %s%s' % (status, host, self.cur['name'] if self.cur else '?',
                                     (': ' + str(r.get('msg'))[:200]) if status in ('failed', 'unreachable') else ''))

    def v2_runner_on_ok(self, result):
        self._record(result, 'changed' if result._result.get('changed') else 'ok')

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self._record(result, 'ignored' if ignore_errors else 'failed')

    def v2_runner_on_unreachable(self, result):
        self._record(result, 'unreachable')

    def v2_runner_on_skipped(self, result):
        self._record(result, 'skipped')

    def v2_playbook_on_no_hosts_matched(self):
        self._p('no hosts matched')

    def v2_playbook_on_stats(self, stats):
        hosts = sorted(stats.processed.keys())
        doc = {'tasks': self.tasks, 'stats': {h: stats.summarize(h) for h in hosts}}
        self._p('DONE')
        self._display.display('ASM_JSON:' + json.dumps(doc, default=str))
