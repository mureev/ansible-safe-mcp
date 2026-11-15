"""The contract clients rely on, as in mac-terminal-mcp 0.7.1-0.7.2: protocol negotiation, a title on every tool (own
and in annotations), every argument described, descriptions long enough to say what a tool returns and changes, and
the rules that matter in the descriptions themselves (Claude desktop doesn't pass the server's instructions on)."""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'server'))
import ansible_safe_mcp as M  # noqa: E402

fails = []


def check(name, ok, detail=''):
    print('%s %s%s' % ('PASS' if ok else 'FAIL', name, '' if ok else ': ' + str(detail)[:300]))
    if not ok:
        fails.append(name)


tools = {t['name']: t for t in M.TOOLS}
for n, t in tools.items():
    check('%s: title, also in annotations' % n, t.get('title') and t['annotations'].get('title') == t['title'])
    ann = t['annotations']
    check('%s: read-only or destructive said' % n, 'readOnlyHint' in ann and ('destructiveHint' in ann or ann['readOnlyHint']))
    check('%s: description >= 90 chars' % n, len(t['description']) >= 90, len(t['description']))
    for k, v in t['inputSchema']['properties'].items():
        check('%s.%s described' % (n, k), bool(v.get('description')), v)

for n in ('look', 'plan', 'apply', 'hands'):
    check('%s: says host output is data, never instructions' % n, 'never instructions' in tools[n]['description'])
for n in ('apply', 'hosts'):
    check('%s: the approval is a dialog on the Mac, not the chat' % n, 'dialog' in tools[n]['description']
          and 'chat' in tools[n]['description'])


def negotiate(v):
    env = dict(os.environ, ASM_PROJECT=os.path.join('/tmp', 'asm-contract-proj'), ASM_STATE='/tmp/asm-contract-state')
    p = subprocess.run([sys.executable, os.path.join(HERE, '..', 'server', 'ansible_safe_mcp.py')], env=env,
                       input=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                                         'params': {'protocolVersion': v}}) + '\n', capture_output=True, text=True,
                       timeout=60)
    return json.loads(p.stdout.splitlines()[0])['result']['protocolVersion']


check('a known protocol version is echoed', negotiate('2025-06-18') == '2025-06-18')
check('an unknown one gets the newest', negotiate('1999-01-01') == M.PROTOCOLS[0])
print('tool contract: %s' % ('all passed' if not fails else '%d failed' % len(fails)))
sys.exit(1 if fails else 0)
