#!/usr/bin/env python3
"""End-to-end test of the MCP server over stdio, against a disposable SSH host on 127.0.0.1:2222 with accounts
`look` (no sudo) and `change` (sudo) that accept the key in $ASM_TEST_KEY. Destructive to that host."""
import json, os, shutil, subprocess, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
W = '/tmp/asm-e2e'
shutil.rmtree(W, ignore_errors=True)
os.makedirs(W)
LOG = os.path.join(W, 'asked.log')
with open(os.path.join(W, 'approver.py'), 'w') as f:
    f.write('import json,os,sys\nr=json.load(sys.stdin)\nopen(%r,"a").write(json.dumps(r)+"\\n")\n'
            'sys.exit(1 if os.path.exists(%r) else 0)\n' % (LOG, os.path.join(W, 'DENY')))
env = dict(os.environ, ASM_PROJECT=W + '/project', ASM_STATE=W + '/state', ASM_TEST_SHORT_WINDOWS='1',
           ASM_APPROVER='%s %s/approver.py' % (sys.executable, W))
srv = subprocess.Popen([sys.executable, os.path.join(ROOT, 'server', 'ansible_safe_mcp.py')], env=env,
                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
n = 0
passed = 0


def rpc(method, params=None):
    global n
    n += 1
    srv.stdin.write(json.dumps({'jsonrpc': '2.0', 'id': n, 'method': method, 'params': params or {}}) + '\n')
    srv.stdin.flush()
    while True:
        msg = json.loads(srv.stdout.readline())
        if msg.get('id') == n:
            return msg


def tool(_tool, **args):
    r = rpc("tools/call", {"name": _tool, "arguments": args})["result"]
    return r['content'][0]['text'], r['isError']


def asked():
    return sum(1 for _ in open(LOG)) if os.path.exists(LOG) else 0


def check(label, cond, detail=''):
    global passed
    print(('PASS ' if cond else 'FAIL ') + label)
    if not cond:
        print('----\n' + detail + '\n----')
        srv.kill()
        sys.exit(1)
    passed += 1


init = rpc('initialize', {'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {'name': 't'}})
check('initialize', init['result']['serverInfo']['name'] == 'ansible-safe-mcp', json.dumps(init))
names = [t['name'] for t in rpc('tools/list')['result']['tools']]
check('8 tools', names == ['hosts', 'look', 'playbook', 'plan', 'apply', 'hands', 'job', 'status'], str(names))

t, e = tool('hosts', action='add', name='box', address='127.0.0.1', port=2222, look_user='look',
            change_user='change', key_file=os.environ.get('ASM_TEST_KEY', '/root/.ssh/asm_test'), groups=['web'])
check('add host: asked once, both accounts work', not e and asked() == 1 and 'look account: logs in' in t
      and 'change account: logs in and can sudo' in t, t)
t, e = tool('hosts', action='add', name='localhost', address='127.0.0.1', look_user='a', change_user='b')
check('refuse a host named localhost', e, t)

t, e = tool('look', hosts='box', read='overview')
check('look overview', not e and 'load average' in t, t)
t, e = tool('look', hosts='box', command="echo '{{ 7*7 }}'; id -un; sudo -n true 2>&1 | head -1")
check('look command: not templated, runs as look, no sudo', '{{ 7*7 }}' in t and '\nlook' in t and
      'password' in t, t)
t, e = tool('look', hosts='localhost', read='overview')
check('look refuses localhost', e, t)

bad = """- hosts: box
  tasks:
    - ansible.builtin.shell: cat ~/.ssh/id_ed25519
      delegate_to: localhost
    - ansible.builtin.copy:
        content: "{{ lookup('pipe', 'id') }}"
        dest: /tmp/x
    - ansible.builtin.copy: {src: /Users/me/.ssh/id_rsa, dest: /tmp/k}
    - ansible.builtin.command: id
      check_mode: false
      vars:
        ansible_connection: local
"""
t, e = tool('playbook', action='write', path='playbooks/bad.yml', content=bad)
check('lint refuses delegate_to, lookup, local src, check_mode:false, connection var',
      all(x in t for x in ('delegate_to', 'lookups run', 'reads', 'check_mode', 'ansible_connection')), t)
t, e = tool('plan', playbook='playbooks/bad.yml')
check('plan refuses while lint refuses', e and 'Lint refuses' in t, t)
tool('playbook', action='delete', path='playbooks/bad.yml')
t, e = tool('playbook', action='write', path='playbooks/library/x.py', content='x')
check('refuse plugin folders', e, t)

motd = """- hosts: web
  become: true
  gather_facts: false
  vars:
    asm_params:
      message: {type: str, pattern: '^[A-Za-z0-9 .!-]{1,80}$'}
  tasks:
    - name: write the banner
      ansible.builtin.copy:
        dest: /etc/asm-motd
        content: "{{ message }}\\n"
"""
t, e = tool('playbook', action='write', path='playbooks/motd.yml', content=motd)
check('write a clean playbook with params', not e and 'Lint: clean' in t and 'Syntax: ok' in t and 'message' in t, t)
t, e = tool('plan', playbook='playbooks/motd.yml', params={'message': 'hello'})
check('plan: shows the diff, not approved yet', not e and '+hello' in t and 'not approved yet' in t
      and '/etc/asm-motd' in t, t)
check('plan changed nothing', not os.path.exists('/etc/asm-motd'))
t, e = tool('apply', playbook='playbooks/motd.yml', params={'message': 'hello'}, window='30s')
check('apply: asks once, confirms', not e and asked() == 2 and 'CONFIRMED' in t and
      open('/etc/asm-motd').read() == 'hello\n', t)
t, e = tool('apply', playbook='playbooks/motd.yml', params={'message': 'world'}, window='30s')
check('apply again with a new param value: no question', not e and asked() == 2 and 'without asking' in t and
      open('/etc/asm-motd').read() == 'world\n', t)
t, e = tool('apply', playbook='playbooks/motd.yml', params={'message': '{{ lookup("pipe","id") }}'})
check('params with braces refused', e, t)
t, e = tool('apply', playbook='playbooks/motd.yml', params={'message': 'x', 'other': 1})
check('undeclared params refused', e and 'not declared' in t, t)
tool('playbook', action='write', path='playbooks/motd.yml', content=motd.replace('write the banner', 'write it'))
open(os.path.join(W, 'DENY'), 'w').close()
t, e = tool('apply', playbook='playbooks/motd.yml', params={'message': 'denied'})
check('edited playbook asks again; a decline changes nothing', asked() == 3 and 'declined' in t and
      open('/etc/asm-motd').read() == 'world\n', t)
os.remove(os.path.join(W, 'DENY'))

failing = """- hosts: box
  become: true
  gather_facts: false
  tasks:
    - ansible.builtin.copy: {dest: /etc/asm-half, content: "half\\n"}
    - ansible.builtin.command: /bin/false
"""
tool('playbook', action='write', path='playbooks/failing.yml', content=failing)
t, e = tool('apply', playbook='playbooks/failing.yml', window='60s')
check('a change that fails halfway is reverted at once', 'REVERTED' in t and not os.path.exists('/etc/asm-half'), t)

lockout = """- hosts: box
  become: true
  gather_facts: false
  tasks:
    - name: deny everyone
      ansible.builtin.copy: {dest: /etc/ssh/sshd_config.d/50-lock.conf, content: "DenyUsers change look\\n"}
    - name: reload sshd
      ansible.builtin.command: service ssh reload
"""
tool('playbook', action='write', path='playbooks/lockout.yml', content=lockout)
t0 = time.time()
t, e = tool('apply', playbook='playbooks/lockout.yml', window='20s')
check('lockout: NOT CONFIRMED', 'NOT CONFIRMED' in t and os.path.exists('/etc/ssh/sshd_config.d/50-lock.conf'), t)
time.sleep(max(0, 26 - (time.time() - t0)))
check('lockout: the host put itself back', not os.path.exists('/etc/ssh/sshd_config.d/50-lock.conf'))
t, e = tool('look', hosts='box', read='guard')
check('look guard reports the revert', 'reverted' in t and '(timeout)' in t, t)
t, e = tool('hands', hosts='box', why='Clear a stale lock file', steps=['rm -f /etc/asm-stale.lock'])
check('hands: refuses to run blind without paths', 'did not run it' in t and 'oneoffs/' in t, t)
open('/etc/asm-stale.lock', 'w').write('x')
t, e = tool('hands', hosts='box', why='Clear a stale lock file', steps=['rm -f /etc/asm-stale.lock'],
            paths=['/etc/asm-stale.lock'], window='60s')
check('hands: asks, runs guarded, confirms', 'CONFIRMED' in t and not os.path.exists('/etc/asm-stale.lock'), t)
t, e = tool('hands', hosts='box', why='Break and notice', steps=['echo broken > /etc/asm-hands', 'false'],
            paths=['/etc/asm-hands'], window='60s')
check('hands: a failing step is undone at once', 'REVERTED' in t and not os.path.exists('/etc/asm-hands'), t)
inv = W + '/project/inventory/hosts.yml'
orig = open(inv).read()
open(inv, 'w').write(orig.replace('asm_kind: linux', 'asm_kind: linux\n      ansible_connection: local'))
t, e = tool('look', hosts='box', read='overview')
check('a hand-added connection variable in the inventory stops everything', e and 'ansible_connection' in t, t)
open(inv, 'w').write(orig)
t, e = tool('status', hosts='box')
check('status', not e and 'approved playbook versions: 5' in t, t)
# ---- RouterOS, against the fake console (rlook/rchange on the same sshd; see tests/fakeros)
if os.path.exists('/usr/local/bin/fakeros'):
    shutil.rmtree('/tmp/fakeros', ignore_errors=True)
    os.makedirs('/tmp/fakeros', mode=0o777)
    os.chmod('/tmp/fakeros', 0o777)
    with open('/tmp/fakeros/config', 'w') as f:
        f.write('/ip address add address=192.168.88.1/24 interface=bridge\n')
    os.chmod('/tmp/fakeros/config', 0o666)
    t, e = tool('hosts', action='add', name='rtr', address='127.0.0.1', port=2222, kind='routeros', look_user='rlook',
                change_user='rchange', key_file=os.environ.get('ASM_TEST_KEY', '/root/.ssh/asm_test'))
    check('routeros: add host, both accounts', not e and 'change account: logs in' in t, t)
    t, e = tool('look', hosts='rtr', command='/system identity print')
    check('routeros: look', 'name: fake' in t, t)
    good = """- hosts: rtr
  gather_facts: false
  tasks:
    - name: add a route
      ansible.builtin.raw: /add /ip route add dst-address=10.9.0.0/16 gateway=192.168.88.2
"""
    tool('playbook', action='write', path='playbooks/rtr-route.yml', content=good)
    t, e = tool('plan', playbook='playbooks/rtr-route.yml')
    check('routeros: plan lists the commands', 'under Safe Mode' in t and '10.9.0.0/16' in t, t)
    t, e = tool('apply', playbook='playbooks/rtr-route.yml', window='60s', checks=['/ping 1.1.1.1 count=1'])
    check('routeros: confirmed under Safe Mode, export diff shown', 'CONFIRMED' in t and '+/ip route add' in t and
          '10.9.0.0' in open('/tmp/fakeros/config').read(), t)
    lock = """- hosts: rtr
  gather_facts: false
  tasks:
    - ansible.builtin.raw: /add /ip service set ssh address=10.99.0.0/24
    - ansible.builtin.raw: /lock
"""
    tool('playbook', action='write', path='playbooks/rtr-lock.yml', content=lock)
    t, e = tool('apply', playbook='playbooks/rtr-lock.yml', window='60s')
    cfg = open('/tmp/fakeros/config').read()
    check('routeros: lockout -> fresh login fails -> undone through the held session',
          'REVERTED' in t and '10.99.0.0' not in cfg and not os.path.exists('/tmp/fakeros/locked'), t + '\n' + cfg)
    bad = """- hosts: rtr
  gather_facts: false
  tasks:
    - ansible.builtin.raw: /add /ip dns set servers=9.9.9.9
    - ansible.builtin.raw: /ip dns sett servers=1.1.1.1
"""
    tool('playbook', action='write', path='playbooks/rtr-bad.yml', content=bad)
    t, e = tool('apply', playbook='playbooks/rtr-bad.yml', window='60s')
    check('routeros: a bad command undoes the whole change', 'REVERTED' in t and
          '9.9.9.9' not in open('/tmp/fakeros/config').read(), t)

lines = open(W + '/state/audit.jsonl').read().splitlines()
ok = True
prev = '0' * 64
import hashlib
for line in lines:
    r = json.loads(line)
    h = r.pop('hash')
    ok = ok and r['prev'] == prev and hashlib.sha256(json.dumps(r, sort_keys=True).encode()).hexdigest() == h
    prev = h
check('audit log chain verifies (%d entries)' % len(lines), ok)
srv.kill()
print('e2e server: %d passed' % passed)
