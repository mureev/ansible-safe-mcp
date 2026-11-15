#!/usr/bin/env python3
"""Unit tests for server/redact.py: what is hidden, what stays, and that hostile input stays fast (linear)."""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'server'))
import redact  # noqa: E402

fails = 0


def check(label, cond, detail=''):
    global fails
    print(('PASS ' if cond else 'FAIL ') + label)
    if not cond:
        fails += 1
        print('----\n%s\n----' % str(detail)[:1500])


s = redact.sanitize('linux', 'password=hunter2xx PasswordAuthentication=no public_key=abc123def\n'
                             'Authorization: Bearer abcdefghijk.lmn\nhttps://user:pw1234@example.org/x\n'
                             'id 3f2a1b4c-1111-2222-3333-444455556666 again 3F2A1B4C-1111-2222-3333-444455556666\n')
check('key=value secret hidden, settings and public keys kept', 'hunter2xx' not in s and
      'PasswordAuthentication=no' in s and 'public_key=abc123def' in s, s)
check('bearer token and URL password hidden', 'abcdefghijk' not in s and 'pw1234' not in s, s)
check('the same UUID gets the same pseudonym in any case', s.count('[UUID:') == 2 and
      len(set(x.split(']')[0] for x in s.split('[UUID:')[1:])) == 1, s)
pem = '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\nBBBB\n-----END OPENSSH PRIVATE KEY-----'
check('private keys hidden', 'AAAA' not in redact.sanitize('linux', pem), redact.sanitize('linux', pem))
wg = 'PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk='
check('WireGuard keys become tokens', 'yAnz5TF' not in redact.sanitize('linux', wg), redact.sanitize('linux', wg))
check('hex digests stay readable', 'a' * 40 in redact.sanitize('linux', 'sha ' + 'a' * 40))
ros = '/system scheduler add name=b on-event="/tool fetch url=\\"https://x/?p=secret\\"" interval=1d\n'
r = redact.sanitize('routeros', '# 2026-11-14 by RouterOS 7.16\n# software id = ABCD-1234\n' + ros)
check('RouterOS script bodies -> length + hash, software id -> last 4', 'secret' not in r and '<hidden:' in r and
      'ABCD-1234' not in r and '****1234' in r and 'interval=1d' in r, r)
check('a plain script name stays', 'on-event=backup' in redact.sanitize('routeros', '0 name=x on-event=backup\n'))
u = redact.sanitize('openwrt', "wireless.radio0.key='wifipass1'\n\toption key 'wifipass2'\nwireless.wg.public_key='p'")
check('uci secrets hidden, public_key kept', 'wifipass1' not in u and 'wifipass2' not in u and "public_key='p'" in u, u)
check('masking twice changes nothing', redact.sanitize('routeros', r) == r)
os.environ['ASM_MASK_DOMAINS'] = 'example.org'
d = redact.sanitize('linux', 'see https://www.example.org/very/secret/path and https://other.net/keep/this')
check('URL paths on ASM_MASK_DOMAINS hidden, others kept', '/very/secret' not in d and '/keep/this' in d, d)

for label, bad in [('a= run', 'a=' * 400000), ('one long token', 'x' * 1000000), ('quotes', '"' + 'a=b ' * 200000),
                   ('serial keys', 'serial: ' * 100000), ('script keys', 'source=' * 100000),
                   ('base64ish', 'Ab1+' * 250000), ('uci lines', "option key 'x\n" * 60000)]:
    t = time.time()
    redact.sanitize('routeros', bad)
    redact.sanitize('openwrt', bad)
    dt = time.time() - t
    check('hostile input (%s) stays fast: %.2fs' % (label, dt), dt < 8, dt)

print('redact: %d failed' % fails if fails else 'redact: all passed')
sys.exit(1 if fails else 0)
