"""Masking and redaction of host output before it reaches the model (ported from infra-bridge's mask.js and
redact.js).

Host output is untrusted and attacker-influenced (log lines, file names), so every pattern here runs in linear time:
quantifiers next to alternations are bounded, key names are matched with a bounded capture and tested separately, and
input is processed in bounded chunks. Two layers:

  mask_for(kind, text)  kind-specific: RouterOS script bodies -> length + hash, DoH and own-domain URL paths -> a hash,
                        uci secret options -> <hidden>, hardware serials -> their last 4 characters
  redact(text)          generic backstop: private keys, bearer tokens, URL passwords, key=value secrets, WireGuard
                        keys, UUIDs and opaque tokens -> stable pseudonyms (distinct values stay distinguishable)

sanitize(kind, text) applies both. ASM_MASK_DOMAINS (comma-separated, e.g. "example.org") names domains whose URL
paths are hidden too (a household's secret paths live there).
"""
from __future__ import annotations

import hashlib
import os
import re

MAX_INPUT = 1024 * 1024
CHUNK = 16 * 1024
MAX_VALUE = 256 * 1024


def _tag(s):
    return hashlib.sha256(s.encode('utf-8', 'surrogatepass')).hexdigest()[:6]


def _short(s):
    return hashlib.sha256(s.encode('utf-8', 'surrogatepass')).hexdigest()[:8]


ANSI = re.compile(r'\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]')
CTRL = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')

# Tested against a captured key name (<= 64 chars) only.
SECRET_KEY = re.compile(r'pass(?:word|wd|phrase)?|secret|token|api[_-]?key|access[_-]?key|priv(?:ate)?[_-]?key|'
                        r'pre-?shared[_-]?key|credential|claim|cookie|session[_-]?id|short[_-]?ids?|psk|r[01]kh|'
                        r'(?:^|[_.-])(?:pin|auth|key[0-9]?|salt)(?:$|[_.-])', re.I)
PUBLIC_KEY = re.compile(r'(?:^|[_.-])public[_-]?key$', re.I)
MASKED = re.compile(r'^(?:<hidden>|\[REDACTED\])$')
SETTING = re.compile(r'^(?:yes|no|true|false|on|off|enabled?|disabled?|none|auto|[01])$', re.I)


def _keep(key, v):
    return bool(PUBLIC_KEY.search(key) or MASKED.match(v) or SETTING.match(v))


PEM = re.compile(r'-----BEGIN ([A-Z0-9 ]{0,40})PRIVATE KEY-----[\s\S]*?(?:-----END \1PRIVATE KEY-----|$)')
RULES = [
    (re.compile(r'\b(Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=-]{8,}'), r'\1 [REDACTED]'),
    (re.compile(r'(\b[a-z][a-z0-9+.-]{0,20}://[^\s:@/]{1,256}:)[^\s@/]{1,256}@', re.I), r'\1[REDACTED]@'),
    (re.compile(r'("auth"\s*:\s*")[^"]{1,8192}"'), r'\1[REDACTED]"'),
    (re.compile(r'\b\d{8,10}:[A-Za-z0-9_-]{35}\b'), '[REDACTED TELEGRAM TOKEN]'),
    (re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'), '[REDACTED AWS KEY]'),
    (re.compile(r'\bgh[pousr]_[A-Za-z0-9]{30,}\b'), '[REDACTED GITHUB TOKEN]'),
    (re.compile(r'\bclaim-[A-Za-z0-9]{10,}\b'), '[REDACTED PLEX CLAIM]'),
    # HTTP-header style, incl. nginx: "X-Api-Key: v" / "proxy_set_header X-Api-Key v;"
    (re.compile(r'\b(X-[A-Za-z0-9-]{0,40}(?:key|token|auth[a-z]{0,12}|secret|password)[A-Za-z0-9-]{0,20})'
                r'(\s*:\s*|\s+)([^\s;"\']{4,})', re.I), r'\1\2[REDACTED]'),
]

# key=value, key: value, "key": "value"; the value stops at "=" so comment="password=x" reaches the inner key
KV = re.compile(r'(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]{1,64})(["\']?[ \t]*[:=][ \t]*["\']?)([^\s"\',;{}\[\]=]{3,})')
KV_DQ = re.compile(r'(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]{1,64})("?[ \t]*[:=][ \t]*)"((?:[^"\\\n]|\\.){1,4096})"')
KV_SQ = re.compile(r"(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]{1,64})([ \t]*=[ \t]*)'([^'\n]{1,4096})'")
UCI_OPT = re.compile(r'''^([ \t]*(?:option|list)[ \t]+)([A-Za-z0-9_]{1,64})([ \t]+)('[^'\n]{0,4096}'|"[^"\n]{0,4096}"|[^\s'"]{1,4096})''',
                     re.M)
WG_KEY = re.compile(r'(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=(?![A-Za-z0-9+/=])')
UUID = re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')
OPAQUE_URL = re.compile(r'(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{32,}(?![A-Za-z0-9_-])')
OPAQUE_B64 = re.compile(r'(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])')


def _mixed(m):
    return bool(re.search('[A-Z]', m) and re.search('[a-z]', m) and re.search('[0-9]', m))


def _replace_kv(s):
    """key=value pairs. A pair whose key isn't secret is not consumed: its value is scanned again (it may hold a pair
    itself, RouterOS: comment="password=x"). Values stop at "=", so each character is rescanned a bounded number of
    times and this stays linear."""
    out = []
    last = 0
    pos = 0
    while True:
        m = KV.search(s, pos)
        if not m:
            break
        key, sep, value = m.group(1), m.group(2), m.group(3)
        if (SECRET_KEY.search(key) and not value.startswith('[REDACTED') and not re.match(r'^<hidden[>:]$', value)
                and not PUBLIC_KEY.search(key) and not SETTING.match(value)):
            out.append(s[last:m.start()] + key + sep + '[REDACTED]')
            last = m.end()
            pos = m.end()
        else:
            pos = m.start() + len(key) + len(sep)
            if pos <= m.start():
                pos = m.start() + 1
    out.append(s[last:])
    return ''.join(out)


def _redact_chunk(s):
    for rx, rep in RULES:
        s = rx.sub(rep, s)
    s = KV_DQ.sub(lambda m: '%s%s"[REDACTED]"' % (m.group(1), m.group(2))
                  if SECRET_KEY.search(m.group(1)) and not _keep(m.group(1), m.group(3)) else m.group(0), s)
    s = KV_SQ.sub(lambda m: "%s%s'[REDACTED]'" % (m.group(1), m.group(2))
                  if SECRET_KEY.search(m.group(1)) and not _keep(m.group(1), m.group(3)) else m.group(0), s)
    s = UCI_OPT.sub(lambda m: "%s%s%s'[REDACTED]'" % (m.group(1), m.group(2), m.group(3))
                    if SECRET_KEY.search(m.group(2)) and not _keep(m.group(2), m.group(4).strip('\'"'))
                    else m.group(0), s)
    s = _replace_kv(s)
    s = WG_KEY.sub(lambda m: '[TOKEN:%s]' % _tag(m.group(0)), s)
    s = UUID.sub(lambda m: '[UUID:%s]' % _tag(m.group(0).lower()), s)
    s = OPAQUE_URL.sub(lambda m: '[TOKEN:%s]' % _tag(m.group(0)) if _mixed(m.group(0)) else m.group(0), s)
    s = OPAQUE_B64.sub(lambda m: '[TOKEN:%s]' % _tag(m.group(0)) if _mixed(m.group(0)) else m.group(0), s)
    return s


def _chunks(s):
    i = 0
    n = len(s)
    while i < n:
        end = min(i + CHUNK, n)
        if end < n:
            nl = s.rfind('\n', i, end)
            if nl > i:
                end = nl + 1
        yield s[i:end]
        i = end


def redact(text):
    if text is None:
        return ''
    s = str(text)
    note = ''
    if len(s) > MAX_INPUT:
        note = '\n[... %d chars dropped before redaction ...]' % (len(s) - MAX_INPUT)
        s = s[:MAX_INPUT]
    s = CTRL.sub('', ANSI.sub('', s.replace('\r\n', '\n')))
    s = PEM.sub('[REDACTED PRIVATE KEY]', s)  # PEM blocks may span chunks: whole string first (linear)
    return ''.join(_redact_chunk(c) for c in _chunks(s)) + note


# ------------------------------------------------------------------------------------------------ kind masking

ROS_SCRIPT_KEYS = {'source', 'on-event', 'up-script', 'down-script', 'test-script', 'on-up', 'on-down',
                   'lease-script', 'script', 'on-login', 'on-logout'}
ROS_KEY = re.compile(r'(^|[\s;])([a-z][a-z-]{0,20})=')
PLAIN_NAME = re.compile(r'^[A-Za-z0-9_.-]{1,64}$')
NEXT_PROPERTY = re.compile(r'[ \t]+(?:[a-z][a-z0-9.-]{0,40}=|![a-z][a-z0-9.-]{0,40}(?!\S))')
RECORD_START = re.compile(r'(?:[ \t]{0,8}\d{1,6}(?=\s|$)|(?:\d{4}-\d\d-\d\d |[a-z]{3}/\d\d(?:/\d{4})? )?'
                          r'\d\d:\d\d:\d\d |== |!! failed: |### |--- )')


def join_export_lines(text):
    """/export wraps a long value with a trailing backslash; join those lines (each line looked at once)."""
    out = []
    acc = None
    for raw in str(text or '').replace('\r', '').split('\n'):
        piece = raw if acc is None else raw.lstrip()
        if piece.endswith('\\') and not piece.endswith('\\\\'):
            if acc is None:
                acc = []
            acc.append(piece[:-1])
            continue
        out.append(piece if acc is None else ''.join(acc) + piece)
        acc = None
    if acc is not None:
        out.append(''.join(acc) + '\\')
    return '\n'.join(out)


def is_routeros_export(text):
    return bool(re.search(r'^#[^\n]*by RouterOS', str(text or '')[:600], re.M))


def _value_end(s, i, quoted=True):
    limit = min(len(s), i + MAX_VALUE)
    if s.startswith('<hidden:', i):
        j = s[i:i + 80].find('>')
        return i if j < 0 else i + j + 1
    if quoted and i < len(s) and s[i] == '"':
        j = i + 1
        while j < limit:
            c = s[j]
            if c == '\\':
                j += 2
            elif c == '"':
                return j + 1
            else:
                j += 1
        return limit
    j = i
    while j < limit and not s[j].isspace():
        j += 1
    return j


def _blank(c):
    return c in ' \t\r'


def _line_end(s, i):
    n = s.find('\n', i)
    return len(s) if n < 0 else n


def _ends_cleanly(s, end, printed):
    if NEXT_PROPERTY.match(s, end):
        return True
    j = end
    while j < len(s) and _blank(s[j]):
        j += 1
    if j < len(s) and s[j] != '\n':
        return False
    if not printed:
        return True
    while j < len(s) and (_blank(s[j]) or s[j] == '\n'):
        j += 1
    if j >= len(s):
        return True
    return bool(RECORD_START.match(s, s.rfind('\n', 0, j) + 1))


def _cut_end(s, end, printed):
    stop = _line_end(s, end)
    if printed:
        while stop < len(s):
            if RECORD_START.match(s, stop + 1):
                break
            stop = _line_end(s, stop + 1)
    while stop > end and (_blank(s[stop - 1]) or s[stop - 1] == '\n'):
        stop -= 1
    return stop


def mask_routeros(text, printed=False):
    """Script values -> '<hidden: N chars, sha256 ...>' (a plain name such as on-event=backup stays)."""
    s = str(text or '')
    out = []
    last = 0
    pos = 0
    while True:
        m = ROS_KEY.search(s, pos)
        if not m:
            break
        pos = m.end()
        if m.group(2) not in ROS_SCRIPT_KEYS:
            continue
        start = m.end()
        end = _value_end(s, start, not printed)
        value = s[start:end]
        clean = _ends_cleanly(s, end, printed)
        masked = value.startswith('<hidden:') and value.endswith('>')
        if clean and (masked or not value or PLAIN_NAME.match(value)):
            pos = max(end, pos)
            continue
        stop = end
        what = 'chars'
        if not clean or printed or not value.startswith('"'):
            stop = _cut_end(s, end, printed)
            if stop > end:
                what = 'chars to the next item' if '\n' in s[end:stop] else 'chars to end of line'
        hidden = s[start:stop]
        out.append(s[last:start] + '<hidden: %d %s, sha256 %s>' % (len(hidden), what, _short(hidden)))
        last = stop
        pos = max(stop, pos)
    out.append(s[last:])
    return mask_urls(''.join(out))


def _own_domains():
    return [d.strip().lower().rstrip('.') for d in os.environ.get('ASM_MASK_DOMAINS', '').split(',') if d.strip()]


DOH_VALUE = re.compile(r'(use-doh-server[ \t]{0,8}[=:][ \t]{0,8}(?:\\?")?)([a-z][a-z0-9+.-]{0,15}://[^\s"\'\\/<>?#]{1,255})'
                       r'(/[^\s"\'\\<>?#]{0,4096})?', re.I)


def _hash_path(p):
    return (p or '') if not p or p == '/' else '/<path sha256:%s>' % _short(p)


def mask_urls(text):
    """A DoH server's path (use-doh-server's value) and any URL path on ASM_MASK_DOMAINS -> a short hash."""
    s = DOH_VALUE.sub(lambda m: m.group(1) + m.group(2) + _hash_path(m.group(3)), str(text or ''))
    for d in _own_domains():
        rx = re.compile(r'\b(https?://(?:[a-z0-9-]{1,63}\.){0,8}%s\.?(?![a-z0-9.-])(?::\d{1,5})?)(/[^\s"\'\\<>?#]{0,4096})?'
                        % re.escape(d), re.I)
        s = rx.sub(lambda m: m.group(1) + _hash_path(m.group(2)), s)
    return s


SERIAL_KEY = re.compile(r'(?<![A-Za-z0-9_-])((?:hardware[ _-]?)?serial(?:[ _-]?(?:number|no\.?|num))?(?: \([a-z ]{1,20}\))?|'
                        r'id_serial(?:_short)?|software[ _-]id)("?[ \t]{0,16}[:=][ \t]{0,16})', re.I)
SERIAL_PLACEHOLDER = re.compile(r'^(?:not specified|not available|not applicable|none|n/a|unknown|default string|'
                                r'to be filled by o\.e\.m\.?|system serial number|chassis serial number|0+)$', re.I)
MAX_SERIAL = 128


def _mask_serial(v):
    return v if SERIAL_PLACEHOLDER.match(v) else '****' + (v[-4:] if len(v) > 4 else '')


def mask_serials(text):
    s = str(text or '')
    out = []
    last = 0
    pos = 0
    while True:
        m = SERIAL_KEY.search(s, pos)
        if not m:
            break
        i = m.end()
        quoted = i < len(s) and s[i] == '"'
        if quoted:
            i += 1
        end = i
        if quoted:
            def stop(c):
                return c in '"\n'
        elif '=' in m.group(2):
            def stop(c):
                return c.isspace()
        else:
            def stop(c):
                return c == '\n'
        while end < len(s) and end - i < MAX_SERIAL and not stop(s[end]):
            end += 1
        v_end = end
        while v_end > i and _blank(s[v_end - 1]):
            v_end -= 1
        if v_end > i:
            out.append(s[last:i] + _mask_serial(s[i:v_end]))
            last = v_end
        pos = max(end, m.end())
    out.append(s[last:])
    return ''.join(out)


UCI_SECRET = re.compile(r'key|psk|pass|secret|token|kh')
UCI_SHOW = re.compile(r'^([^=\n]{1,200}\.)([^.=\n]{1,64})=([^\n]*)$', re.M)
UCI_EXPORT = re.compile(r'^([ \t]*(?:option|list)[ \t]+)([A-Za-z0-9_]{1,64})([ \t]+)([^\n]*)$', re.M)


def mask_uci(text):
    s = UCI_SHOW.sub(lambda m: "%s%s='<hidden>'" % (m.group(1), m.group(2))
                     if UCI_SECRET.search(m.group(2)) and m.group(2) != 'public_key' and m.group(3) != "'<hidden>'"
                     else m.group(0), str(text or ''))
    return UCI_EXPORT.sub(lambda m: "%s%s%s'<hidden>'" % (m.group(1), m.group(2), m.group(3))
                          if UCI_SECRET.search(m.group(2)) and m.group(2) != 'public_key' and m.group(4) != "'<hidden>'"
                          else m.group(0), s)


def mask_routeros_output(text):
    s = str(text or '')
    return mask_routeros(join_export_lines(s)) if is_routeros_export(s) else mask_routeros(s, printed=True)


def mask_for(kind, text, output=True):
    if kind == 'routeros':
        return mask_serials(mask_routeros_output(text) if output else mask_routeros(text))
    if kind == 'openwrt':
        return mask_serials(mask_urls(mask_uci(text)))
    return mask_serials(mask_urls(text))


def sanitize(kind, text):
    return redact(mask_for(kind, text))
