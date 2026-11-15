"""A project folder inside an existing git repo gets no nested .git; one outside gets its own."""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'server'))

fails = 0
with tempfile.TemporaryDirectory() as t:
    outer = os.path.join(t, 'infra')
    os.makedirs(os.path.join(outer, 'ansible'))
    subprocess.run(['git', 'init', '-q'], cwd=outer, check=True)
    for proj, want_git in ((os.path.join(outer, 'ansible'), False), (os.path.join(t, 'standalone'), True)):
        env = dict(os.environ, ASM_PROJECT=proj, ASM_STATE=os.path.join(t, 'state-' + os.path.basename(proj)))
        code = 'import ansible_safe_mcp as m; c = m.Config(); c.setup()'
        subprocess.run([sys.executable, '-c', code], env=env, cwd=os.path.join(HERE, '..', 'server'), check=True,
                       capture_output=True)
        has = os.path.isdir(os.path.join(proj, '.git'))
        ok = has == want_git
        fails += not ok
        print('%s %s: own .git %s' % ('PASS' if ok else 'FAIL', os.path.basename(proj), has))
print('project-in-repo: %s' % ('all passed' if not fails else '%d failed' % fails))
sys.exit(1 if fails else 0)
