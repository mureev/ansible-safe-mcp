#!/bin/sh
# End-to-end tests against a disposable SSH host (see the inventory in $ANSIBLE_CONFIG). Destructive to that host.
set -e
cd "$(dirname "$0")"
ansible-playbook good.yml
ansible-playbook double.yml
mkdir -p /etc/asm-dir && echo orig > /etc/asm-dir/a && rm -f /etc/asm-dir/b
ansible-playbook checkfail.yml && { echo "checkfail should fail"; exit 1; } || true
test "$(cat /etc/asm-dir/a)" = orig && test ! -e /etc/asm-dir/b && test ! -e /etc/asm-cf.conf
ansible-playbook lockout.yml && { echo "lockout should not confirm"; exit 1; } || true
sleep 18
grep -q "lock1 (timeout)" /var/lib/ansible-confirmed/last && test ! -e /etc/ssh/sshd_config.d/50-lock.conf
echo "e2e: all passed"
