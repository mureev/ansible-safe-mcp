# Tests

Both suites need a disposable Linux box they may break, with sshd on 127.0.0.1:2222 and the key in `$ASM_TEST_KEY`
(default `/root/.ssh/asm_test`) accepted by these accounts:

| Account | Shell | Sudo |
|---|---|---|
| `look` | bash | none |
| `change` | bash | `NOPASSWD: ALL` |
| `rlook`, `rchange` | `ForceCommand /usr/local/bin/fakeros` (copy `tests/fakeros` there) | none |
| `owrt` | `SetEnv R=/tmp/fakeowrt`, `ForceCommand /usr/local/bin/owrt-shell` (copy `tests/owrt-shell` there, `tests/fake-uci` to `/usr/local/bin/uci` and `tests/fake-sysupgrade` to `/usr/local/bin/sysupgrade`) | none |

`fakeros` is a small stand-in for a RouterOS console: exec commands change `/tmp/fakeros/config`; an interactive
session has Safe Mode (Ctrl+X), Ctrl+D undoes, `/quit` keeps, an abnormal end undoes; `/lock` refuses every new login
until a revert. It tests the server's handling of Safe Mode, not RouterOS itself: run a real change on a spare router.

- `collections/ansible_collections/mureev/confirmed/tests/e2e/run.sh` (with `ANSIBLE_CONFIG` pointing at an inventory
  for the box): the collection.
- `python3 tests/e2e_server.py`: the MCP server over stdio, 62 checks.
