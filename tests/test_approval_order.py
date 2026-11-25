"""Apply asks before remote work and arms the guard only after a successful dry run."""

import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "server"))
import ansible_safe_mcp as asm


class ApprovalOrderTest(unittest.TestCase):
    def context(self, manager):
        value = manager.__enter__()
        self.addCleanup(manager.__exit__, None, None, None)
        return value

    def setUp(self):
        project = self.context(tempfile.TemporaryDirectory())
        self.server = asm.Server.__new__(asm.Server)
        self.server.cfg = SimpleNamespace(project=project, jobs=project, playbook_bin="test-ansible")
        os.makedirs(Path(project) / "test-job")
        self.server.audit = Mock()
        self.server.approvals = Mock()
        self.server.approvals.approved.return_value = False
        self.server._load_job = Mock(return_value={"kind": "linux", "tags": ["--tags", "web"]})
        self.server._set = Mock()
        self.server._finish = Mock()
        self.order = []
        self.ready = threading.Event()
        self.server._approve = Mock(side_effect=self.approve)
        self.server._plan = Mock(side_effect=self.plan)
        self.inventory = {"web": {"asm_kind": "linux"}}
        for symbol, value in (("check_inventory", None), ("hosts_of", self.inventory), ("load_inventory", {}),
                              ("version_hash", "approved")):
            self.context(patch.object(asm, symbol, return_value=value))
        self.launch = self.context(patch.object(asm.subprocess, "Popen", side_effect=self.start))
        self.context(patch.object(asm, "ansible_env", return_value={}))

    def approve(self, *args):
        self.assertTrue(self.ready.is_set())
        self.assertIn("Publish a config", args[-1])
        self.assertIn("Checks: ssh", args[-1])
        self.order.append("approve")
        return True, True, "test"

    def plan(self, path, limit, params, tags, *, require_success):
        self.assertTrue(require_success)
        self.assertEqual(limit, "web")
        self.assertEqual(tags, ["--tags", "web"])
        self.order.append("plan")
        return {}

    def start(self, cmd, **kwargs):
        self.order.append("run")
        wrapper = Path(cmd[1]).read_text()
        self.assertLess(wrapper.index("mureev.confirmed.arm"), wrapper.index("import_playbook:"))
        self.assertIn("mureev.confirmed.confirm", wrapper)
        # The real subprocess owns duplicates of these handles.
        kwargs["stdout"].close()
        kwargs["stderr"].close()
        return SimpleNamespace(pid=123)

    def run_flow(self):
        self.server._apply_flow("test-job", "/test.yml", "playbooks/test.yml", {}, ["web"], 60,
                                ["ssh"], [], [], "approved", self.inventory,
                                "Publish a config", self.ready)

    def test_approval_precedes_plan_and_guarded_apply(self):
        self.run_flow()
        self.assertEqual(self.order, ["approve", "plan", "run"])
        self.server._finish.assert_called_once()

    def test_declining_skips_the_remote_dry_run(self):
        self.server._approve.side_effect = None
        self.server._approve.return_value = False, True, "test"
        self.run_flow()
        self.server._plan.assert_not_called()
        self.launch.assert_not_called()
        self.assertEqual(self.server._set.call_args.kwargs["status"], "declined")

    def test_previously_approved_version_does_not_open_a_dialog(self):
        self.server.approvals.approved.return_value = True
        self.server._approve = asm.Server._approve.__get__(self.server)
        with patch.object(asm, "ask") as ask:
            self.run_flow()
        ask.assert_not_called()
        self.assertEqual(self.order, ["plan", "run"])

    def test_failed_dry_run_skips_the_guarded_apply(self):
        self.server._plan.side_effect = asm.ToolError("dry run failed")
        self.run_flow()
        self.launch.assert_not_called()
        self.assertIn("dry run failed", self.server._set.call_args.kwargs["error"])

    def test_changed_playbook_stops_before_dry_run(self):
        with patch.object(asm, "version_hash", return_value="different"):
            self.run_flow()
        self.server._plan.assert_not_called()
        self.launch.assert_not_called()
        self.assertIn("approved playbook", self.server._set.call_args.kwargs["error"])

    def test_changed_target_inventory_stops_after_dry_run(self):
        with patch.object(asm, "hosts_of", side_effect=[self.inventory, {"web": {"asm_kind": "windows"}}]):
            self.run_flow()
        self.assertEqual(self.order, ["approve", "plan"])
        self.launch.assert_not_called()

    def test_apply_rejects_nonzero_check_exit_even_with_a_json_report(self):
        server = asm.Server.__new__(asm.Server)
        server.cfg = SimpleNamespace(state=self.server.cfg.project)
        with patch.object(asm, "run_playbook", return_value=({"tasks": []}, "", 2)):
            self.assertEqual(server._plan("/test.yml", "web", {}), {})
            with self.assertRaisesRegex(asm.ToolError, "nothing was changed"):
                server._plan("/test.yml", "web", {}, require_success=True)


if __name__ == "__main__":
    unittest.main()
