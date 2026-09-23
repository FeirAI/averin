import json
import unittest

from importlib.machinery import SourceFileLoader
from pathlib import Path


gate = SourceFileLoader("go_test_gate", str(Path(__file__).with_name("check-go-test-events.py"))).load_module()
PKG = "github.com/feirai/averin/server/internal/api"


def stream(*events):
    return [json.dumps(event) for event in events]


def event(action, test, package=PKG):
    return {"Action": action, "Package": package, "Test": test}


class GoTestEventGateTest(unittest.TestCase):
    def test_pass(self):
        lines = stream(event("run", "TestRequired"), event("pass", "TestRequired"),
                       event("skip", "TestUnrelatedFixture"))
        self.assertEqual([], gate.check_events(lines, ("TestRequired",)))

    def test_root_skip(self):
        lines = stream(event("run", "TestRequired"), event("skip", "TestRequired"))
        self.assertTrue(gate.check_events(lines, ("TestRequired",)))

    def test_child_skip_even_when_parent_passes(self):
        lines = stream(event("run", "TestRequired"), event("skip", "TestRequired/setup"),
                       event("pass", "TestRequired"))
        self.assertTrue(gate.check_events(lines, ("TestRequired",)))

    def test_missing(self):
        self.assertTrue(gate.check_events([], ("TestRequired",)))

    def test_fail(self):
        lines = stream(event("run", "TestRequired"), event("fail", "TestRequired"))
        self.assertTrue(gate.check_events(lines, ("TestRequired",)))

    def test_unrelated_failure_rejected_after_required_pass(self):
        lines = stream(event("run", "TestRequired"), event("pass", "TestRequired"),
                       event("fail", "TestUnrelated"))
        self.assertTrue(gate.check_events(lines, ("TestRequired",)))

    def test_package_failure_rejected_after_required_pass(self):
        lines = stream(event("run", "TestRequired"), event("pass", "TestRequired"),
                       {"Action": "fail", "Package": PKG})
        self.assertTrue(gate.check_events(lines, ("TestRequired",)))

    def test_wrong_package(self):
        lines = stream(event("run", "TestRequired", "other/internal/api"),
                       event("pass", "TestRequired", "other/internal/api"))
        self.assertTrue(gate.check_events(lines, ("TestRequired",)))

    def test_bad_json(self):
        self.assertTrue(gate.check_events(["{bad"], ("TestRequired",)))

    def test_non_object_json(self):
        self.assertTrue(gate.check_events(["[]"], ("TestRequired",)))


if __name__ == "__main__":
    unittest.main()
