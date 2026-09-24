import json
import unittest

from importlib.machinery import SourceFileLoader
from pathlib import Path


gate = SourceFileLoader("go_test_gate", str(Path(__file__).with_name("check-go-test-events.py"))).load_module()
PKG = "github.com/feirai/averin/server/internal/api"
STORE_PKG = "github.com/feirai/averin/server/internal/store"
REQUIRED = f"{PKG}:TestRequired"


def stream(*events):
    return [json.dumps(event) for event in events]


def event(action, test, package=PKG):
    return {"Action": action, "Package": package, "Test": test}


class GoTestEventGateTest(unittest.TestCase):
    def test_pass(self):
        lines = stream(event("run", "TestRequired"), event("pass", "TestRequired"),
                       event("skip", "TestUnrelatedFixture"))
        self.assertEqual([], gate.check_events(lines, (REQUIRED,)))

    def test_root_skip(self):
        lines = stream(event("run", "TestRequired"), event("skip", "TestRequired"))
        self.assertTrue(gate.check_events(lines, (REQUIRED,)))

    def test_child_skip_even_when_parent_passes(self):
        lines = stream(event("run", "TestRequired"), event("skip", "TestRequired/setup"),
                       event("pass", "TestRequired"))
        self.assertTrue(gate.check_events(lines, (REQUIRED,)))

    def test_missing(self):
        self.assertTrue(gate.check_events([], (REQUIRED,)))

    def test_fail(self):
        lines = stream(event("run", "TestRequired"), event("fail", "TestRequired"))
        self.assertTrue(gate.check_events(lines, (REQUIRED,)))

    def test_unrelated_failure_rejected_after_required_pass(self):
        lines = stream(event("run", "TestRequired"), event("pass", "TestRequired"),
                       event("fail", "TestUnrelated"))
        self.assertTrue(gate.check_events(lines, (REQUIRED,)))

    def test_package_failure_rejected_after_required_pass(self):
        lines = stream(event("run", "TestRequired"), event("pass", "TestRequired"),
                       {"Action": "fail", "Package": PKG})
        self.assertTrue(gate.check_events(lines, (REQUIRED,)))

    def test_wrong_package(self):
        lines = stream(event("run", "TestRequired", "other/internal/api"),
                       event("pass", "TestRequired", "other/internal/api"))
        self.assertTrue(gate.check_events(lines, (REQUIRED,)))

    def test_bad_json(self):
        self.assertTrue(gate.check_events(["{bad"], (REQUIRED,)))

    def test_non_object_json(self):
        self.assertTrue(gate.check_events(["[]"], (REQUIRED,)))

    def test_same_name_in_wrong_package(self):
        lines = stream(event("run", "TestRequired", STORE_PKG),
                       event("pass", "TestRequired", STORE_PKG))
        self.assertTrue(gate.check_events(lines, (REQUIRED,)))

    def test_multiple_packages_required(self):
        store_required = f"{STORE_PKG}:TestStoreRequired"
        lines = stream(event("run", "TestRequired"), event("pass", "TestRequired"),
                       event("run", "TestStoreRequired", STORE_PKG),
                       event("pass", "TestStoreRequired", STORE_PKG))
        self.assertEqual([], gate.check_events(lines, (REQUIRED, store_required)))

    def test_store_child_skip_rejected(self):
        store_required = f"{STORE_PKG}:TestStoreRequired"
        lines = stream(event("run", "TestStoreRequired", STORE_PKG),
                       event("skip", "TestStoreRequired/postgres", STORE_PKG),
                       event("pass", "TestStoreRequired", STORE_PKG))
        self.assertTrue(gate.check_events(lines, (store_required,)))

    def test_unqualified_required_rejected(self):
        self.assertTrue(gate.check_events([], ("TestRequired",)))


if __name__ == "__main__":
    unittest.main()
