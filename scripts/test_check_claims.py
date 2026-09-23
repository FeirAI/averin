import copy
import json
import unittest

from importlib.machinery import SourceFileLoader
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
checker = SourceFileLoader("claim_checker", str(ROOT / "scripts/check-claims.py")).load_module()


class ClaimCheckerTest(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / "formal/claims.json").read_text())
        self.workflow = (ROOT / ".github/workflows/ci.yml").read_text()

    def test_live_manifest(self):
        self.assertEqual([], checker.check_manifest(self.data, ROOT, self.workflow))

    def test_missing_gate_rejected(self):
        data = copy.deepcopy(self.data)
        data["claims"][0]["gates"] = ["no-such-required-job"]
        self.assertTrue(any("missing CI job" in error for error in
                            checker.check_manifest(data, ROOT, self.workflow)))

    def test_missing_symbol_rejected(self):
        data = copy.deepcopy(self.data)
        data["claims"][0]["sources"][0]["symbol"] = "no_such_symbol"
        self.assertTrue(any("missing symbol" in error for error in
                            checker.check_manifest(data, ROOT, self.workflow)))

    def test_path_traversal_rejected(self):
        data = copy.deepcopy(self.data)
        data["claims"][0]["sources"][0]["file"] = "../outside.lean"
        self.assertTrue(any("missing/invalid file" in error for error in
                            checker.check_manifest(data, ROOT, self.workflow)))


if __name__ == "__main__":
    unittest.main()
