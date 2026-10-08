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

    def test_non_required_gate_rejected(self):
        data = copy.deepcopy(self.data)
        data["claims"][0]["gates"] = ["formal-kani-strings-ascii"]
        self.assertTrue(any("is not required by ci-required" in error for error in
                            checker.check_manifest(data, ROOT, self.workflow)))

    def test_required_job_is_not_a_scheduled_gate(self):
        data = copy.deepcopy(self.data)
        data["claims"][0]["scheduled_gates"] = ["formal-lean"]
        self.assertTrue(any("is not a schedule-only job" in error for error in
                            checker.check_manifest(data, ROOT, self.workflow)))

    def test_missing_aggregator_rejected(self):
        workflow = self.workflow.replace("\n  ci-required:\n", "\n  ci-optional:\n")
        self.assertTrue(any("no ci-required job" in error for error in
                            checker.check_manifest(self.data, ROOT, workflow)))

    def test_missing_symbol_rejected(self):
        data = copy.deepcopy(self.data)
        data["claims"][0]["sources"][0]["symbol"] = "no_such_symbol"
        self.assertTrue(any("missing symbol" in error for error in
                            checker.check_manifest(data, ROOT, self.workflow)))

    def test_trivial_symbol_rejected(self):
        data = copy.deepcopy(self.data)
        data["claims"][0]["sources"][0]["symbol"] = "main"
        self.assertTrue(any("too short" in error for error in
                            checker.check_manifest(data, ROOT, self.workflow)))

    def test_path_traversal_rejected(self):
        data = copy.deepcopy(self.data)
        data["claims"][0]["sources"][0]["file"] = "../outside.lean"
        self.assertTrue(any("missing/invalid file" in error for error in
                            checker.check_manifest(data, ROOT, self.workflow)))

    def test_unconditional_job_missing_from_needs_rejected(self):
        # A job with no `if:` that ci-required does not need would run but never gate a pull request.
        workflow = self.workflow.replace("\njobs:\n", "\njobs:\n  stray:\n    runs-on: ubuntu-latest\n    steps: []\n", 1)
        self.assertTrue(any("must equal the jobs with no job-level if" in error and "stray" in error for error in
                            checker.check_manifest(self.data, ROOT, workflow)))

    def test_needed_job_made_conditional_rejected(self):
        workflow = self.workflow.replace("\n  formal-lean:\n", "\n  formal-lean:\n    if: github.event_name == 'push'\n", 1)
        self.assertTrue(any("must equal the jobs with no job-level if" in error and "formal-lean" in error for error in
                            checker.check_manifest(self.data, ROOT, workflow)))

    def test_evidence_run_must_be_a_run_id(self):
        data = copy.deepcopy(self.data)
        data["claims"][0]["evidence_run"] = "latest"
        self.assertTrue(any("must be a GitHub Actions run id" in error for error in
                            checker.check_manifest(data, ROOT, self.workflow)))

    def test_scheduled_evidence_needs_scheduled_gates(self):
        data = copy.deepcopy(self.data)
        data["claims"][0]["scheduled_gates"] = []
        data["claims"][0]["scheduled_evidence_run"] = "37678805697"
        self.assertTrue(any("has no scheduled_gates" in error for error in
                            checker.check_manifest(data, ROOT, self.workflow)))

    def test_valid_evidence_run_accepted(self):
        data = copy.deepcopy(self.data)
        data["claims"][0]["evidence_run"] = "37678805697"
        self.assertEqual([], checker.check_manifest(data, ROOT, self.workflow))


class OverclaimDenylistTest(unittest.TestCase):
    def test_live_copy_is_clean(self):
        self.assertEqual([], checker.check_copy_tree(ROOT))

    def test_final_source_phrases_rejected(self):
        for text in ("All of it was verified on the final source.", "Confirmed on final source by hand."):
            self.assertTrue(checker.check_copy(text, "x.md"), text)

    def test_48_of_48_needs_a_named_run(self):
        self.assertTrue(checker.check_copy("The mutation suite caught 48/48.", "x.md"))
        self.assertEqual([], checker.check_copy("CI run 37678805697 caught 48/48 mutants.", "x.md"))
        # the excuse is per sentence: a run named elsewhere does not cover this one
        self.assertTrue(checker.check_copy("See CI run 37678805697. The suite caught 48/48.", "x.md"))

    def test_decision_core_proof_claim_for_dag_chain_anchor_rejected(self):
        for noun in ("DAG", "chain", "anchor"):
            self.assertTrue(checker.check_copy(f"The {noun} closure is proven by decision-core.", "x.md"), noun)
        self.assertEqual([], checker.check_copy("Canonical bytes are checked by decision-core tests.", "x.md"))

    def test_scans_the_documented_paths(self):
        names = {str(p.relative_to(ROOT)) for p in checker.copy_files(ROOT)}
        self.assertIn("README.md", names)
        self.assertIn("formal/README.md", names)
        self.assertIn("formal/claims.json", names)
        self.assertTrue(any(n.startswith("docs/") for n in names))


if __name__ == "__main__":
    unittest.main()
