import unittest
import csv
import json
import tempfile
from pathlib import Path

from code.config import Config
from code.audit_pipeline import AuditPipeline


class TestPhase4Pipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pipeline = AuditPipeline()
        with open(Config.DATASET_DIR / "sample_deletion_requests.csv", encoding="utf-8") as f:
            cls.sample_reqs = list(csv.DictReader(f))
        with open(Config.DATASET_DIR / "sample_output.csv", encoding="utf-8") as f:
            cls.sample_outputs = {
                r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"]))
                for r in csv.DictReader(f)
            }

    def test_pipeline_sample_status_accuracy(self):
        """Verify deletion_status accuracy across all 32 public samples."""
        matches = 0
        total = len(self.sample_reqs)
        for req in self.sample_reqs:
            cid = req["case_id"]
            gold_status, _ = self.sample_outputs[cid]
            pred_status, _ = self.pipeline.audit_case(
                case_id=cid,
                email=req["email"],
                requested_at=req["requested_at"],
                reported_status=req["reported_status"],
                reported_at=req["reported_at"],
                audit_at=req["audit_at"],
                request_text=req["request_text"]
            )
            if pred_status == gold_status:
                matches += 1

        accuracy = matches / total
        print(f"\n[Phase 4 Test] Sample Status Accuracy: {matches}/{total} ({accuracy * 100:.1f}%)")
        self.assertGreaterEqual(accuracy, 0.95, f"Status accuracy below 95%: {matches}/{total}")

    def test_step_schema_and_numbering(self):
        """Verify all generated steps comply with HackerRank schema and ordering."""
        allowed_phases = ("FINDING", "REMEDIATION", "VERIFICATION")
        allowed_states = ("PRESENT", "ABSENT", "REDACTED", "ANONYMIZED", "ACTIVE", "DISABLED", "BLOCKED")

        for req in self.sample_reqs[:10]:
            cid = req["case_id"]
            pred_status, pred_steps = self.pipeline.audit_case(
                case_id=cid,
                email=req["email"],
                requested_at=req["requested_at"],
                reported_status=req["reported_status"],
                reported_at=req["reported_at"],
                audit_at=req["audit_at"],
                request_text=req["request_text"]
            )

            phase_order = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
            last_phase_val = -1

            for idx, step in enumerate(pred_steps):
                self.assertEqual(step["step_no"], idx + 1, f"Step numbering must be 1..N: {step}")
                self.assertIn(step["phase"], allowed_phases)
                self.assertIn(step["state"], allowed_states)
                self.assertIsInstance(step["system_id"], str)
                self.assertIsInstance(step["resource_id"], str)
                self.assertIsInstance(step["operation"], str)

                current_phase_val = phase_order[step["phase"]]
                self.assertGreaterEqual(current_phase_val, last_phase_val, f"Phase out of order: {step['phase']}")
                last_phase_val = current_phase_val

                # In complete cases, verification steps must cite valid evidence_id
                if pred_status == "COMPLETE":
                    self.assertEqual(step["phase"], "VERIFICATION")
                    self.assertTrue(step["evidence_id"], f"Complete case verification must cite evidence: {step}")

                # In incomplete cases, remediation and verification have empty evidence_id
                if pred_status == "INCOMPLETE" and step["phase"] in ("REMEDIATION", "VERIFICATION"):
                    self.assertEqual(step["evidence_id"], "")

    def test_non_deletion_handling(self):
        """Confirm non-deletion requests produce NOT_APPLICABLE with empty steps."""
        status, steps = self.pipeline.audit_case(
            case_id="case_test_info",
            email="user@example.com",
            requested_at="2026-09-01T10:00:00Z",
            reported_status="NOT_STARTED",
            reported_at="2026-09-01T12:00:00Z",
            audit_at="2026-09-05T12:00:00Z",
            request_text="Could you please provide an export of all my personal data?"
        )
        self.assertEqual(status, "NOT_APPLICABLE")
        self.assertEqual(steps, [])

    def test_pipeline_run_file(self):
        """Test batch run_file writes correctly formatted CSV."""
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            count = self.pipeline.run_file(
                input_path=Config.DATASET_DIR / "sample_deletion_requests.csv",
                output_path=tmp_path
            )
            self.assertEqual(count, 32)

            with open(tmp_path, "r", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
                self.assertEqual(len(rows), 32)
                self.assertEqual(rows[0]["case_id"], "case_01")
                self.assertEqual(rows[-1]["case_id"], "case_32")
                self.assertIn("deletion_status", rows[0])
                self.assertIn("steps_json", rows[0])
                # Validate JSON array
                steps = json.loads(rows[0]["steps_json"])
                self.assertIsInstance(steps, list)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()


if __name__ == "__main__":
    unittest.main()
