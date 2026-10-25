import sys
import unittest
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from code.evidence.models import EvidenceRecord
from code.policy.engine import PolicyEngine, AuditStep

class TestPhase3PolicyEngine(unittest.TestCase):
    def setUp(self):
        self.engine = PolicyEngine()

    def test_user_profile_evaluation(self):
        # Violation case: profile remains
        rec_viol = EvidenceRecord(
            evidence_id="ev_01", file_path="dummy.sql", captured_at="2026-09-01T10:00:00Z",
            system_id="account_service", resource_id="account_001", category="USER_PROFILE",
            state="PRESENT", has_pii=True
        )
        is_viol, find, rem, ver = self.engine.evaluate_resource(rec_viol)
        self.assertTrue(is_viol)
        self.assertEqual(find["operation"], "REPORT_REMAINING_RECORD")
        self.assertEqual(find["state"], "PRESENT")
        self.assertEqual(rem["operation"], "DELETE_RECORD")
        self.assertEqual(rem["state"], "ABSENT")
        self.assertEqual(ver["operation"], "VERIFY_RECORD_ABSENT")

        # Compliant case: profile absent
        rec_comp = EvidenceRecord(
            evidence_id="ev_02", file_path="dummy.sql", captured_at="2026-09-01T10:00:00Z",
            system_id="account_service", resource_id="account_001", category="USER_PROFILE",
            state="ABSENT", has_pii=False
        )
        is_viol2, find2, rem2, ver2 = self.engine.evaluate_resource(rec_comp)
        self.assertFalse(is_viol2)
        self.assertIsNone(find2)
        self.assertIsNone(rem2)
        self.assertEqual(ver2["operation"], "VERIFY_RECORD_ABSENT")

    def test_support_message_evaluation(self):
        # PII exposed
        rec_pii = EvidenceRecord(
            evidence_id="ev_03", file_path="dummy.log", captured_at="2026-09-01T10:00:00Z",
            system_id="support_platform", resource_id="support_001", category="SUPPORT_MESSAGE",
            state="PRESENT", has_pii=True
        )
        is_viol, find, rem, ver = self.engine.evaluate_resource(rec_pii)
        self.assertTrue(is_viol)
        self.assertEqual(find["operation"], "REPORT_EXPOSED_PII")
        self.assertEqual(rem["operation"], "REDACT_RECORD")
        self.assertEqual(ver["operation"], "VERIFY_RECORD_REDACTED")

        # Redacted
        rec_red = EvidenceRecord(
            evidence_id="ev_04", file_path="dummy.log", captured_at="2026-09-01T10:00:00Z",
            system_id="support_platform", resource_id="support_001", category="SUPPORT_MESSAGE",
            state="REDACTED", has_pii=False
        )
        is_viol2, find2, rem2, ver2 = self.engine.evaluate_resource(rec_red)
        self.assertFalse(is_viol2)
        self.assertEqual(ver2["operation"], "VERIFY_RECORD_REDACTED")

    def test_data_flow_and_backup_evaluation(self):
        # Data flow active
        flow = EvidenceRecord(
            evidence_id="ev_05", file_path="dummy.json", captured_at="2026-09-01T10:00:00Z",
            system_id="integration_service", resource_id="data_flow_01", category="DATA_FLOW",
            state="ACTIVE"
        )
        is_viol, find, rem, ver = self.engine.evaluate_resource(flow)
        self.assertTrue(is_viol)
        self.assertEqual(find["operation"], "REPORT_ACTIVE_DATA_FLOW")
        self.assertEqual(rem["operation"], "DISABLE_DATA_FLOW")
        self.assertEqual(ver["operation"], "VERIFY_DATA_FLOW_DISABLED")

        # Backup active
        backup = EvidenceRecord(
            evidence_id="ev_06", file_path="dummy.json", captured_at="2026-09-01T10:00:00Z",
            system_id="backup_service", resource_id="backup_01", category="BACKUP_ARCHIVE",
            state="ACTIVE"
        )
        is_viol_b, find_b, rem_b, ver_b = self.engine.evaluate_resource(backup)
        self.assertTrue(is_viol_b)
        self.assertEqual(find_b["operation"], "REPORT_RESTORE_RISK")
        self.assertEqual(rem_b["operation"], "BLOCK_RESTORE")
        self.assertEqual(ver_b["operation"], "VERIFY_RESTORE_BLOCKED")

    def test_complete_case_evaluation(self):
        # A case where all resources are compliant
        resources = {
            ("account_service", "account_001"): EvidenceRecord(
                evidence_id="ev_92", file_path="dummy.json", captured_at="2026-09-15T12:00:00Z",
                system_id="account_service", resource_id="account_001", category="USER_PROFILE",
                state="ABSENT"
            ),
            ("security_service", "audit_record_001"): EvidenceRecord(
                evidence_id="ev_92", file_path="dummy.json", captured_at="2026-09-15T12:00:00Z",
                system_id="security_service", resource_id="audit_record_001", category="SECURITY_AUDIT_LOG",
                state="PRESENT"
            ),
            ("analytics_platform", "analytics_001"): EvidenceRecord(
                evidence_id="ev_92", file_path="dummy.json", captured_at="2026-09-15T12:00:00Z",
                system_id="analytics_platform", resource_id="analytics_001", category="ANALYTICS_PROFILE",
                state="ANONYMIZED", has_pii=False
            ),
        }
        status, steps = self.engine.evaluate_case(resources)
        self.assertEqual(status, "COMPLETE")
        self.assertEqual(len(steps), 3)
        self.assertTrue(all(s.phase == "VERIFICATION" for s in steps))
        self.assertTrue(all(s.evidence_id == "ev_92" for s in steps))
        self.assertEqual([s.step_no for s in steps], [1, 2, 3])

    def test_incomplete_case_evaluation(self):
        # A case with remaining record and active data flow
        resources = {
            ("search_service", "search_101"): EvidenceRecord(
                evidence_id="ev_94", file_path="dummy.log", captured_at="2026-09-26T10:00:00Z",
                system_id="search_service", resource_id="search_101", category="SEARCH_INDEX_ENTRY",
                state="PRESENT", has_pii=True
            ),
            ("integration_service", "data_flow_101"): EvidenceRecord(
                evidence_id="ev_94", file_path="dummy.log", captured_at="2026-09-26T10:00:00Z",
                system_id="integration_service", resource_id="data_flow_101", category="DATA_FLOW",
                state="ACTIVE"
            ),
            ("account_service", "account_101"): EvidenceRecord(
                evidence_id="ev_54", file_path="dummy.sql", captured_at="2026-09-02T10:00:00Z",
                system_id="account_service", resource_id="account_101", category="USER_PROFILE",
                state="ABSENT"
            ),
        }
        status, steps = self.engine.evaluate_case(resources)
        self.assertEqual(status, "INCOMPLETE")
        
        # Check phases sequence: FINDING -> REMEDIATION -> VERIFICATION
        phases = [s.phase for s in steps]
        findings = [s for s in steps if s.phase == "FINDING"]
        remediations = [s for s in steps if s.phase == "REMEDIATION"]
        verifications = [s for s in steps if s.phase == "VERIFICATION"]

        self.assertEqual(len(findings), 2)
        self.assertEqual(len(remediations), 2)
        self.assertEqual(len(verifications), 3)

        # Findings must cite evidence_94
        for f in findings:
            self.assertEqual(f.evidence_id, "ev_94")

        # Remediation and verification in INCOMPLETE case must have empty evidence_id
        for r in remediations:
            self.assertEqual(r.evidence_id, "")
        for v in verifications:
            self.assertEqual(v.evidence_id, "")

        # Verify step numbering
        self.assertEqual([s.step_no for s in steps], list(range(1, len(steps) + 1)))

if __name__ == "__main__":
    unittest.main()
