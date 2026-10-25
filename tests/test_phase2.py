import sys
import unittest
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from code.identity.resolver import IdentityResolver
from code.evidence.models import EvidenceRecord
from code.evidence.parsers import (
    HandoverParser,
    ServiceExportParser,
    SnapshotBundleParser,
    ReadbackLogParser,
    SqlDumpParser,
    ImageConsoleParser,
    SpecializedParser,
)
from code.evidence.store import EvidenceStore

class TestPhase2EvidenceEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.resolver = IdentityResolver()
        cls.store = EvidenceStore()

    def test_store_loaded(self):
        """Test that EvidenceStore loads records and system activity successfully."""
        self.assertGreater(len(self.store.records), 1500)
        self.assertEqual(len(self.store.system_activities), 4011)

    def test_structured_json_log_parsing(self):
        """Test that structured JSON logs (e.g. structured_service_events_eu_west_20260918.log) are parsed."""
        log_path = repo_root / "dataset" / "evidence" / "logs" / "structured_service_events_eu_west_20260918.log"
        records = ReadbackLogParser.parse(log_path, "evidence_test", "2026-09-18T10:00:00Z")
        self.assertGreater(len(records), 20)
        
        # Verify trace pairing for user_61 -> audit_record_4902
        audit_recs = [r for r in records if r.resource_id == "audit_record_4902"]
        self.assertEqual(len(audit_recs), 1)
        self.assertEqual(audit_recs[0].customer_reference, "user_61")
        self.assertEqual(audit_recs[0].system_id, "security_service")
        self.assertEqual(audit_recs[0].state, "PRESENT")

    def test_key_value_log_parsing(self):
        """Test that key-value trace logs (e.g. resource_lookup_trace_20260926_103856.log) are parsed."""
        log_path = repo_root / "dataset" / "evidence" / "logs" / "resource_lookup_trace_20260926_103856.log"
        records = ReadbackLogParser.parse(log_path, "evidence_94", "2026-09-26T10:38:56Z")
        self.assertGreater(len(records), 10)

        # Check search_4013 for mori.ren@gmail.com
        search_recs = [r for r in records if r.resource_id == "search_4013"]
        self.assertEqual(len(search_recs), 1)
        self.assertEqual(search_recs[0].email, "mori.ren@gmail.com")
        self.assertEqual(search_recs[0].state, "PRESENT")

    def test_sql_dump_parsing(self):
        """Test that SQL dump parser handles schema tables."""
        sql_path = repo_root / "dataset" / "evidence" / "databases" / "customer_accounts_failover_replica_20260902.sql"
        records = SqlDumpParser.parse(sql_path, "evidence_54", "2026-09-02T10:00:00Z")
        self.assertGreater(len(records), 0)

    def test_image_console_parser(self):
        """Test that image console parses ground truth console screenshot."""
        img_path = repo_root / "dataset" / "evidence" / "images" / "account_admin_console_20260926.png"
        records = ImageConsoleParser.parse(img_path, "evidence_img", "2026-09-26T10:00:00Z")
        self.assertGreater(len(records), 0)
        self.assertTrue(any(r.resource_id == "account_5762" for r in records))

    def test_point_in_time_cutoff(self):
        """Test that records captured after audit_at are strictly excluded."""
        cluster = self.resolver.resolve("user_03")
        self.assertIsNotNone(cluster)

        early_records = self.store.get_user_records(cluster, "2026-03-01T00:00:00Z")
        later_records = self.store.get_user_records(cluster, "2026-09-30T23:59:59Z")
        self.assertLessEqual(len(early_records), len(later_records))
        for r in early_records:
            self.assertLessEqual(r.captured_at, "2026-03-01T00:00:00Z")

if __name__ == "__main__":
    unittest.main()
