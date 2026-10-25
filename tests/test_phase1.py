import sys
import os
from pathlib import Path

# Ensure repo root is on sys.path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

import unittest
import csv
from code.identity.resolver import IdentityResolver
from code.intent.classifier import IntentClassifier
from code.config import DATASET_DIR

class TestPhase1(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.resolver = IdentityResolver()
        cls.classifier = IntentClassifier()

    def test_identity_resolution_current(self):
        # Test resolving by current email
        cluster = self.resolver.resolve("amina.elmasri@gmail.com")
        self.assertIsNotNone(cluster)
        self.assertEqual(cluster.user_id, "user_01")
        self.assertIn("amina.elmasri@gmail.com", cluster.emails)
        self.assertEqual(cluster.primary_name, "Amina El-Masri")

    def test_identity_resolution_historical(self):
        audit_log = DATASET_DIR / "user_audit_log.csv"
        found_hist_email = None
        target_uid = None
        if audit_log.exists():
            with open(audit_log, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for r in reader:
                    if r["field_name"] == "email" and r["old_value"]:
                        found_hist_email = r["old_value"].strip().lower()
                        target_uid = r["user_id"].strip()
                        break

        if found_hist_email:
            cluster = self.resolver.resolve(found_hist_email)
            self.assertIsNotNone(cluster)
            self.assertEqual(cluster.user_id, target_uid)
            self.assertIn(found_hist_email, cluster.emails)

    def test_identity_cluster_matching(self):
        cluster = self.resolver.resolve("user_01")
        self.assertIsNotNone(cluster)
        # Test matches() method on various identifiers
        self.assertTrue(cluster.matches("user_01"))
        self.assertTrue(cluster.matches("Amina El-Masri"))
        self.assertTrue(cluster.matches("amina.elmasri@gmail.com"))
        self.assertFalse(cluster.matches("unrelated.person@example.com"))

    def test_sample_requests_intent_all_authorized(self):
        sample_reqs = DATASET_DIR / "sample_deletion_requests.csv"
        with open(sample_reqs, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for r in reader:
                text = r["request_text"]
                self.assertTrue(
                    self.classifier.is_deletion_authorized(text),
                    f"Sample case {r['case_id']} was wrongly classified as non-deletion: {text}"
                )

    def test_evaluation_non_deletion_cases(self):
        eval_reqs = DATASET_DIR / "deletion_requests.csv"
        non_del_cases = [f"case_{i}" for i in range(533, 543)]
        with open(eval_reqs, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for r in reader:
                if r["case_id"] in non_del_cases:
                    self.assertFalse(
                        self.classifier.is_deletion_authorized(r["request_text"]),
                        f"Non-deletion case {r['case_id']} was wrongly authorized: {r['request_text']}"
                    )

    def test_multilingual_intents(self):
        # French
        self.assertTrue(self.classifier.is_deletion_authorized("Veuillez supprimer toutes mes données personnelles immédiatement."))
        # Spanish
        self.assertTrue(self.classifier.is_deletion_authorized("Por favor elimine mi cuenta y mis datos del sistema."))
        # German
        self.assertTrue(self.classifier.is_deletion_authorized("Bitte löschen Sie alle meine personenbezogenen Daten."))
        # Japanese
        self.assertTrue(self.classifier.is_deletion_authorized("私のアカウントと関連データをすべて削除してください。"))
        # Korean
        self.assertTrue(self.classifier.is_deletion_authorized("제 계정과 모든 개인정보를 영구적으로 삭제해 주시기 바랍니다."))
        # Non-deletion access request
        self.assertFalse(self.classifier.is_deletion_authorized("Please send me a copy of my data for portability, keep my account active."))
        self.assertFalse(self.classifier.is_deletion_authorized("I need help resetting the login password for my profile."))

if __name__ == "__main__":
    unittest.main()
