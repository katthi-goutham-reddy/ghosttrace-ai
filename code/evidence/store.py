import csv
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from .models import EvidenceRecord
from .parsers import (
    HandoverParser,
    ServiceExportParser,
    SnapshotBundleParser,
    ReadbackLogParser,
    SqlDumpParser,
    ImageConsoleParser,
    SpecializedParser,
)
from ..identity.models import UserCluster
from ..config import EVIDENCE_FILES_PATH, SYSTEM_ACTIVITY_PATH, DATASET_DIR

logger = logging.getLogger(__name__)

class EvidenceStore:
    def __init__(
        self,
        evidence_manifest_path: Path = EVIDENCE_FILES_PATH,
        system_activity_path: Path = SYSTEM_ACTIVITY_PATH,
        dataset_dir: Path = DATASET_DIR,
    ):
        self.evidence_manifest_path = evidence_manifest_path
        self.system_activity_path = system_activity_path
        self.dataset_dir = dataset_dir
        self.records: List[EvidenceRecord] = []
        self.system_activities: List[Dict[str, Any]] = []
        self._load()

    def _load(self):
        self._load_evidence_files()
        self._load_system_activity()

    def _load_evidence_files(self):
        if not self.evidence_manifest_path.exists():
            return

        with open(self.evidence_manifest_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                file_id = row["file_id"].strip()
                rel_path = row.get("file_path", row.get("path", "")).strip()
                captured_at = row.get("captured_at", row.get("capture_time", "")).strip()
                full_path = self.dataset_dir / rel_path

                if not full_path.exists():
                    continue

                parsed_records = self._parse_file(full_path, file_id, captured_at)
                for pr in parsed_records:
                    if not pr.file_captured_at:
                        pr.file_captured_at = captured_at
                self.records.extend(parsed_records)

    def _parse_file(self, full_path: Path, file_id: str, captured_at: str) -> List[EvidenceRecord]:
        name = full_path.name.lower()
        suffix = full_path.suffix.lower()

        try:
            if suffix == ".txt":
                return HandoverParser.parse(full_path, file_id, captured_at)
            elif suffix == ".json":
                if "service_resource_export" in name:
                    return ServiceExportParser.parse(full_path, file_id, captured_at)
                elif "customer_data_snapshot_bundle" in name:
                    return SnapshotBundleParser.parse(full_path, file_id, captured_at)
                else:
                    return SpecializedParser.parse_json(full_path, file_id, captured_at)
            elif suffix == ".log":
                return ReadbackLogParser.parse(full_path, file_id, captured_at)
            elif suffix == ".sql":
                return SqlDumpParser.parse(full_path, file_id, captured_at)
            elif suffix == ".png":
                return ImageConsoleParser.parse(full_path, file_id, captured_at)
            elif suffix == ".pdf":
                return SpecializedParser.parse_pdf(full_path, file_id, captured_at)
        except Exception as e:
            logger.warning(f"Error parsing {full_path}: {e}")

        return []

    def _load_system_activity(self):
        if not self.system_activity_path.exists():
            return

        with open(self.system_activity_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                self.system_activities.append({
                    "activity_id": row["activity_id"].strip(),
                    "event_time": row["event_time"].strip(),
                    "event_type": row["event_type"].strip(),
                    "source_system": row["source_system"].strip(),
                    "target_system": row["target_system"].strip(),
                    "resource_id": row["resource_id"].strip(),
                    "reported_result": row["reported_result"].strip(),
                    "details": row.get("details", "").strip(),
                })

    def get_user_records(self, cluster: UserCluster, audit_at: str) -> List[EvidenceRecord]:
        """Finds all evidence records matching the user cluster captured at or before audit_at."""
        matching = []
        known_resources = set()
        for rec in self.records:
            if rec.file_captured_at and rec.file_captured_at > audit_at:
                continue
            if rec.captured_at > audit_at:
                continue

            is_match = False
            if rec.customer_reference and cluster.matches(rec.customer_reference):
                is_match = True
            elif rec.email and cluster.matches(rec.email):
                is_match = True
            elif rec.phone and cluster.matches(rec.phone):
                is_match = True
            elif rec.email_hash and cluster.matches(rec.email_hash):
                is_match = True
            elif rec.name and cluster.matches(rec.name):
                is_match = True

            if is_match:
                matching.append(rec)
                known_resources.add((rec.system_id, rec.resource_id))

        # Pass 2: include state updates for known resources (e.g. 404 lookups without profile body)
        for rec in self.records:
            if rec.file_captured_at and rec.file_captured_at > audit_at:
                continue
            if rec.captured_at > audit_at:
                continue
            if (rec.system_id, rec.resource_id) in known_resources and rec not in matching:
                matching.append(rec)

        return matching

    def get_latest_resource_states(
        self, cluster: UserCluster, audit_at: str
    ) -> Dict[Tuple[str, str], EvidenceRecord]:
        """Returns the latest EvidenceRecord per (system_id, resource_id) at or before audit_at."""
        matching_records = self.get_user_records(cluster, audit_at)
        grouped: Dict[Tuple[str, str], List[EvidenceRecord]] = {}

        for rec in matching_records:
            key = (rec.system_id, rec.resource_id)
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(rec)

        latest_by_key: Dict[Tuple[str, str], EvidenceRecord] = {}
        for key, rec_list in grouped.items():
            # Sort by captured_at ascending, so the last is the latest
            rec_list.sort(key=lambda r: r.captured_at)
            latest_by_key[key] = rec_list[-1]

        return latest_by_key

    def get_user_activities(self, cluster: UserCluster, audit_at: str) -> List[Dict[str, Any]]:
        """Returns all system_activity rows matching the user cluster up to audit_at."""
        matching = []
        for act in self.system_activities:
            if act["event_time"] > audit_at:
                continue
            # Check if details or resource_id mentions user
            details = act.get("details", "")
            matched = False
            if cluster.user_id in details:
                matched = True
            else:
                for em in cluster.emails:
                    if em in details:
                        matched = True
                        break
            if matched:
                matching.append(act)
        return matching
