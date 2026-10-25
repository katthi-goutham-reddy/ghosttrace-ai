import csv
from pathlib import Path
from typing import Dict, Optional, Set, List, Any
from .models import UserCluster
from ..config import USER_IDENTITIES_PATH, USER_AUDIT_LOG_PATH

class IdentityResolver:
    def __init__(self, identities_path: Path = USER_IDENTITIES_PATH, audit_log_path: Path = USER_AUDIT_LOG_PATH):
        self.identities_path = identities_path
        self.audit_log_path = audit_log_path
        self.base_identities: Dict[str, Dict[str, Any]] = {}
        self.audit_log_events: List[Dict[str, Any]] = []
        self._load()

    def _load(self):
        if not self.identities_path.exists():
            return

        with open(self.identities_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row["user_id"].strip()
                name = row["name"].strip()
                email = row["email"].strip().lower()
                phone = row["phone"].strip()
                email_hash = row["email_hash"].strip().lower()
                updated_at = row.get("updated_at")

                self.base_identities[uid] = {
                    "user_id": uid,
                    "name": name,
                    "email": email,
                    "phone": phone,
                    "email_hash": email_hash,
                    "updated_at": updated_at,
                }

        if not self.audit_log_path.exists():
            return

        with open(self.audit_log_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                self.audit_log_events.append({
                    "audit_id": row.get("audit_id", "").strip(),
                    "user_id": row["user_id"].strip(),
                    "event_time": row.get("event_time", "").strip(),
                    "field_name": row["field_name"].strip(),
                    "old_value": row["old_value"].strip(),
                    "new_value": row["new_value"].strip(),
                })

    def resolve(self, term: str, audit_at: Optional[str] = None) -> Optional[UserCluster]:
        if not term:
            return None
        clean = term.strip()
        clean_lower = clean.lower()

        # Step 1: Find candidate user_id
        target_uid = None

        # Check direct UID
        if clean in self.base_identities:
            target_uid = clean
        elif clean_lower in self.base_identities:
            target_uid = clean_lower

        # Check base identities (current snapshot)
        if not target_uid:
            for uid, info in self.base_identities.items():
                if (
                    info["email"] == clean_lower
                    or info["phone"] == clean
                    or info["email_hash"] == clean_lower
                    or info["name"].lower() == clean_lower
                ):
                    target_uid = uid
                    break

        # Check historical audit log up to audit_at
        if not target_uid:
            for ev in self.audit_log_events:
                if audit_at and ev["event_time"] and ev["event_time"] > audit_at:
                    continue
                old_val = ev["old_value"]
                new_val = ev["new_value"]
                if (
                    old_val.lower() == clean_lower
                    or new_val.lower() == clean_lower
                    or old_val == clean
                    or new_val == clean
                ):
                    target_uid = ev["user_id"]
                    break

        if not target_uid or target_uid not in self.base_identities:
            return None

        # Step 2: Build cluster using base identity + audit log <= audit_at
        info = self.base_identities[target_uid]
        cluster = UserCluster(
            user_id=target_uid,
            primary_name=info["name"],
            names={info["name"]},
            emails={info["email"]},
            phones={info["phone"]},
            email_hashes={info["email_hash"]},
            updated_at=info["updated_at"],
        )

        for ev in self.audit_log_events:
            if ev["user_id"] != target_uid:
                continue
            if audit_at and ev["event_time"] and ev["event_time"] > audit_at:
                continue

            field = ev["field_name"]
            old_val = ev["old_value"]
            new_val = ev["new_value"]

            if field == "email":
                cluster.emails.add(old_val.lower())
                cluster.emails.add(new_val.lower())
            elif field == "phone":
                cluster.phones.add(old_val)
                cluster.phones.add(new_val)
            elif field == "email_hash":
                cluster.email_hashes.add(old_val.lower())
                cluster.email_hashes.add(new_val.lower())
            elif field == "name":
                cluster.names.add(old_val)
                cluster.names.add(new_val)

        return cluster
