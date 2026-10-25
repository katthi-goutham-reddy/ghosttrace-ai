import csv
from pathlib import Path
from typing import Dict, Optional, Set
from .models import UserCluster
from ..config import USER_IDENTITIES_PATH, USER_AUDIT_LOG_PATH

class IdentityResolver:
    def __init__(self, identities_path: Path = USER_IDENTITIES_PATH, audit_log_path: Path = USER_AUDIT_LOG_PATH):
        self.identities_path = identities_path
        self.audit_log_path = audit_log_path
        self.clusters_by_uid: Dict[str, UserCluster] = {}
        self.email_to_uid: Dict[str, str] = {}
        self.phone_to_uid: Dict[str, str] = {}
        self.hash_to_uid: Dict[str, str] = {}
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

                cluster = UserCluster(
                    user_id=uid,
                    primary_name=name,
                    names={name},
                    emails={email},
                    phones={phone},
                    email_hashes={email_hash},
                    updated_at=updated_at,
                )
                self.clusters_by_uid[uid] = cluster
                self.email_to_uid[email] = uid
                self.phone_to_uid[phone] = uid
                self.hash_to_uid[email_hash] = uid

        if not self.audit_log_path.exists():
            return

        with open(self.audit_log_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row["user_id"].strip()
                field_name = row["field_name"].strip()
                old_val = row["old_value"].strip()
                new_val = row["new_value"].strip()

                cluster = self.clusters_by_uid.get(uid)
                if not cluster:
                    continue

                if field_name == "email":
                    old_em = old_val.lower()
                    new_em = new_val.lower()
                    cluster.emails.add(old_em)
                    cluster.emails.add(new_em)
                    self.email_to_uid[old_em] = uid
                    self.email_to_uid[new_em] = uid
                elif field_name == "phone":
                    cluster.phones.add(old_val)
                    cluster.phones.add(new_val)
                    self.phone_to_uid[old_val] = uid
                    self.phone_to_uid[new_val] = uid
                elif field_name == "email_hash":
                    old_h = old_val.lower()
                    new_h = new_val.lower()
                    cluster.email_hashes.add(old_h)
                    cluster.email_hashes.add(new_h)
                    self.hash_to_uid[old_h] = uid
                    self.hash_to_uid[new_h] = uid
                elif field_name == "name":
                    cluster.names.add(old_val)
                    cluster.names.add(new_val)

    def resolve(self, term: str) -> Optional[UserCluster]:
        if not term:
            return None
        clean = term.strip()
        clean_lower = clean.lower()

        # Direct UID match
        if clean in self.clusters_by_uid:
            return self.clusters_by_uid[clean]
        if clean_lower in self.clusters_by_uid:
            return self.clusters_by_uid[clean_lower]

        # Email match
        if clean_lower in self.email_to_uid:
            uid = self.email_to_uid[clean_lower]
            return self.clusters_by_uid.get(uid)

        # Phone match
        if clean in self.phone_to_uid:
            uid = self.phone_to_uid[clean]
            return self.clusters_by_uid.get(uid)

        # Hash match
        if clean_lower in self.hash_to_uid:
            uid = self.hash_to_uid[clean_lower]
            return self.clusters_by_uid.get(uid)

        return None
