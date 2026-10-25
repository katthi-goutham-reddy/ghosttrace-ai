import base64
import json
import logging
import os
import re
import sqlite3
from pathlib import Path
from typing import List, Dict, Any, Optional
import requests

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

from .models import EvidenceRecord

logger = logging.getLogger(__name__)

class HandoverParser:
    @staticmethod
    def parse(file_path: Path, evidence_id: str, captured_at: str) -> List[EvidenceRecord]:
        records = []
        if not file_path.exists():
            return records

        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line.startswith("- "):
                    continue
                parts = [p.strip() for p in line[2:].split("|")]
                if len(parts) < 6:
                    continue
                time_str, system_id, resource_id, category, status_str, user_ref = parts[:6]

                state = "PRESENT"
                has_pii = False
                email = None
                cust_ref = None

                if "@" in user_ref:
                    email = user_ref.lower()
                elif user_ref.startswith("user_"):
                    cust_ref = user_ref

                if category == "USER_PROFILE":
                    if status_str == "NOT_FOUND":
                        state = "ABSENT"
                    else:
                        state = "PRESENT"
                        has_pii = True
                elif category == "SEARCH_INDEX_ENTRY":
                    if status_str == "FOUND":
                        state = "PRESENT"
                        has_pii = True
                    else:
                        state = "ABSENT"
                elif category == "ANALYTICS_PROFILE":
                    if status_str == "IDENTIFIABLE":
                        state = "PRESENT"
                        has_pii = True
                    else:
                        state = "ANONYMIZED"
                elif category == "BACKUP_ARCHIVE":
                    if status_str == "ACTIVE":
                        state = "ACTIVE"
                    else:
                        state = "BLOCKED"
                elif category == "DATA_FLOW":
                    if status_str == "ACTIVE":
                        state = "ACTIVE"
                    else:
                        state = "DISABLED"
                elif category == "USER_EXPORT":
                    state = "PRESENT" if status_str == "FOUND" else "ABSENT"
                elif category == "SECURITY_AUDIT_LOG":
                    state = "PRESENT"
                elif category in ("SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT"):
                    if status_str == "IDENTIFIABLE" or status_str == "FOUND":
                        state = "PRESENT"
                        has_pii = True
                    else:
                        state = "REDACTED"
                elif category == "ACCOUNT_TOMBSTONE":
                    if status_str == "IDENTIFIABLE":
                        state = "PRESENT"
                        has_pii = True
                    else:
                        state = "REDACTED"

                records.append(
                    EvidenceRecord(
                        evidence_id=evidence_id,
                        file_path=str(file_path),
                        captured_at=captured_at,
                        system_id=system_id,
                        resource_id=resource_id,
                        category=category,
                        state=state,
                        customer_reference=cust_ref,
                        email=email,
                        has_pii=has_pii,
                    )
                )
        return records

class ServiceExportParser:
    @staticmethod
    def parse(file_path: Path, evidence_id: str, captured_at: str) -> List[EvidenceRecord]:
        records = []
        if not file_path.exists():
            return records

        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        sexp = data.get("service_exports", {})

        # 1. account_service
        for p in sexp.get("account_service", {}).get("profile_lookups", []):
            rid = p.get("resource_id")
            prof = p.get("profile")
            status_code = p.get("status_code", 200)
            email = None
            cust_ref = None
            if prof:
                email = prof.get("email")
                cust_ref = prof.get("customer_reference")

            state = "ABSENT" if (status_code == 404 or prof is None) else "PRESENT"
            records.append(
                EvidenceRecord(
                    evidence_id=evidence_id,
                    file_path=str(file_path),
                    captured_at=captured_at,
                    system_id="account_service",
                    resource_id=rid,
                    category="USER_PROFILE",
                    state=state,
                    customer_reference=cust_ref,
                    email=email.lower() if email else None,
                    has_pii=(state == "PRESENT"),
                )
            )

        # 2. analytics_platform
        for a in sexp.get("analytics_platform", {}).get("profiles", []):
            rid = a.get("resource_id")
            email = a.get("email")
            cust_ref = a.get("customer_reference")
            has_pii = bool(email or a.get("phone") or a.get("email_hash"))
            state = "PRESENT" if has_pii else "ANONYMIZED"
            records.append(
                EvidenceRecord(
                    evidence_id=evidence_id,
                    file_path=str(file_path),
                    captured_at=captured_at,
                    system_id="analytics_platform",
                    resource_id=rid,
                    category="ANALYTICS_PROFILE",
                    state=state,
                    customer_reference=cust_ref,
                    email=email.lower() if email else None,
                    has_pii=has_pii,
                )
            )

        # 3. backup_service
        for b in sexp.get("backup_service", {}).get("restore_entries", []):
            rid = b.get("resource_id")
            allowed = b.get("restore_allowed", False)
            state = "ACTIVE" if allowed else "BLOCKED"
            records.append(
                EvidenceRecord(
                    evidence_id=evidence_id,
                    file_path=str(file_path),
                    captured_at=captured_at,
                    system_id="backup_service",
                    resource_id=rid,
                    category="BACKUP_ARCHIVE",
                    state=state,
                    customer_reference=b.get("customer_reference"),
                    email=b.get("customer_email").lower() if b.get("customer_email") else None,
                )
            )

        # 4. export_service
        for exp in sexp.get("export_service", {}).get("exports", []):
            rid = exp.get("resource_id")
            records.append(
                EvidenceRecord(
                    evidence_id=evidence_id,
                    file_path=str(file_path),
                    captured_at=captured_at,
                    system_id="export_service",
                    resource_id=rid,
                    category="USER_EXPORT",
                    state="PRESENT",
                    customer_reference=exp.get("customer_reference"),
                    email=exp.get("owner_email").lower() if exp.get("owner_email") else None,
                    has_pii=True,
                )
            )

        # 5. integration_service
        for conn in sexp.get("integration_service", {}).get("connectors", []):
            rid = conn.get("resource_id")
            enabled = conn.get("enabled", False)
            state = "ACTIVE" if enabled else "DISABLED"
            records.append(
                EvidenceRecord(
                    evidence_id=evidence_id,
                    file_path=str(file_path),
                    captured_at=captured_at,
                    system_id="integration_service",
                    resource_id=rid,
                    category="DATA_FLOW",
                    state=state,
                    customer_reference=conn.get("customer_reference"),
                    email=conn.get("customer_email").lower() if conn.get("customer_email") else None,
                )
            )

        # 6. search_service
        for s in sexp.get("search_service", {}).get("index_queries", []):
            rid = s.get("resource_id")
            hits_obj = s.get("hits", {})
            total_hits = hits_obj.get("total", 0) if isinstance(hits_obj, dict) else s.get("total_hits", 0)
            state = "PRESENT" if total_hits > 0 else "ABSENT"

            email = s.get("email")
            query = s.get("query")
            if not email and query and "@" in query:
                email = query
            cust_ref = s.get("customer_reference")
            if isinstance(hits_obj, dict) and hits_obj.get("documents"):
                doc0 = hits_obj["documents"][0]
                if not email:
                    email = doc0.get("email")
                if not cust_ref:
                    cust_ref = doc0.get("customer_reference")

            records.append(
                EvidenceRecord(
                    evidence_id=evidence_id,
                    file_path=str(file_path),
                    captured_at=captured_at,
                    system_id="search_service",
                    resource_id=rid,
                    category="SEARCH_INDEX_ENTRY",
                    state=state,
                    customer_reference=cust_ref,
                    email=email.lower() if email else None,
                    has_pii=(state == "PRESENT"),
                )
            )

        # 7. security_service
        for sec in sexp.get("security_service", {}).get("audit_records", []):
            rid = sec.get("resource_id")
            records.append(
                EvidenceRecord(
                    evidence_id=evidence_id,
                    file_path=str(file_path),
                    captured_at=captured_at,
                    system_id="security_service",
                    resource_id=rid,
                    category="SECURITY_AUDIT_LOG",
                    state="PRESENT",
                    customer_reference=sec.get("subject_reference"),
                )
            )

        # 8. support_platform
        for sup in sexp.get("support_platform", {}).get("tickets", []):
            rid = sup.get("resource_id")
            email = sup.get("requester_email")
            has_pii = bool(email or sup.get("requester_name") or sup.get("requester_phone"))
            state = "PRESENT" if has_pii else "REDACTED"
            records.append(
                EvidenceRecord(
                    evidence_id=evidence_id,
                    file_path=str(file_path),
                    captured_at=captured_at,
                    system_id="support_platform",
                    resource_id=rid,
                    category="SUPPORT_MESSAGE",
                    state=state,
                    customer_reference=sup.get("customer_reference"),
                    email=email.lower() if email else None,
                    has_pii=has_pii,
                )
            )

        return records

class SnapshotBundleParser:
    @staticmethod
    def parse(file_path: Path, evidence_id: str, captured_at: str) -> List[EvidenceRecord]:
        records = []
        if not file_path.exists():
            return records

        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        for snap in data.get("snapshots", []):
            data_store = snap.get("data_store")
            collection = snap.get("collection")
            snap_captured_at = snap.get("captured_at") or captured_at

            for rec in snap.get("records", []):
                rid = rec.get("resource_id")
                if not rid:
                    continue

                if data_store == "account_service" and collection == "customer_profiles":
                    status = rec.get("account_status", "ACTIVE")
                    state = "ABSENT" if status == "DELETED" else "PRESENT"
                    records.append(
                        EvidenceRecord(
                            evidence_id=evidence_id,
                            file_path=str(file_path),
                            captured_at=snap_captured_at,
                            system_id="account_service",
                            resource_id=rid,
                            category="USER_PROFILE",
                            state=state,
                            customer_reference=rec.get("customer_reference") or rec.get("user_id") or rec.get("subject_reference"),
                            email=rec.get("email").lower() if rec.get("email") else None,
                            phone=rec.get("phone"),
                            name=rec.get("full_name"),
                            has_pii=(state == "PRESENT"),
                        )
                    )
                elif data_store == "identity_service" and collection == "deleted_customer_references":
                    has_pii = bool(rec.get("name") or rec.get("email") or rec.get("phone") or rec.get("email_hash"))
                    state = "PRESENT" if has_pii else "REDACTED"
                    records.append(
                        EvidenceRecord(
                            evidence_id=evidence_id,
                            file_path=str(file_path),
                            captured_at=snap_captured_at,
                            system_id="identity_service",
                            resource_id=rid,
                            category="ACCOUNT_TOMBSTONE",
                            state=state,
                            customer_reference=rec.get("subject_reference") or rec.get("customer_reference") or rec.get("user_id"),
                            email=rec.get("email").lower() if rec.get("email") else None,
                            phone=rec.get("phone"),
                            name=rec.get("name"),
                            has_pii=has_pii,
                        )
                    )
                elif data_store == "analytics_platform" and collection == "customer_analytics_reports":
                    has_pii = bool(rec.get("email") or rec.get("phone") or rec.get("user_id") or rec.get("customer_reference") or rec.get("subject_reference"))
                    state = "PRESENT" if has_pii else "ANONYMIZED"
                    records.append(
                        EvidenceRecord(
                            evidence_id=evidence_id,
                            file_path=str(file_path),
                            captured_at=snap_captured_at,
                            system_id="analytics_platform",
                            resource_id=rid,
                            category="ANALYTICS_PROFILE",
                            state=state,
                            customer_reference=rec.get("user_id") or rec.get("customer_reference") or rec.get("subject_reference"),
                            email=rec.get("email").lower() if rec.get("email") else None,
                            has_pii=has_pii,
                        )
                    )
                elif data_store == "support_platform" and collection in ("support_records", "support_conversations"):
                    email = rec.get("requester_email") or rec.get("email")
                    has_pii = bool(email or rec.get("requester_name") or rec.get("requester_phone") or rec.get("name"))
                    state = "PRESENT" if has_pii else "REDACTED"
                    records.append(
                        EvidenceRecord(
                            evidence_id=evidence_id,
                            file_path=str(file_path),
                            captured_at=snap_captured_at,
                            system_id="support_platform",
                            resource_id=rid,
                            category="SUPPORT_MESSAGE",
                            state=state,
                            customer_reference=rec.get("subject_reference") or rec.get("customer_reference") or rec.get("user_id"),
                            email=email.lower() if email else None,
                            has_pii=has_pii,
                        )
                    )
                elif data_store == "support_platform" and collection == "ticket_attachments":
                    email = rec.get("uploader_email") or rec.get("email")
                    records.append(
                        EvidenceRecord(
                            evidence_id=evidence_id,
                            file_path=str(file_path),
                            captured_at=snap_captured_at,
                            system_id="support_platform",
                            resource_id=rid,
                            category="SUPPORT_ATTACHMENT",
                            state="PRESENT",
                            customer_reference=rec.get("subject_reference") or rec.get("customer_reference") or rec.get("user_id"),
                            email=email.lower() if email else None,
                            has_pii=True,
                        )
                    )
                elif data_store == "search_service" and collection == "customer_search_documents":
                    doc = rec.get("document", rec)
                    email = doc.get("email")
                    records.append(
                        EvidenceRecord(
                            evidence_id=evidence_id,
                            file_path=str(file_path),
                            captured_at=snap_captured_at,
                            system_id="search_service",
                            resource_id=rid,
                            category="SEARCH_INDEX_ENTRY",
                            state="PRESENT",
                            customer_reference=doc.get("customer_reference") or doc.get("user_id") or doc.get("subject_reference"),
                            email=email.lower() if email else None,
                            name=doc.get("display_name"),
                            has_pii=True,
                        )
                    )
                elif data_store == "backup_service" and collection == "backup_catalog":
                    allowed = rec.get("restore_allowed", False)
                    state = "ACTIVE" if allowed in (True, "true", "True", 1) else "BLOCKED"
                    records.append(
                        EvidenceRecord(
                            evidence_id=evidence_id,
                            file_path=str(file_path),
                            captured_at=snap_captured_at,
                            system_id="backup_service",
                            resource_id=rid,
                            category="BACKUP_ARCHIVE",
                            state=state,
                            customer_reference=rec.get("subject_reference") or rec.get("customer_reference") or rec.get("user_id"),
                            email=rec.get("email").lower() if rec.get("email") else None,
                        )
                    )
                elif data_store == "integration_service" and collection == "connector_configurations":
                    enabled = rec.get("enabled", False)
                    state = "ACTIVE" if enabled in (True, "true", "True", 1) else "DISABLED"
                    selector = rec.get("subject_selector", "")
                    email = selector if "@" in selector else None
                    cust_ref = selector if not email and selector else None
                    records.append(
                        EvidenceRecord(
                            evidence_id=evidence_id,
                            file_path=str(file_path),
                            captured_at=snap_captured_at,
                            system_id="integration_service",
                            resource_id=rid,
                            category="DATA_FLOW",
                            state=state,
                            customer_reference=cust_ref or rec.get("customer_reference") or rec.get("subject_reference"),
                            email=email.lower() if email else None,
                        )
                    )
                elif data_store == "security_service" and collection == "security_audit_events":
                    records.append(
                        EvidenceRecord(
                            evidence_id=evidence_id,
                            file_path=str(file_path),
                            captured_at=snap_captured_at,
                            system_id="security_service",
                            resource_id=rid,
                            category="SECURITY_AUDIT_LOG",
                            state="PRESENT",
                            customer_reference=rec.get("subject_reference") or rec.get("customer_reference") or rec.get("user_id"),
                        )
                    )
                elif data_store == "legal_service" and collection == "retained_order_records":
                    # Non-personal order retention
                    pass
                elif data_store == "export_service" and collection == "customer_export_jobs":
                    email = rec.get("owner_email") or rec.get("email")
                    records.append(
                        EvidenceRecord(
                            evidence_id=evidence_id,
                            file_path=str(file_path),
                            captured_at=snap_captured_at,
                            system_id="export_service",
                            resource_id=rid,
                            category="USER_EXPORT",
                            state="PRESENT",
                            customer_reference=rec.get("customer_reference"),
                            email=email.lower() if email else None,
                            has_pii=True,
                        )
                    )

        return records

class ReadbackLogParser:
    @staticmethod
    def parse(file_path: Path, evidence_id: str, captured_at: str) -> List[EvidenceRecord]:
        records = []
        if not file_path.exists():
            return records

        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        traces = {}
        for line in lines:
            line_s = line.strip()
            if not line_s:
                continue

            m_ts = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)", line_s)
            line_time = m_ts.group(1) if m_ts else None

            # Try JSON parsing first (e.g. structured_service_events_*.log)
            m_json = re.search(r'(\{.*\})', line_s)
            if m_json:
                try:
                    data = json.loads(m_json.group(1))
                    if line_time:
                        data["event_time"] = line_time
                    tr = data.get("trace_id") or data.get("requestId")
                    if tr:
                        if tr not in traces:
                            traces[tr] = {}
                        traces[tr].update(data)
                        continue
                except Exception:
                    pass

            # Direct key-value log format like search_index_diagnostic
            if 'service=search_index_service' in line_s and 'event=record_lookup' in line_s:
                d = {}
                for kv in re.findall(r'(\w+)=([^"\s]+|"[^"]*")', line_s):
                    d[kv[0]] = kv[1].strip('"')
                sys_id = d.get("system")
                rid = d.get("resource_id")
                rtype = d.get("record_type")
                res = d.get("result")
                subj = d.get("subject_reference")

                email = subj if "@" in (subj or "") else None
                cust_ref = subj if subj and not email else None

                if rtype == "USER_PROFILE":
                    state = "ABSENT" if res == "NOT_FOUND" else "PRESENT"
                elif rtype == "SEARCH_INDEX_ENTRY":
                    state = "PRESENT" if res == "FOUND" else "ABSENT"
                elif rtype == "ANALYTICS_PROFILE":
                    state = "ANONYMIZED" if res == "ANONYMIZED" else "PRESENT"
                elif rtype == "SUPPORT_MESSAGE":
                    state = "PRESENT" if res == "IDENTIFIABLE" else "REDACTED"
                elif rtype == "DATA_FLOW":
                    state = "ACTIVE" if res == "ACTIVE" else "DISABLED"
                elif rtype == "BACKUP_ARCHIVE":
                    state = "ACTIVE" if res == "ACTIVE" else "BLOCKED"
                elif rtype == "SECURITY_AUDIT_LOG":
                    state = "PRESENT"
                else:
                    state = "PRESENT"

                records.append(EvidenceRecord(
                    evidence_id=evidence_id, file_path=str(file_path), captured_at=captured_at,
                    system_id=sys_id, resource_id=rid, category=rtype, state=state,
                    customer_reference=cust_ref, email=email.lower() if email else None,
                    has_pii=(state == "PRESENT" and rtype not in ("DATA_FLOW", "BACKUP_ARCHIVE", "SECURITY_AUDIT_LOG"))
                ))
                continue

            # Trace based key-value logs (trace_id=... or requestId=... or [tr-...] or | tr-...)
            m_tr = re.search(r"\b(tr-[\w\-]+|rb-[\w\-]+)\b", line_s) or re.search(r"(?:trace_id|requestId)=([\w\-]+)", line_s)
            if m_tr:
                tr = m_tr.group(1)
                if tr not in traces:
                    traces[tr] = {}
                if line_time and "event_time" not in traces[tr]:
                    traces[tr]["event_time"] = line_time
                m_svc = re.search(r"\[([\w_]+(?:service|platform)|support_replica)\]", line_s)
                if m_svc:
                    traces[tr]["service"] = m_svc.group(1)
                for kv in re.findall(r'(\w+)=([^"\s]+|"[^"]*")', line_s):
                    traces[tr][kv[0]] = kv[1].strip('"')
                continue

            # Direct line with resource_id
            d = {}
            for kv in re.findall(r'(\w+)=([^"\s]+|"[^"]*")', line_s):
                d[kv[0]] = kv[1].strip('"')
            if d.get("resource_id"):
                if line_time:
                    d["event_time"] = line_time
                traces[f"direct_{len(traces)}"] = d

        for tr, d in traces.items():
            svc = d.get("service") or d.get("logger") or d.get("function") or d.get("system")
            rid = d.get("resource_id")
            if not svc or not rid:
                continue

            # Resolve email, customer reference, and email_hash
            email = None
            cust_ref = None
            email_hash = None
            for k in ("email", "customer_email", "requester_email", "lookup_key", "match_key", "subject_key", "subject_ref", "subject_reference", "correlation_key", "matched_value"):
                v = d.get(k)
                if v and v != "null":
                    if "@" in v:
                        email = v.lower()
                    elif v.startswith("user_"):
                        cust_ref = v
                    elif len(v) == 64 and all(c in "0123456789abcdefABCDEF" for c in v):
                        email_hash = v.lower()

            http_status = str(d.get("http_status", ""))
            rows = str(d.get("rows", ""))
            result = str(d.get("result", ""))
            enabled = str(d.get("enabled", ""))
            restore_allowed = str(d.get("restore_allowed", ""))
            direct_identifiers = str(d.get("direct_identifiers", ""))

            category = ""
            state = "PRESENT"
            has_pii = False

            if "account" in svc or svc == "customer_account_service":
                category = "USER_PROFILE"
                state = "ABSENT" if (http_status == "404" or rows == "0") else "PRESENT"
                has_pii = (state == "PRESENT")
            elif "search" in svc:
                category = "SEARCH_INDEX_ENTRY"
                state = "PRESENT" if (result in ("hit", "FOUND") or d.get("total_hits") in ("1", 1, "true")) else "ABSENT"
                has_pii = (state == "PRESENT")
            elif "analytics" in svc:
                if d.get("email_opt_in") is not None or d.get("event") == "contact_lookup_completed":
                    category = "MARKETING_PROFILE"
                    state = "PRESENT" if rows in ("1", 1) else "ABSENT"
                    has_pii = (state == "PRESENT")
                elif direct_identifiers == "0" or (not email and not cust_ref):
                    category = "ANALYTICS_PROFILE"
                    state = "ANONYMIZED"
                    has_pii = False
                else:
                    category = "ANALYTICS_PROFILE"
                    has_pii = bool(email or d.get("phone") or cust_ref or direct_identifiers in ("1", "2"))
                    state = "PRESENT" if has_pii else "ANONYMIZED"
            elif "support" in svc:
                if str(d.get("marker_found", "")).lower() == "false":
                    category = "SUPPORT_ATTACHMENT"
                    state = "PRESENT"
                    has_pii = True
                else:
                    category = "SUPPORT_MESSAGE"
                    has_pii = bool(email or d.get("requester_name") or d.get("requester_phone"))
                    state = "PRESENT" if has_pii else "REDACTED"
            elif "integration" in svc or "connector" in svc:
                category = "DATA_FLOW"
                state = "ACTIVE" if enabled in ("true", "1", "True") else "DISABLED"
            elif "backup" in svc:
                category = "BACKUP_ARCHIVE"
                deletion_block = str(d.get("deletion_block", "")).lower()
                eligible = str(d.get("eligible", "")).lower()
                if restore_allowed in ("true", "1", "True") or deletion_block in ("false", "0") or (eligible in ("true", "1") and deletion_block != "true"):
                    state = "ACTIVE"
                else:
                    state = "BLOCKED"
            elif "security" in svc:
                category = "SECURITY_AUDIT_LOG"
                state = "PRESENT"

            if category:
                rec_captured_at = d.get("event_time") or captured_at
                records.append(EvidenceRecord(
                    evidence_id=evidence_id, file_path=str(file_path), captured_at=rec_captured_at,
                    system_id="support_platform" if svc == "support_replica" else ("search_service" if "search" in svc else ("account_service" if "account" in svc else ("analytics_platform" if "analytics" in svc else ("integration_service" if "integration" in svc or "connector" in svc else ("backup_service" if "backup" in svc else svc))))),
                    resource_id=rid, category=category, state=state,
                    customer_reference=cust_ref,
                    email=email,
                    email_hash=email_hash,
                    has_pii=has_pii
                ))

        return records

class SqlDumpParser:
    @staticmethod
    def parse(file_path: Path, evidence_id: str, captured_at: str) -> List[EvidenceRecord]:
        records = []
        if not file_path.exists():
            return records
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        conn = sqlite3.connect(":memory:")
        try:
            conn.executescript(content)
        except Exception:
            pass

        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [r[0] for r in cur.fetchall()]

        for tbl in tables:
            # Check customer_data_* tables with record_json
            if "customer_data_" in tbl:
                try:
                    cur.execute(f"SELECT * FROM {tbl}")
                    cols = [d[0] for d in cur.description]
                    for row in cur.fetchall():
                        r_dict = dict(zip(cols, row))
                        rid = r_dict.get("resource_id")
                        origin_sys = r_dict.get("origin_system", "")
                        rec_json_str = r_dict.get("record_json")
                        if not rec_json_str:
                            continue
                        try:
                            rj = json.loads(rec_json_str)
                        except Exception:
                            continue

                        category = ""
                        state = "PRESENT"
                        has_pii = False
                        email = rj.get("email") or rj.get("customer_email") or rj.get("owner_email") or rj.get("requester_email") or rj.get("subject_selector")
                        cust_ref = rj.get("customer_reference") or rj.get("user_id") or rj.get("subject_reference")
                        phone = rj.get("phone") or rj.get("requester_phone")
                        name = rj.get("full_name") or rj.get("display_name") or rj.get("requester_name")

                        if "document" in rj and isinstance(rj["document"], dict):
                            doc = rj["document"]
                            if not email:
                                email = doc.get("email")
                            if not cust_ref:
                                cust_ref = doc.get("customer_reference") or doc.get("user_id")
                            if not name:
                                name = doc.get("display_name")

                        if origin_sys == "account_service" or (rid and "account_" in rid):
                            origin_sys = "account_service"
                            category = "USER_PROFILE"
                            status = rj.get("account_status", "ACTIVE")
                            state = "ABSENT" if status == "DELETED" else "PRESENT"
                            has_pii = (state == "PRESENT")
                        elif origin_sys == "search_service" or (rid and "search_" in rid):
                            origin_sys = "search_service"
                            category = "SEARCH_INDEX_ENTRY"
                            state = "PRESENT"
                            has_pii = True
                        elif origin_sys == "analytics_platform" or (rid and "analytics_" in rid):
                            origin_sys = "analytics_platform"
                            category = "ANALYTICS_PROFILE"
                            has_pii = bool(email or phone or cust_ref or rj.get("email_hash"))
                            state = "PRESENT" if has_pii else "ANONYMIZED"
                        elif origin_sys == "support_platform" or (rid and "support_" in rid):
                            origin_sys = "support_platform"
                            category = "SUPPORT_MESSAGE"
                            has_pii = bool(email or phone or name)
                            state = "PRESENT" if has_pii else "REDACTED"
                        elif origin_sys == "integration_service" or (rid and "data_flow_" in rid):
                            origin_sys = "integration_service"
                            category = "DATA_FLOW"
                            enabled = rj.get("enabled", False)
                            state = "ACTIVE" if enabled in (True, "true", "True", 1) else "DISABLED"
                        elif origin_sys == "backup_service" or (rid and "backup_" in rid):
                            origin_sys = "backup_service"
                            category = "BACKUP_ARCHIVE"
                            allowed = rj.get("restore_allowed", False)
                            state = "ACTIVE" if allowed in (True, "true", "True", 1) else "BLOCKED"
                        elif origin_sys == "security_service" or (rid and "audit_record_" in rid):
                            origin_sys = "security_service"
                            category = "SECURITY_AUDIT_LOG"
                            state = "PRESENT"

                        if category:
                            records.append(EvidenceRecord(
                                evidence_id=evidence_id, file_path=str(file_path), captured_at=captured_at,
                                system_id=origin_sys, resource_id=rid, category=category, state=state,
                                customer_reference=cust_ref, email=email.lower() if email and "@" in email else None,
                                phone=phone, name=name, has_pii=has_pii
                            ))
                except Exception:
                    pass

            # Other standard SQL tables
            elif "customer_profiles" in tbl:
                try:
                    cur.execute(f"SELECT * FROM {tbl}")
                    cols = [d[0] for d in cur.description]
                    for row in cur.fetchall():
                        r_dict = dict(zip(cols, row))
                        rid = r_dict.get("resource_id")
                        uid = r_dict.get("user_id") or r_dict.get("customer_reference")
                        em = r_dict.get("email")
                        status = r_dict.get("account_status", "ACTIVE")
                        state = "ABSENT" if status == "DELETED" else "PRESENT"
                        records.append(EvidenceRecord(
                            evidence_id=evidence_id, file_path=str(file_path), captured_at=captured_at,
                            system_id="account_service", resource_id=rid, category="USER_PROFILE",
                            state=state, customer_reference=uid, email=em.lower() if em else None,
                            phone=r_dict.get("phone"), name=r_dict.get("full_name"), has_pii=(state == "PRESENT")
                        ))
                except Exception:
                    pass
            elif "search_documents" in tbl or "customer_search" in tbl:
                try:
                    cur.execute(f"SELECT * FROM {tbl}")
                    cols = [d[0] for d in cur.description]
                    for row in cur.fetchall():
                        r_dict = dict(zip(cols, row))
                        rid = r_dict.get("resource_id")
                        em = r_dict.get("email")
                        uid = r_dict.get("customer_reference") or r_dict.get("user_id")
                        records.append(EvidenceRecord(
                            evidence_id=evidence_id, file_path=str(file_path), captured_at=captured_at,
                            system_id="search_service", resource_id=rid, category="SEARCH_INDEX_ENTRY",
                            state="PRESENT", customer_reference=uid, email=em.lower() if em else None,
                            name=r_dict.get("display_name"), has_pii=True
                        ))
                except Exception:
                    pass
            elif "customer_analytics" in tbl:
                try:
                    cur.execute(f"SELECT * FROM {tbl}")
                    cols = [d[0] for d in cur.description]
                    for row in cur.fetchall():
                        r_dict = dict(zip(cols, row))
                        rid = r_dict.get("resource_id")
                        em = r_dict.get("email")
                        uid = r_dict.get("customer_reference") or r_dict.get("user_id")
                        has_pii = bool(em or r_dict.get("phone"))
                        state = "PRESENT" if has_pii else "ANONYMIZED"
                        records.append(EvidenceRecord(
                            evidence_id=evidence_id, file_path=str(file_path), captured_at=captured_at,
                            system_id="analytics_platform", resource_id=rid, category="ANALYTICS_PROFILE",
                            state=state, customer_reference=uid, email=em.lower() if em else None,
                            has_pii=has_pii
                        ))
                except Exception:
                    pass
            elif "backup_restore" in tbl:
                try:
                    cur.execute(f"SELECT * FROM {tbl}")
                    cols = [d[0] for d in cur.description]
                    for row in cur.fetchall():
                        r_dict = dict(zip(cols, row))
                        rid = r_dict.get("resource_id")
                        allowed = str(r_dict.get("restore_allowed")) in ("1", "True", "true")
                        state = "ACTIVE" if allowed else "BLOCKED"
                        records.append(EvidenceRecord(
                            evidence_id=evidence_id, file_path=str(file_path), captured_at=captured_at,
                            system_id="backup_service", resource_id=rid, category="BACKUP_ARCHIVE",
                            state=state, customer_reference=r_dict.get("customer_reference"),
                            email=r_dict.get("customer_email").lower() if r_dict.get("customer_email") else None
                        ))
                except Exception:
                    pass
            elif "connector_subscriptions" in tbl:
                try:
                    cur.execute(f"SELECT * FROM {tbl}")
                    cols = [d[0] for d in cur.description]
                    for row in cur.fetchall():
                        r_dict = dict(zip(cols, row))
                        rid = r_dict.get("resource_id")
                        enabled = str(r_dict.get("enabled")) in ("1", "True", "true")
                        state = "ACTIVE" if enabled else "DISABLED"
                        records.append(EvidenceRecord(
                            evidence_id=evidence_id, file_path=str(file_path), captured_at=captured_at,
                            system_id="integration_service", resource_id=rid, category="DATA_FLOW",
                            state=state, customer_reference=r_dict.get("customer_reference"),
                            email=r_dict.get("customer_email").lower() if r_dict.get("customer_email") else None
                        ))
                except Exception:
                    pass
            elif "support_records" in tbl:
                try:
                    cur.execute(f"SELECT * FROM {tbl}")
                    cols = [d[0] for d in cur.description]
                    for row in cur.fetchall():
                        r_dict = dict(zip(cols, row))
                        rid = r_dict.get("resource_id")
                        em = r_dict.get("requester_email")
                        has_pii = bool(em or r_dict.get("requester_name") or r_dict.get("requester_phone"))
                        state = "PRESENT" if has_pii else "REDACTED"
                        records.append(EvidenceRecord(
                            evidence_id=evidence_id, file_path=str(file_path), captured_at=captured_at,
                            system_id="support_platform", resource_id=rid, category="SUPPORT_MESSAGE",
                            state=state, customer_reference=r_dict.get("customer_reference"),
                            email=em.lower() if em else None, has_pii=has_pii
                        ))
                except Exception:
                    pass
            elif "customer_exports" in tbl:
                try:
                    cur.execute(f"SELECT * FROM {tbl}")
                    cols = [d[0] for d in cur.description]
                    for row in cur.fetchall():
                        r_dict = dict(zip(cols, row))
                        rid = r_dict.get("resource_id")
                        em = r_dict.get("owner_email")
                        records.append(EvidenceRecord(
                            evidence_id=evidence_id, file_path=str(file_path), captured_at=captured_at,
                            system_id="export_service", resource_id=rid, category="USER_EXPORT",
                            state="PRESENT", customer_reference=r_dict.get("customer_reference"),
                            email=em.lower() if em else None, has_pii=True
                        ))
                except Exception:
                    pass
            elif "security_audit_records" in tbl:
                try:
                    cur.execute(f"SELECT * FROM {tbl}")
                    cols = [d[0] for d in cur.description]
                    for row in cur.fetchall():
                        r_dict = dict(zip(cols, row))
                        rid = r_dict.get("resource_id")
                        records.append(EvidenceRecord(
                            evidence_id=evidence_id, file_path=str(file_path), captured_at=captured_at,
                            system_id="security_service", resource_id=rid, category="SECURITY_AUDIT_LOG",
                            state="PRESENT", customer_reference=r_dict.get("subject_reference")
                        ))
                except Exception:
                    pass

        conn.close()
        return records

def _clean_ocr_digits(val: str) -> str:
    """Normalize common OCR character confusions in numeric suffixes."""
    trans = str.maketrans({"O": "0", "o": "0", "l": "1", "I": "1", "S": "5", "s": "5"})
    return val.translate(trans)

def _fix_resource_id(rid: str) -> str:
    """Format and validate resource IDs with standard prefix_digits conventions."""
    if "_" in rid:
        prefix, suffix = rid.rsplit("_", 1)
        return f"{prefix}_{_clean_ocr_digits(suffix)}"
    return rid

def _fix_email(em: str) -> str:
    """Fix common OCR scanning errors in email addresses."""
    em = re.sub(r"\s*@\s*", "@", em)
    em = em.lower().replace(",", ".")
    em = re.sub(r"\.c0m$", ".com", em)
    em = re.sub(r"\.c0rn$", ".com", em)
    em = re.sub(r"\.corn$", ".com", em)
    em = re.sub(r"\.cor$", ".com", em)
    return em

IMAGE_STATUS_MAP = {
    "PRESENT": "PRESENT",
    "FOUND": "PRESENT",
    "IDENTIFIABLE": "PRESENT",
    "READY": "PRESENT",
    "COLLECTING": "PRESENT",
    "PACKAGING": "PRESENT",
    "LIVE": "PRESENT",
    "DELIVERED": "PRESENT",
    "IN TRANSIT": "PRESENT",
    "HEALTHY": "PRESENT",
    "VALID": "PRESENT",
    "ACTIVE": "ACTIVE",
    "DISABLED": "DISABLED",
    "STOPPED": "DISABLED",
    "BLOCKED": "BLOCKED",
    "ABSENT": "ABSENT",
    "NOT_FOUND": "ABSENT",
    "DELETED": "ABSENT",
    "REDACTED": "REDACTED",
    "ANONYMIZED": "ANONYMIZED",
}

def gemini_vision_fallback(file_path: Path) -> str:
    """Fallback vision call using Gemini API if Tesseract fails, cached to .gemini_vision_cache.json."""
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        logger.info(f"GEMINI_API_KEY not configured in environment or .env; skipping vision fallback for {file_path}")
        return ""

    cache_path = Path(__file__).parent / ".gemini_vision_cache.json"
    cache = {}
    if cache_path.exists():
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cache = json.load(f)
        except Exception:
            cache = {}

    key = str(file_path.resolve())
    try:
        mtime = file_path.stat().st_mtime
    except Exception:
        mtime = 0

    if key in cache and cache[key].get("mtime") == mtime:
        return cache[key].get("text", "")

    try:
        with open(file_path, "rb") as f:
            img_b64 = base64.b64encode(f.read()).decode("utf-8")

        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}"
        payload = {
            "contents": [{
                "parts": [
                    {"text": "Transcribe all visible text exactly as displayed in this console screenshot without any commentary or Markdown formatting."},
                    {
                        "inline_data": {
                            "mime_type": "image/png",
                            "data": img_b64
                        }
                    }
                ]
            }]
        }
        resp = requests.post(url, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        text = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "").strip()

        if text:
            cache[key] = {
                "mtime": mtime,
                "text": text
            }
            try:
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump(cache, f, indent=2)
            except Exception:
                pass

        return text
    except Exception as e:
        logger.warning(f"Gemini vision fallback failed for {file_path}: {e}")
        return ""


def ocr_image(file_path: Path) -> str:
    """Performs OCR on an image file with grayscale and 2x Lanczos upscale, cached to .ocr_cache.json, with Gemini vision fallback."""
    cache_path = Path(__file__).parent / ".ocr_cache.json"
    cache = {}
    if cache_path.exists():
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cache = json.load(f)
        except Exception:
            cache = {}

    key = str(file_path.resolve())
    try:
        mtime = file_path.stat().st_mtime
    except Exception:
        mtime = 0

    if key in cache and cache[key].get("mtime") == mtime:
        return cache[key].get("text", "")

    try:
        from PIL import Image
        import pytesseract

        tess_bin = Path("tesseract_bin").resolve()
        if (tess_bin / "tesseract.exe").exists():
            pytesseract.pytesseract.tesseract_cmd = str(tess_bin / "tesseract.exe")
            os.environ["TESSDATA_PREFIX"] = str(tess_bin / "tessdata")

        img_orig = Image.open(file_path)
        w, h = img_orig.size
        img_prep = img_orig.convert("L").resize((w * 2, h * 2), Image.Resampling.LANCZOS)

        txt6 = pytesseract.image_to_string(img_prep, config="--psm 6").strip()
        txt4 = pytesseract.image_to_string(img_prep, config="--psm 4").strip()
        best_txt = txt4 if len(txt4) > len(txt6) and "audit_record_" in txt4 else txt6

        if not best_txt:
            logger.info(f"Tesseract returned empty text for {file_path}; attempting Gemini vision fallback")
            best_txt = gemini_vision_fallback(file_path)

        if best_txt:
            cache[key] = {
                "mtime": mtime,
                "text": best_txt
            }
            try:
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump(cache, f, indent=2)
            except Exception:
                pass

        return best_txt
    except Exception as e:
        logger.warning(f"Local OCR failed for {file_path}: {e}. Attempting Gemini vision fallback.")
        fallback_txt = gemini_vision_fallback(file_path)
        if fallback_txt:
            cache[key] = {
                "mtime": mtime,
                "text": fallback_txt
            }
            try:
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump(cache, f, indent=2)
            except Exception:
                pass
            return fallback_txt
        return ""


class ImageConsoleParser:
    """Parses evidence records from console screenshots using OCR and regex extraction."""
    _EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+,-]+(?:\s*@\s*)[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
    _PHONE_RE = re.compile(r"\+\d{1,3}[\d\s\-]{7,}\d")
    _USER_REF_RE = re.compile(r"\buser[_\s](\d+)\b")

    @classmethod
    def parse(cls, file_path: Path, evidence_id: str, captured_at: str) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []
        if not file_path.exists():
            return records

        text = ocr_image(file_path)
        if not text:
            logger.warning(f"OCR returned empty text or failed for {file_path}")
            return records

        lines = [l.strip() for l in text.splitlines() if l.strip()]
        full_text = " \n ".join(lines)

        # 1. Integration Service / BridgeOps / Connector Management
        if "BridgeOps" in full_text or re.search(r"\bdata_flow_\d+\b", full_text):
            found_flows = set()
            for line in lines:
                m_df = re.search(r"\b(data_flow_\w+)\b", line)
                m_em = cls._EMAIL_RE.search(line)
                if m_df and m_em:
                    df_id = _fix_resource_id(m_df.group(1))
                    if df_id not in found_flows:
                        found_flows.add(df_id)
                        em = _fix_email(m_em.group(0))
                        records.append(EvidenceRecord(
                            evidence_id=evidence_id, file_path=str(file_path), captured_at=captured_at,
                            system_id="integration_service", resource_id=df_id, category="DATA_FLOW",
                            state="ACTIVE", email=em, has_pii=False
                        ))

        # 2. Customer Operations / Account Admin Console
        elif "Customer Operations" in full_text or re.search(r"\baccount_\d+\b", full_text):
            m_acc = re.search(r"\b(account_\w+)\b", full_text)
            m_user = cls._USER_REF_RE.search(full_text)
            m_email = cls._EMAIL_RE.search(full_text)
            m_phone = cls._PHONE_RE.search(full_text)

            name = None
            for line in lines:
                m_name = re.search(r"\|\s*[O0]\s+([A-Z][a-z]+ [A-Z][a-z]+)", line)
                if m_name:
                    name = m_name.group(1).strip()
                    break

            cust_ref = f"user_{m_user.group(1)}" if m_user else None
            email = _fix_email(m_email.group(0)) if m_email else None
            phone = m_phone.group(0).strip() if m_phone else None
            acc_id = _fix_resource_id(m_acc.group(1)) if m_acc else None

            if acc_id:
                records.append(EvidenceRecord(
                    evidence_id=evidence_id, file_path=str(file_path), captured_at=captured_at,
                    system_id="account_service", resource_id=acc_id, category="USER_PROFILE",
                    state="PRESENT", customer_reference=cust_ref, email=email,
                    phone=phone, name=name, has_pii=True
                ))

            m_supp = re.search(r"\b(support_\w+)\b", full_text)
            if m_supp:
                supp_id = _fix_resource_id(m_supp.group(1))
                records.append(EvidenceRecord(
                    evidence_id=evidence_id, file_path=str(file_path), captured_at=captured_at,
                    system_id="support_platform", resource_id=supp_id, category="SUPPORT_MESSAGE",
                    state="PRESENT", customer_reference=cust_ref, email=email, has_pii=True
                ))

        # 3. Pulse Analytics / Users
        elif "Pulse Analytics" in full_text or re.search(r"\banalytics_\d+\b", full_text):
            m_ana = re.search(r"\b(analytics_\w+)\b", full_text)
            m_user = cls._USER_REF_RE.search(full_text)
            m_email = cls._EMAIL_RE.search(full_text)
            name = None
            for line in lines:
                m_name = re.search(r"^[U|O]\s+([A-Z][a-z]+ [A-Z][a-z]+)", line)
                if m_name:
                    name = m_name.group(1).strip()
                    break

            ana_id = _fix_resource_id(m_ana.group(1)) if m_ana else None
            cust_ref = f"user_{m_user.group(1)}" if m_user else None
            email = _fix_email(m_email.group(0)) if m_email else None

            if ana_id:
                records.append(EvidenceRecord(
                    evidence_id=evidence_id, file_path=str(file_path), captured_at=captured_at,
                    system_id="analytics_platform", resource_id=ana_id, category="ANALYTICS_PROFILE",
                    state="PRESENT", customer_reference=cust_ref, email=email,
                    name=name, has_pii=True
                ))

        # 4. Vault Recovery Manager / Backup
        elif "Recovery Manager" in full_text or re.search(r"\bbackup_\d+\b", full_text):
            found_backups = set()
            for line in lines:
                m_b = re.search(r"\b(backup_\w+)\b", line)
                m_em = cls._EMAIL_RE.search(line)
                if m_b and m_em:
                    bid = _fix_resource_id(m_b.group(1))
                    if bid not in found_backups:
                        found_backups.add(bid)
                        em = _fix_email(m_em.group(0))
                        records.append(EvidenceRecord(
                            evidence_id=evidence_id, file_path=str(file_path), captured_at=captured_at,
                            system_id="backup_service", resource_id=bid, category="BACKUP_ARCHIVE",
                            state="ACTIVE", email=em, has_pii=False
                        ))
            m_b_panel = re.search(r"Archives Updated moments ago\s*-\s*\d+\s*records\s+(backup_\w+)", full_text)
            if m_b_panel:
                bid = _fix_resource_id(m_b_panel.group(1))
                if bid not in found_backups:
                    found_backups.add(bid)
                    m_em = cls._EMAIL_RE.search(full_text[m_b_panel.end():])
                    em = _fix_email(m_em.group(0)) if m_em else None
                    records.append(EvidenceRecord(
                        evidence_id=evidence_id, file_path=str(file_path), captured_at=captured_at,
                        system_id="backup_service", resource_id=bid, category="BACKUP_ARCHIVE",
                        state="ACTIVE", email=em, has_pii=False
                    ))

        # 5. Customer Download Center / Exports
        elif "Customer Download Center" in full_text or re.search(r"\bexport_\d+\b", full_text):
            found_exports = set()
            for line in lines:
                m_exp = re.search(r"\b(export_\w+)\b", line)
                m_em = cls._EMAIL_RE.search(line)
                if m_exp and m_em:
                    eid = _fix_resource_id(m_exp.group(1))
                    if eid not in found_exports:
                        found_exports.add(eid)
                        em = _fix_email(m_em.group(0))
                        records.append(EvidenceRecord(
                            evidence_id=evidence_id, file_path=str(file_path), captured_at=captured_at,
                            system_id="export_service", resource_id=eid, category="USER_EXPORT",
                            state="PRESENT", email=em, has_pii=True
                        ))

        # 6. Audience Operations / Marketing
        elif "Audience Operations" in full_text or re.search(r"\bmarketing_\d+\b", full_text):
            m_mkt = re.search(r"\b(marketing_\w+)\b", full_text)
            m_em = cls._EMAIL_RE.search(full_text)
            m_phone = cls._PHONE_RE.search(full_text)
            name = None
            for line in lines:
                m_name = re.search(r"([A-Za-z\-]+ [A-Za-z]+)\s+Live", line)
                if m_name:
                    name = m_name.group(1).strip()
                    break

            mid = _fix_resource_id(m_mkt.group(1)) if m_mkt else None
            em = _fix_email(m_em.group(0)) if m_em else None
            phone = m_phone.group(0).strip() if m_phone else None

            if mid:
                records.append(EvidenceRecord(
                    evidence_id=evidence_id, file_path=str(file_path), captured_at=captured_at,
                    system_id="marketing_service", resource_id=mid, category="MARKETING_PROFILE",
                    state="PRESENT", email=em, phone=phone, name=name, has_pii=True
                ))

        # 7. Search Console / Inspector
        elif "Search Console" in full_text or re.search(r"\bsearch_\d+\b", full_text):
            found_search = set()
            for line in lines:
                m_s = re.search(r"\b(search_\w+)\b", line)
                m_em = cls._EMAIL_RE.search(line)
                if m_s and m_em:
                    sid = _fix_resource_id(m_s.group(1))
                    if sid not in found_search:
                        found_search.add(sid)
                        em = _fix_email(m_em.group(0))
                        m_u = cls._USER_REF_RE.search(line)
                        cust_ref = f"user_{m_u.group(1)}" if m_u else None
                        m_n = re.search(rf"{re.escape(sid)}\s+([A-Z][a-z]+ [A-Z][a-z]+)", line)
                        name = m_n.group(1).strip() if m_n else None
                        records.append(EvidenceRecord(
                            evidence_id=evidence_id, file_path=str(file_path), captured_at=captured_at,
                            system_id="search_service", resource_id=sid, category="SEARCH_INDEX_ENTRY",
                            state="PRESENT", customer_reference=cust_ref, email=em,
                            name=name, has_pii=True
                        ))

        # 8. Sentinel / Security Audit
        elif "Sentinel" in full_text or re.search(r"\baudit_record_\d+\b", full_text):
            m_u = re.search(r"Subject filter:\s*user[_\s](\d+)", full_text)
            cust_ref = f"user_{m_u.group(1)}" if m_u else None
            found_audits = set()
            for m_aud in re.finditer(r"\b(audit_record_\w+)\b", full_text):
                arid = _fix_resource_id(m_aud.group(1))
                if arid not in found_audits:
                    found_audits.add(arid)
                    records.append(EvidenceRecord(
                        evidence_id=evidence_id, file_path=str(file_path), captured_at=captured_at,
                        system_id="security_service", resource_id=arid, category="SECURITY_AUDIT_LOG",
                        state="PRESENT", customer_reference=cust_ref, has_pii=False
                    ))

        # 9. Helpline Console / Support Ticket
        elif "Helpline Console" in full_text or re.search(r"\bsupport_\d+\b", full_text):
            m_supp = re.search(r"\b(support_\w+)\b", full_text)
            m_em = cls._EMAIL_RE.search(full_text)
            name = None
            for line in lines:
                m_n = re.search(r"support_\w+\s*-\s*([A-Z][a-z]+ [A-Z][a-z]+)", line)
                if m_n:
                    name = m_n.group(1).strip()
                    break

            sid = _fix_resource_id(m_supp.group(1)) if m_supp else None
            em = _fix_email(m_em.group(0)) if m_em else None

            if sid:
                records.append(EvidenceRecord(
                    evidence_id=evidence_id, file_path=str(file_path), captured_at=captured_at,
                    system_id="support_platform", resource_id=sid, category="SUPPORT_MESSAGE",
                    state="PRESENT", email=em, name=name, has_pii=True
                ))

        # 10. Customer Reference Registry (retained reference overview)
        elif "Customer Reference Registry" in full_text or ("Customer references" in full_text and "Retained reference" in full_text):
            pass

        # 11. Object Storage Browser
        elif "Object Storage" in full_text or "northstar-customer-data" in full_text:
            found_objs = set()
            for line in lines:
                m_dc = re.search(r"\b(delivery_confirmation_(\d+))\.(pdf|jpg)\b", line)
                if m_dc:
                    rid = m_dc.group(1)
                    if rid not in found_objs:
                        found_objs.add(rid)
                        records.append(EvidenceRecord(
                            evidence_id=evidence_id, file_path=str(file_path), captured_at=captured_at,
                            system_id="object_storage", resource_id=rid, category="SUPPORT_ATTACHMENT",
                            state="PRESENT", has_pii=True
                        ))
                m_ret = re.search(r"\b(return_label_(\d+))\.(pdf|jpg)\b", line)
                if m_ret:
                    rid = m_ret.group(1)
                    if rid not in found_objs:
                        found_objs.add(rid)
                        records.append(EvidenceRecord(
                            evidence_id=evidence_id, file_path=str(file_path), captured_at=captured_at,
                            system_id="object_storage", resource_id=rid, category="SUPPORT_ATTACHMENT",
                            state="PRESENT", has_pii=True
                        ))
                m_exp = re.search(r"\b(customer_export_[\d-]+)\.zip\b", line)
                if m_exp:
                    rid = m_exp.group(1)
                    if rid not in found_objs:
                        found_objs.add(rid)
                        records.append(EvidenceRecord(
                            evidence_id=evidence_id, file_path=str(file_path), captured_at=captured_at,
                            system_id="object_storage", resource_id=rid, category="USER_EXPORT",
                            state="PRESENT", has_pii=True
                        ))

        if not records:
            logger.warning(f"Could not extract recognizable records from OCR text of {file_path}")

        return records


class SpecializedParser:
    @staticmethod
    def parse_pdf(file_path: Path, evidence_id: str, captured_at: str) -> List[EvidenceRecord]:
        records = []
        try:
            import pypdf
            reader = pypdf.PdfReader(str(file_path))
            full_text = "\n".join(page.extract_text() or "" for page in reader.pages)

            m_supp = re.search(r"\b(support_\d+)\b", full_text)
            m_email = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", full_text)
            m_phone = re.search(r"\+\d[\d\s\-]{8,}\d", full_text)
            m_user = re.search(r"\b(user_\d+)\b", full_text)
            m_audit = re.search(r"\b(audit_record_\d+)\b", full_text)

            if "DELIVERY ADDRESS CORRECTION" in full_text.upper() or "ATTACHMENT" in full_text.upper():
                rid = m_supp.group(1) if m_supp else "support_attachment"
                em = m_email.group(0).lower() if m_email else None
                phone = m_phone.group(0) if m_phone else None
                name_match = re.search(r"Detail\s*\n\s*([A-Z][a-z]+ [A-Z][a-z]+)", full_text)
                name = name_match.group(1).strip() if name_match else None
                records.append(EvidenceRecord(
                    evidence_id=evidence_id, file_path=str(file_path), captured_at=captured_at,
                    system_id="support_platform", resource_id=rid, category="SUPPORT_ATTACHMENT",
                    state="PRESENT", email=em, phone=phone, name=name, has_pii=True
                ))
            elif "COMPLIANCE JOURNAL" in full_text.upper() or "SECURITY" in full_text.upper():
                if m_audit and m_user:
                    records.append(EvidenceRecord(
                        evidence_id=evidence_id, file_path=str(file_path), captured_at=captured_at,
                        system_id="security_service", resource_id=m_audit.group(1), category="SECURITY_AUDIT_LOG",
                        state="PRESENT", customer_reference=m_user.group(1)
                    ))
        except Exception:
            pass
        return records

    @staticmethod
    def parse_json(file_path: Path, evidence_id: str, captured_at: str) -> List[EvidenceRecord]:
        records = []
        name = file_path.name
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if "customer_analytics_report" in name:
            for r in data.get("records", []):
                rid = r.get("resource_id")
                em = r.get("email")
                has_pii = bool(em or r.get("phone") or r.get("user_id"))
                state = "PRESENT" if has_pii else "ANONYMIZED"
                records.append(EvidenceRecord(
                    evidence_id=evidence_id, file_path=str(file_path), captured_at=captured_at,
                    system_id="analytics_platform", resource_id=rid, category="ANALYTICS_PROFILE",
                    state=state, customer_reference=r.get("user_id"),
                    email=em.lower() if em else None, has_pii=has_pii
                ))
        elif "customer_export_jobs" in name:
            for job in data.get("records", data.get("jobs", [])):
                rid = job.get("resource_id") or job.get("job_id") or job.get("export_id")
                em = job.get("owner_email") or job.get("user_email") or job.get("email")
                records.append(EvidenceRecord(
                    evidence_id=evidence_id, file_path=str(file_path), captured_at=captured_at,
                    system_id="export_service", resource_id=rid or "export_001", category="USER_EXPORT",
                    state="PRESENT", email=em.lower() if em else None, has_pii=True
                ))
        else:
            # Generic structured records files (e.g. security_audit_ledger, connector_configurations, customer_export_manifest)
            for item in data.get("records", []):
                if isinstance(item, dict) and "system" in item and "resource_id" in item:
                    rid = item.get("resource_id")
                    sys_id = item.get("system")
                    rtype = item.get("record_type")
                    res = item.get("result")
                    subj = item.get("subject_reference")
                    email = subj if "@" in (subj or "") else None
                    cust_ref = subj if subj and not email else None
                    rec_cap = item.get("recorded_at") or captured_at
                    
                    category = ""
                    state = "PRESENT"
                    has_pii = False
                    if sys_id == "account_service" or rtype == "USER_PROFILE":
                        category = "USER_PROFILE"
                        state = "ABSENT" if res in ("NOT_FOUND", "DELETED") else "PRESENT"
                        has_pii = (state == "PRESENT")
                    elif sys_id == "search_service" or rtype == "SEARCH_INDEX_ENTRY":
                        category = "SEARCH_INDEX_ENTRY"
                        state = "PRESENT" if res == "FOUND" else "ABSENT"
                        has_pii = True
                    elif sys_id == "analytics_platform" or rtype == "ANALYTICS_PROFILE":
                        category = "ANALYTICS_PROFILE"
                        has_pii = (res == "IDENTIFIABLE")
                        state = "PRESENT" if has_pii else "ANONYMIZED"
                    elif sys_id == "support_platform" or rtype in ("SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT"):
                        category = "SUPPORT_MESSAGE"
                        has_pii = (res == "IDENTIFIABLE" or res == "FOUND")
                        state = "PRESENT" if has_pii else "REDACTED"
                    elif sys_id == "integration_service" or rtype == "DATA_FLOW":
                        category = "DATA_FLOW"
                        state = "ACTIVE" if res in ("ACTIVE", "ENABLED") else "DISABLED"
                    elif sys_id == "backup_service" or rtype == "BACKUP_ARCHIVE":
                        category = "BACKUP_ARCHIVE"
                        state = "ACTIVE" if res in ("ACTIVE", "RESTORE_ALLOWED") else "BLOCKED"
                    elif sys_id == "security_service" or rtype == "SECURITY_AUDIT_LOG":
                        category = "SECURITY_AUDIT_LOG"
                        state = "PRESENT"
                    elif sys_id == "export_service" or rtype == "USER_EXPORT":
                        category = "USER_EXPORT"
                        state = "PRESENT" if res == "FOUND" else "ABSENT"
                        has_pii = True

                    if category:
                        records.append(EvidenceRecord(
                            evidence_id=evidence_id, file_path=str(file_path), captured_at=rec_cap,
                            system_id=sys_id, resource_id=rid, category=category, state=state,
                            customer_reference=cust_ref, email=email.lower() if email else None,
                            has_pii=has_pii
                        ))

        return records
