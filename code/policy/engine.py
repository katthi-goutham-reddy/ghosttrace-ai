"""Policy Evaluation & Remediation Planning Engine for GhostTrace AI.

Applies deletion_rules.csv to discovered resource states at audit_at,
identifies compliance violations, generates ordered remediation plans,
and specifies verification checks.
"""
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple, Any

from .rules import (
    CATEGORY_ACTION_MAP,
    PHASE_ORDER,
    FINDING_OP_ORDER,
    REMEDIATION_OP_ORDER,
    VERIFICATION_OP_ORDER,
)
from ..evidence.models import EvidenceRecord

@dataclass
class AuditStep:
    step_no: int
    phase: str
    system_id: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_no": self.step_no,
            "phase": self.phase,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation,
            "state": self.state,
            "evidence_id": self.evidence_id,
        }

class PolicyEngine:
    def __init__(self, category_action_map: Optional[Dict[str, str]] = None):
        self.category_action_map = category_action_map or CATEGORY_ACTION_MAP

    def evaluate_resource(
        self, record: EvidenceRecord
    ) -> Tuple[bool, Optional[Dict[str, str]], Optional[Dict[str, str]], Dict[str, str]]:
        """Evaluates a single resource against policy rules.
        
        Returns:
            (is_violation, finding_spec, remediation_spec, verification_spec)
        """
        cat = record.category
        req_action = self.category_action_map.get(cat, "DELETE")
        state = record.state.upper()
        has_pii = record.has_pii

        is_violation = False
        finding_spec = None
        remediation_spec = None
        verification_spec = None

        if req_action == "DELETE":
            if state != "ABSENT":
                is_violation = True
                finding_spec = {
                    "operation": "REPORT_REMAINING_RECORD",
                    "state": "PRESENT",
                }
                remediation_spec = {
                    "operation": "DELETE_RECORD",
                    "state": "ABSENT",
                }
            verification_spec = {
                "operation": "VERIFY_RECORD_ABSENT",
                "state": "ABSENT",
            }

        elif req_action == "REDACT":
            # For support messages and account tombstones
            if has_pii or state == "PRESENT":
                is_violation = True
                finding_spec = {
                    "operation": "REPORT_EXPOSED_PII",
                    "state": "PRESENT",
                }
                remediation_spec = {
                    "operation": "REDACT_RECORD",
                    "state": "REDACTED",
                }
            verification_spec = {
                "operation": "VERIFY_RECORD_REDACTED",
                "state": "REDACTED",
            }

        elif req_action == "ANONYMIZE":
            if has_pii or state != "ANONYMIZED":
                is_violation = True
                finding_spec = {
                    "operation": "REPORT_EXPOSED_PII",
                    "state": "PRESENT",
                }
                remediation_spec = {
                    "operation": "ANONYMIZE_RECORD",
                    "state": "ANONYMIZED",
                }
            verification_spec = {
                "operation": "VERIFY_RECORD_ANONYMIZED",
                "state": "ANONYMIZED",
            }

        elif req_action == "DISABLE":
            if state == "ACTIVE":
                is_violation = True
                finding_spec = {
                    "operation": "REPORT_ACTIVE_DATA_FLOW",
                    "state": "ACTIVE",
                }
                remediation_spec = {
                    "operation": "DISABLE_DATA_FLOW",
                    "state": "DISABLED",
                }
            verification_spec = {
                "operation": "VERIFY_DATA_FLOW_DISABLED",
                "state": "DISABLED",
            }

        elif req_action in ("BLOCK", "RETAIN"):
            if cat == "BACKUP_ARCHIVE":
                if state == "ACTIVE":
                    is_violation = True
                    finding_spec = {
                        "operation": "REPORT_RESTORE_RISK",
                        "state": "ACTIVE",
                    }
                    remediation_spec = {
                        "operation": "BLOCK_RESTORE",
                        "state": "BLOCKED",
                    }
                verification_spec = {
                    "operation": "VERIFY_RESTORE_BLOCKED",
                    "state": "BLOCKED",
                }
            elif cat in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"):
                # Always retained
                is_violation = False
                verification_spec = {
                    "operation": "VERIFY_RECORD_PRESENT",
                    "state": "PRESENT",
                }

        if verification_spec is None:
            verification_spec = {
                "operation": "VERIFY_RECORD_ABSENT",
                "state": "ABSENT",
            }

        return is_violation, finding_spec, remediation_spec, verification_spec

    def evaluate_case(
        self, resource_states: Dict[Tuple[str, str], EvidenceRecord]
    ) -> Tuple[str, List[AuditStep]]:
        """Evaluates all resource states for a case.
        
        Returns:
            (deletion_status, steps)
        """
        if not resource_states:
            return "COMPLETE", []

        raw_findings = []
        raw_remediations = []
        raw_verifications = []

        is_case_incomplete = False

        for (sys_id, rid), rec in resource_states.items():
            is_viol, find_spec, rem_spec, ver_spec = self.evaluate_resource(rec)

            if is_viol:
                is_case_incomplete = True
                raw_findings.append({
                    "phase": "FINDING",
                    "system_id": sys_id,
                    "resource_id": rid,
                    "operation": find_spec["operation"],
                    "state": find_spec["state"],
                    "evidence_id": rec.evidence_id,
                })
                raw_remediations.append({
                    "phase": "REMEDIATION",
                    "system_id": sys_id,
                    "resource_id": rid,
                    "operation": rem_spec["operation"],
                    "state": rem_spec["state"],
                    "evidence_id": "",
                })

            raw_verifications.append({
                "phase": "VERIFICATION",
                "system_id": sys_id,
                "resource_id": rid,
                "operation": ver_spec["operation"],
                "state": ver_spec["state"],
                "evidence_id": rec.evidence_id if not is_viol else "",
            })

        deletion_status = "INCOMPLETE" if is_case_incomplete else "COMPLETE"

        # If case is INCOMPLETE, all verification steps must use evidence_id: ""
        if deletion_status == "INCOMPLETE":
            for v in raw_verifications:
                v["evidence_id"] = ""

        # Sort steps by specification contract
        def sort_key(s: Dict[str, Any]) -> Tuple[int, int, str, str]:
            phase = s["phase"]
            phase_idx = PHASE_ORDER.get(phase, 99)
            op = s["operation"]
            if phase == "FINDING":
                op_idx = FINDING_OP_ORDER.get(op, 99)
            elif phase == "REMEDIATION":
                op_idx = REMEDIATION_OP_ORDER.get(op, 99)
            elif phase == "VERIFICATION":
                op_idx = VERIFICATION_OP_ORDER.get(op, 99)
            else:
                op_idx = 99
            return (phase_idx, op_idx, s["system_id"], s["resource_id"])

        sorted_steps_raw = []
        if deletion_status == "INCOMPLETE":
            raw_findings.sort(key=sort_key)
            raw_remediations.sort(key=sort_key)
            raw_verifications.sort(key=sort_key)
            sorted_steps_raw.extend(raw_findings)
            sorted_steps_raw.extend(raw_remediations)
            sorted_steps_raw.extend(raw_verifications)
        else:
            raw_verifications.sort(key=sort_key)
            sorted_steps_raw.extend(raw_verifications)

        # Number steps consecutively from 1
        steps = []
        for idx, s in enumerate(sorted_steps_raw, start=1):
            steps.append(
                AuditStep(
                    step_no=idx,
                    phase=s["phase"],
                    system_id=s["system_id"],
                    resource_id=s["resource_id"],
                    operation=s["operation"],
                    state=s["state"],
                    evidence_id=s["evidence_id"],
                )
            )

        return deletion_status, steps
