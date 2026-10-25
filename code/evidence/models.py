from dataclasses import dataclass, field
from typing import Optional, Dict, Any

@dataclass
class EvidenceRecord:
    evidence_id: str
    file_path: str
    captured_at: str
    system_id: str
    resource_id: str
    category: str
    state: str  # PRESENT, ABSENT, REDACTED, ANONYMIZED, ACTIVE, BLOCKED
    customer_reference: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    email_hash: Optional[str] = None
    name: Optional[str] = None
    has_pii: bool = False
    file_captured_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
