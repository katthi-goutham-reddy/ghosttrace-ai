from dataclasses import dataclass, field
from typing import Set, Optional

@dataclass
class UserCluster:
    user_id: str
    primary_name: str
    names: Set[str] = field(default_factory=set)
    emails: Set[str] = field(default_factory=set)
    phones: Set[str] = field(default_factory=set)
    email_hashes: Set[str] = field(default_factory=set)
    updated_at: Optional[str] = None

    def matches(self, term: str) -> bool:
        if not term:
            return False
        clean_term = term.strip().lower()
        if clean_term == self.user_id.lower():
            return True
        for em in self.emails:
            if clean_term == em.lower():
                return True
        for ph in self.phones:
            if clean_term == ph.lower():
                return True
        for eh in self.email_hashes:
            if clean_term == eh.lower():
                return True
        for nm in self.names:
            if clean_term == nm.lower():
                return True
        return False
