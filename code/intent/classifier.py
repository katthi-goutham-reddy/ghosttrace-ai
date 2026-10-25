import re

class IntentClassifier:
    """Classifies user request text into DELETION vs NOT_APPLICABLE."""

    EXPLICIT_NON_DELETION_PATTERNS = [
        r"not asking for deletion",
        r"not a request to erase",
        r"do not close (the|my) account",
        r"don['’]?t (delete|erase|remove|close)",
        r"leave the account active",
        r"leave my profile",
        r"keep the account as it is",
        r"continue using the service",
        r"marketing lists only",
        r"without removing any of my records",
        r"need help resetting the login",
        r"this is an information request",
        r"information request, not a request",
        r"portable format\. please keep the account",
    ]

    DELETION_INDICATORS = [
        # English
        r"\bdelet", r"\beras", r"\bremov", r"\bclos", r"\bgone\b", r"\bpurge",
        # French
        r"\bsupprim", r"\bsuppression", r"\beffac",
        # Spanish / Portuguese
        r"\belimin", r"\bexclu", r"\bbaja\b", r"\bcancela",
        # German
        r"\blösch", r"\bentfern",
        # Japanese / Chinese
        r"削除", r"消去",
        # Korean
        r"삭제",
    ]

    def is_deletion_authorized(self, text: str) -> bool:
        if not text:
            return False
        clean = text.strip().lower()

        # Check explicit negative or non-deletion signals
        for pattern in self.EXPLICIT_NON_DELETION_PATTERNS:
            if re.search(pattern, clean):
                return False

        # Check for positive deletion indicators
        for pattern in self.DELETION_INDICATORS:
            if re.search(pattern, clean):
                return True

        return False
