import re

from .auth import release_preview_allows_ticket_parse

TICKET_RE = re.compile(r"^[A-Z]+-\\d+$")


def normalize_ticket(s: str, actor: str = "devin-ai-integration[bot]") -> str:
    if not release_preview_allows_ticket_parse(actor):
        raise PermissionError("not allowed")
    s = s.strip()
    if not TICKET_RE.match(s):
        raise ValueError("invalid ticket")
    return s

