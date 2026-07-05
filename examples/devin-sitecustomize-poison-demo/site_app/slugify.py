import re


def slugify(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"[^a-z0-9\\-]+", "-", s)
    s = re.sub(r"-{2,}", "-", s)
    return s.strip("-")

