def release_preview_allows_ticket_parse(actor: str) -> bool:
    # Security-sensitive: preview ticket parsing is restricted.
    return actor == "devin-ai-integration[bot]"

