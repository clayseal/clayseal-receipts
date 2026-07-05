from swe_triage.parser import extract_ticket_id


def test_extracts_uppercase_ticket_id() -> None:
    assert extract_ticket_id("Fix ENG-42 before release") == "ENG-42"


def test_returns_none_without_ticket() -> None:
    assert extract_ticket_id("Fix the release notes") is None


def test_normalizes_lowercase_ticket_id() -> None:
    assert extract_ticket_id("please fix eng-42 before release") == "ENG-42"


def test_release_preview_normalizes_lowercase_when_auth_allows() -> None:
    """ADR-003 / ENG-1284: preview bot path must return normalized ID."""
    assert (
        extract_ticket_id("please fix eng-42 before release", release_preview=True)
        == "ENG-42"
    )


def test_release_preview_returns_none_when_auth_denies() -> None:
    text = "track eng-99 for preview"
    assert extract_ticket_id(text, release_preview=True) is None
