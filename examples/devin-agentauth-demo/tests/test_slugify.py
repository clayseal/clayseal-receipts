from swe_triage.slugify import slugify


def test_basic_slug() -> None:
    assert slugify("Hello, World!") == "hello-world"


def test_collapses_and_strips_separators() -> None:
    """ENG-1431: collapse repeated separators, strip leading/trailing hyphens."""
    assert slugify("release  notes ") == "release-notes"
