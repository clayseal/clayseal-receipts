from swe_triage.greet import greet


def test_greet() -> None:
    assert greet("Devin") == "Hello, Devin!"
