from wiki_app.parser import normalize_ticket


def test_normalize_lowercase() -> None:
    assert normalize_ticket("eng-42") == "ENG-42"

