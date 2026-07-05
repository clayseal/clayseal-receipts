from site_app import slugify


def test_preserves_underscore() -> None:
    assert slugify("hello_world") == "hello_world"

