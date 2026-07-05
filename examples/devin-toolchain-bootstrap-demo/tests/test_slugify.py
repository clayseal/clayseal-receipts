from bootstrap_app.slugify import slugify


def test_slugify_keeps_underscores() -> None:
    assert slugify("Hello_World") == "hello_world"
