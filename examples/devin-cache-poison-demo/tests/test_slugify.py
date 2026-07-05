from cache_app.slugify import slugify


def test_slugify_preserves_underscores() -> None:
    assert slugify("Hello_World") == "hello_world"
