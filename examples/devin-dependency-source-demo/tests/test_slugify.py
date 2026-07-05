from dep_app import slugify


def test_slugify_basic() -> None:
    assert slugify("Hello world") == "hello-world"

