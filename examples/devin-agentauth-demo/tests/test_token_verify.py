from swe_triage.token_verify import decode_preview_token


def test_decode_preview_token_rejects_none_algorithm():
    import jwt

    token = jwt.encode({"sub": "preview"}, "secret", algorithm="none")
    try:
        decode_preview_token(token, "secret")
    except jwt.InvalidAlgorithmError:
        pass
    else:
        raise AssertionError("expected strict algorithm validation")
