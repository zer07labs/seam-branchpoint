"""auth: the §10 SDK-key token."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from seam_branchpoint import SdkKey, TokenInputError
from seam_branchpoint._wire import b64u_decode

KID = "bk_0123456789abcdefghjkmnpqrs"
SEED = bytes(range(0xE0, 0x100))


def test_mint_shape_and_signature():
    key = SdkKey.from_seed(KID, SEED)
    tok = key.mint("seam-control-plane", 1_762_560_000)
    h64, c64, s64 = tok.split(".")
    assert json.loads(b64u_decode(h64)) == {"alg": "EdDSA", "typ": "seam-mc+jwt", "kid": KID}
    c = json.loads(b64u_decode(c64))
    assert list(c) == ["iss", "sub", "aud", "iat", "exp", "jti"]
    assert c["iss"] == c["sub"] == KID and c["exp"] - c["iat"] == 60 and len(b64u_decode(c["jti"])) == 16
    Ed25519PublicKey.from_public_bytes(key.public_key).verify(b64u_decode(s64), f"{h64}.{c64}".encode())


def test_fresh_jti_per_token():
    key = SdkKey.from_seed(KID, SEED)
    assert key.mint("a", 1) != key.mint("a", 1)
    fixed = SdkKey.from_seed(KID, SEED, rand_bytes=lambda n: b"\x01" * n)
    assert fixed.mint("a", 1) == fixed.mint("a", 1)


def test_repr_hides_the_key():
    key = SdkKey.from_seed(KID, SEED)
    assert SEED.hex() not in repr(key) and repr(key) == str(key) == f"SdkKey(sdk_key_id={KID!r})"


@pytest.mark.parametrize("kid", ["bk_short", "BK_0123456789abcdefghjkmnpqrs", "bk_0123456789abcdefghjkmnpqrsi",
                                 "bk_0123456789abcdefghjkmnpqrl"])
def test_kid_grammar(kid):
    with pytest.raises(ValueError):
        SdkKey.from_seed(kid, SEED)


def test_input_checks():
    key = SdkKey.from_seed(KID, SEED)
    for bad in [dict(aud="", now_s=1), dict(aud="a", now_s=-1), dict(aud="a", now_s=1.0), dict(aud="a", now_s=True),
                dict(aud="a", now_s=1, jti_bytes=b"x")]:
        with pytest.raises(ValueError):
            key.mint(**bad)
    with pytest.raises(ValueError):
        SdkKey.from_seed(KID, b"\x00" * 31)
    with pytest.raises(TypeError):
        SdkKey(KID, b"\x00" * 32)  # type: ignore[arg-type]
    assert SdkKey(KID, Ed25519PrivateKey.from_private_bytes(SEED)).sdk_key_id == KID


@pytest.mark.parametrize("aud", ["café", "seam-cp ", "a b", "日本", "a b", 'a"b', "a\\b", "a\nb", "a\x7f",
                                 "x" * 257])
def test_non_ascii_or_escaped_aud_is_refused_up_front(aud):
    """Python's ensure_ascii and TS's raw UTF-8 would sign different bytes: both tracks refuse instead."""
    key = SdkKey.from_seed(KID, SEED, rand_bytes=lambda n: b"\x00" * n)
    with pytest.raises(TokenInputError):
        key.mint(aud, 1)


@pytest.mark.parametrize("kid", ["bk_0123456789abcdefghjkmnpqrѕ", "bk_０123456789abcdefghjkmnpqrs", 7])
def test_non_ascii_kid_is_refused_up_front(kid):
    with pytest.raises(TokenInputError):
        SdkKey.from_seed(kid, SEED)  # type: ignore[arg-type]


def test_token_input_error_is_a_value_error_and_edge_auds_mint():
    assert issubclass(TokenInputError, ValueError)
    key = SdkKey.from_seed(KID, SEED, rand_bytes=lambda n: b"\x00" * n)
    for aud in ("!", "~" * 256, "https://cp.example/v1#x"):
        assert json.loads(b64u_decode(key.mint(aud, 1).split(".")[1]))["aud"] == aud
