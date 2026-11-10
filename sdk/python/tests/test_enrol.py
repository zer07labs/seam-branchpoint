"""enrol: the AS-6 SDK-key enrol bundle `{public_jwk, proof}` (keys are generated per test; no seed is fixed here)."""

from __future__ import annotations

import json
import os
import stat

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from seam_branchpoint import POP_TYP, TokenInputError, enrol_bundle, jwk_thumbprint, public_jwk
from seam_branchpoint._wire import b64u_decode
from seam_branchpoint.enrol import main, read_seed

AUD = "seam-control-plane"
NOW = 1_762_560_000


def _seed_hex(sk: Ed25519PrivateKey) -> str:
    return sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()


def _no_d(v: object) -> bool:
    if isinstance(v, dict):
        return "d" not in v and all(_no_d(x) for x in v.values())
    if isinstance(v, list):
        return all(_no_d(x) for x in v)
    return True


def test_rfc8037_thumbprint_vector():
    # RFC 8037 Appendix A.3: the public key and its RFC 7638 thumbprint (public values only).
    x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    jwk = public_jwk(b64u_decode(x))
    assert jwk == {"kty": "OKP", "crv": "Ed25519", "x": x}
    assert jwk_thumbprint(jwk) == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"


def test_bundle_shape_claims_and_signature():
    sk = Ed25519PrivateKey.generate()
    b = enrol_bundle(sk, AUD, now_s=NOW)
    assert list(b) == ["public_jwk", "proof"] and _no_d(b)
    jwk = b["public_jwk"]
    assert list(jwk) == ["kty", "crv", "x"] and jwk["kty"] == "OKP" and jwk["crv"] == "Ed25519"
    assert len(jwk["x"]) == 43 and jwk == public_jwk(sk.public_key())
    h64, c64, s64 = b["proof"].split(".")
    assert json.loads(b64u_decode(h64)) == {"alg": "EdDSA", "typ": POP_TYP} == {"alg": "EdDSA", "typ": "seam-mc-pop+jwt"}
    c = json.loads(b64u_decode(c64))
    assert list(c) == ["sub", "aud", "iat", "exp", "jti"]
    assert c["sub"] == jwk_thumbprint(jwk) and c["aud"] == AUD and c["iat"] == NOW and c["exp"] - c["iat"] == 300
    assert len(c["jti"]) == 22 and len(b64u_decode(c["jti"])) == 16
    Ed25519PublicKey.from_public_bytes(b64u_decode(jwk["x"])).verify(b64u_decode(s64), f"{h64}.{c64}".encode())
    assert _seed_hex(sk) not in json.dumps(b)


def test_fresh_jti_and_injectable():
    sk = Ed25519PrivateKey.generate()
    assert enrol_bundle(sk, AUD, now_s=NOW)["proof"] != enrol_bundle(sk, AUD, now_s=NOW)["proof"]
    one = enrol_bundle(sk, AUD, now_s=NOW, jti_bytes=b"\x01" * 16)
    assert one == enrol_bundle(sk, AUD, now_s=NOW, jti_bytes=b"\x01" * 16)


@pytest.mark.parametrize("bad", [dict(aud=""), dict(aud='a"b'), dict(aud="a b"), dict(lifetime_s=0),
                                 dict(lifetime_s=301), dict(lifetime_s=True), dict(now_s=-1), dict(now_s=1.0),
                                 dict(jti_bytes=b"x")])
def test_input_checks(bad):
    args = dict(aud=AUD, now_s=NOW) | bad
    with pytest.raises(TokenInputError):
        enrol_bundle(Ed25519PrivateKey.generate(), **args)


def test_type_check():
    with pytest.raises(TypeError):
        enrol_bundle(b"\x00" * 32, AUD)  # type: ignore[arg-type]


def test_cli_new_writes_seed_0600_and_never_prints_it(tmp_path, capsys):
    seed = tmp_path / "sdk-key.seed"
    assert main(["--aud", AUD, "--new", str(seed)]) == 0
    out, err = capsys.readouterr()
    seed_hex = seed.read_text().strip()
    assert len(seed_hex) == 64 and stat.S_IMODE(os.stat(seed).st_mode) == 0o600
    assert seed_hex not in out and seed_hex not in err
    b = json.loads(out)
    assert out.endswith("\n") and out.count("\n") == 1 and _no_d(b)
    assert b["public_jwk"] == public_jwk(read_seed(str(seed)))


def test_cli_seed_file_reproves_same_key(tmp_path, capsys):
    seed = tmp_path / "sdk-key.seed"
    assert main(["--aud", AUD, "--new", str(seed)]) == 0
    first = json.loads(capsys.readouterr().out)
    assert main(["--aud", AUD, "--seed-file", str(seed), "--lifetime", "120"]) == 0
    second = json.loads(capsys.readouterr().out)
    assert second["public_jwk"] == first["public_jwk"] and second["proof"] != first["proof"]
    c = json.loads(b64u_decode(second["proof"].split(".")[1]))
    assert c["exp"] - c["iat"] == 120


def test_cli_refuses_overwrite_and_bad_input_before_writing(tmp_path, capsys):
    seed = tmp_path / "sdk-key.seed"
    seed.write_text("keep\n")
    assert main(["--aud", AUD, "--new", str(seed)]) == 2
    assert seed.read_text() == "keep\n"
    fresh = tmp_path / "fresh.seed"
    assert main(["--aud", "a b", "--new", str(fresh)]) == 2 and not fresh.exists()
    assert main(["--aud", AUD, "--seed-file", str(seed)]) == 2
    out, _ = capsys.readouterr()
    assert out == ""
