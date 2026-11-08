# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography==44.0.1"]
# ///
"""Tests for the branchpoint.v1 Python reference. Run: uv run --script reference/python/test_branchpoint_ref.py"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import shutil
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import branchpoint_ref as bp  # noqa: E402

GOLDEN = bp.GOLDEN_DIR


def load(name: str) -> dict:
    return json.loads((GOLDEN / name).read_text("utf-8"))


class GoldenFiles(unittest.TestCase):
    def test_committed_bytes_match_generator(self) -> None:
        for name, data in bp.render().items():
            self.assertEqual((GOLDEN / name).read_bytes(), data, name)

    def test_verify_recomputes_every_vector(self) -> None:
        self.assertEqual(bp.verify_committed(), [])

    def test_check_detects_one_byte_edit_in_every_file(self) -> None:
        self.assertEqual(bp.check(), [])
        for name in sorted(p.name for p in GOLDEN.iterdir()):
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                d = Path(tmp)
                for f in GOLDEN.iterdir():
                    shutil.copy(f, d / f.name)
                raw = bytearray((d / name).read_bytes())
                i = raw.index(b"0")  # first ASCII digit '0' (hex, number or sha256)
                raw[i] = ord("1")
                (d / name).write_bytes(bytes(raw))
                self.assertEqual(bp.check(d), [name])
                (d / name).unlink()
                self.assertEqual(bp.check(d), [name], "a missing file is a mismatch")

    def test_verify_detects_unit_tag_edit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            for f in GOLDEN.iterdir():
                shutil.copy(f, d / f.name)
            target = d / "unit_tag_golden.json"
            raw = bytearray(target.read_bytes())
            i = raw.index(b'"unit_tag": "') + len(b'"unit_tag": "')
            raw[i] = ord("0") if raw[i] != ord("0") else ord("1")
            target.write_bytes(bytes(raw))
            self.assertTrue(any("unit_tag" in e for e in bp.verify_committed(d)))

    def test_verify_recomputes_chain_fields_from_layout(self) -> None:
        """A re-signed receipt whose propensity no longer follows from the layout fails verify."""
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            for f in GOLDEN.iterdir():
                shutil.copy(f, d / f.name)
            c = json.loads((d / "receipt_chain_golden.json").read_text("utf-8"))
            wl = bp.Ed25519PrivateKey.from_private_bytes(bp.WORKLOAD_SEED)
            x = c["chains"][0]["receipts"][0]
            x["receipt"]["propensity_bp"] = 10000 - x["receipt"]["propensity_bp"]
            canonical = bp.jcs(x["receipt"])
            x.update(canonical=canonical.decode("ascii"), receipt_hash=bp.receipt_hash(canonical).hex(),
                     sig_hex=bp.sign_message(wl, canonical).hex())
            (d / "receipt_chain_golden.json").write_bytes(bp.dump(c))
            errs = bp.verify_committed(d)
            self.assertTrue(any("do not follow from the layout" in e for e in errs), errs)

    def test_sha256sums_cover_every_file(self) -> None:
        lines = (GOLDEN / "SHA256SUMS").read_text().splitlines()
        names = sorted(p.name for p in GOLDEN.iterdir() if p.name != "SHA256SUMS")
        self.assertEqual([ln.split("  ")[1] for ln in lines], names)
        for ln in lines:
            digest, name = ln.split("  ")
            self.assertEqual(hashlib.sha256((GOLDEN / name).read_bytes()).hexdigest(), digest)

    def test_golden_format(self) -> None:
        for p in GOLDEN.glob("*.json"):
            raw = p.read_bytes()
            self.assertTrue(raw.endswith(b"}\n"), p.name)
            obj = json.loads(raw, parse_float=lambda s: self.fail(f"float {s} in {p.name}"))
            self.assertEqual(raw, bp.dump(obj), p.name)

    def test_dump_refuses_floats(self) -> None:
        with self.assertRaises(TypeError):
            bp.dump({"a": [1, {"b": 0.5}]})


class Bucketing(unittest.TestCase):
    def test_bucket_matches_independent_stdlib_formula(self) -> None:
        g = load("bpa1_golden.json")
        salt = bytes.fromhex(g["salt_hex"])
        for b in g["buckets"]:
            msg = b"bpa1\n" + g["experiment_id"].encode() + b"\n" + bytes.fromhex(b["unit_utf8_hex"])
            want = int.from_bytes(hmac.digest(salt, msg, "sha256")[:8], "big") % 10000
            self.assertEqual(b["bucket"], want, b["unit"])

    def test_unit_tag_matches_independent_formula(self) -> None:
        t = load("unit_tag_golden.json")
        salt = bytes.fromhex(t["salt_hex"])
        for x in t["tags"]:
            want = hmac.digest(salt, b"bpa1-tag\n" + bytes.fromhex(x["unit_utf8_hex"]), "sha256")[:16].hex()
            self.assertEqual(x["unit_tag"], want)

    def test_non_ascii_unit_is_utf8(self) -> None:
        self.assertIn("c3bc6e69742dc39f", [b["unit_utf8_hex"] for b in load("bpa1_golden.json")["buckets"]])

    def test_salt_kid(self) -> None:
        self.assertEqual(bp.salt_kid(bp.SALT), hashlib.sha256(bp.SALT).digest()[:4].hex())


def L(name: str) -> bp.ExperimentDef:
    return bp._layouts()[name]


class Evaluation(unittest.TestCase):
    def test_split_propensity_is_arm_weight(self) -> None:
        for u in bp.UNITS[:4]:
            e = bp.evaluate(L("L2"), u)
            self.assertEqual(e.propensity_bp, {"A": 1000, "B": 2500, "C": 6500}[e.variant_id])

    def test_split_interval_boundaries(self) -> None:
        d = L("L2")
        arms = d.arms
        for b, want in [(0, "A"), (999, "A"), (1000, "B"), (3499, "B"), (3500, "C"), (9999, "C")]:
            cum = 0
            for a in arms:
                cum += a.weight_bp
                if b < cum:
                    self.assertEqual(a.variant_id, want, b)
                    break

    def test_holdout_split_by_budget(self) -> None:
        d = L("L3")
        for u in bp.UNITS[:4]:
            e = bp.evaluate(d, u)
            if bp.bucket(bp.SALT, bp.EXPERIMENT_ID, u) < 2500:
                self.assertEqual((e.outcome, e.variant_id, e.propensity_bp), ("held_out", "", 2500))
            else:
                self.assertEqual((e.outcome, e.variant_id, e.propensity_bp), ("variant", "T", 7500))
            self.assertTrue(e.receipt)

    def test_holdout_budget_zero_is_paused(self) -> None:
        e = bp.evaluate(replace(L("L3"), budget_bp=0), "subj-a")
        self.assertEqual((e.outcome, e.reason, e.propensity_bp, e.receipt), ("default", "paused", 10000, False))

    def test_holdout_budget_full_holds_everyone_out(self) -> None:
        d = replace(L("L3"), budget_bp=10000)
        for u in bp.UNITS[:4]:
            e = bp.evaluate(d, u)
            self.assertEqual((e.outcome, e.propensity_bp), ("held_out", 10000))

    def test_fail_soft_order(self) -> None:
        base = L("L2")
        cases = [
            (replace(base, assigner="runtime", state="paused"), "ASSIGNED_BY_RUNTIME"),
            (replace(base, state="paused", bucket_version="bp9"), "paused"),
            (replace(base, bucket_version="bp9", salt=None), "unsupported_bucket_version"),
            (replace(base, salt=None, mode="unspecified"), "salt_absent"),
            (replace(base, mode="unspecified"), "config_invalid"),
            (replace(base, state="unspecified"), "config_invalid"),
            (replace(base, variant_kind="unspecified"), "config_invalid"),
            (replace(base, assigner="unspecified"), "config_invalid"),
            (replace(base, salt=bp.SALT[:31]), "config_invalid"),
            (replace(base, salt_kid="00000000"), "config_invalid"),
            (replace(base, experiment_id="01jbp9000000000000000000ab"), "config_invalid"),
            (replace(base, arms=(bp.Arm("A", 5000), bp.Arm("A", 5000))), "config_invalid"),
            (replace(base, arms=(bp.Arm("A b", 10000),)), "config_invalid"),
            (replace(base, arms=(bp.Arm("A", 5000), bp.Arm("B", 4999))), "config_invalid"),
            (replace(base, arms=(bp.Arm("A", 10001),)), "config_invalid"),
            (replace(base, arms=()), "config_invalid"),
            (replace(base, budget_bp=1), "config_invalid"),
            (replace(L("L3"), budget_bp=10001), "config_invalid"),
            (replace(L("L3"), arms=(bp.Arm("T", 0), bp.Arm("U", 0))), "config_invalid"),
            (replace(base, arms=(bp.Arm("A", 0), bp.Arm("B", 0))), "paused"),
        ]
        for d, reason in cases:
            e = bp.evaluate(d, "subj-a")
            self.assertEqual((e.outcome, e.reason, e.propensity_bp, e.receipt), ("default", reason, 10000, False), d)
        self.assertEqual(bp.evaluate(base, "").reason, "empty_unit")
        self.assertEqual(bp.evaluate(replace(base, state="paused"), "").reason, "paused")

    def test_single_arm_split(self) -> None:
        e = bp.evaluate(replace(L("L2"), arms=(bp.Arm("only", 10000),)), "subj-a")
        self.assertEqual((e.variant_id, e.propensity_bp), ("only", 10000))


class Jcs(unittest.TestCase):
    def test_sorted_compact(self) -> None:
        self.assertEqual(bp.jcs({"b": 1, "a": "x"}), b'{"a":"x","b":1}')

    def test_refusals(self) -> None:
        for bad in ({"a": 1.0}, {"a": True}, {"a": None}, {"a": -1}, {"a": 2**53}, {"a": "é"}, {"a": 'q"'},
                    {"a": "\\"}, {"a": "\n"}, {"a": [1]}, {"é": 1}):
            with self.assertRaises(bp.JcsError, msg=repr(bad)):
                bp.jcs(bad)

    def test_max_safe_integer_allowed(self) -> None:
        self.assertEqual(bp.jcs({"a": 2**53 - 1}), b'{"a":9007199254740991}')


class CertAndReceipts(unittest.TestCase):
    def test_cert_signature_and_key_ids(self) -> None:
        w = load("workload_cert_golden.json")
        cp = bytes.fromhex(w["cp_public_key_hex"])
        cert = bp.verify_cert(bytes.fromhex(w["wcert_hex"]), bytes.fromhex(w["cert_sig_hex"]), w["issuer_kid"],
                              {w["issuer_kid"]: cp})
        self.assertEqual((cert.sdk_key_id, cert.tenant), (w["sdk_key_id"], w["tenant"]))
        self.assertEqual(len(w["issuer_kid"]), 43)

    def test_wcert_layout(self) -> None:
        w = load("workload_cert_golden.json")
        body = bytes.fromhex(w["wcert_hex"])
        dom = b"seam.branchpoint.workload-cert.v1"
        self.assertEqual(body[:4], len(dom).to_bytes(4, "little"))
        self.assertEqual(body[4 : 4 + len(dom)], dom)
        off = 4 + len(dom)
        self.assertEqual(body[off : off + 4], (32).to_bytes(4, "little"))
        off += 36
        self.assertEqual(int.from_bytes(body[off : off + 8], "little"), w["not_before_ms"])
        self.assertEqual(int.from_bytes(body[off + 8 : off + 16], "little"), w["not_after_ms"])

    def test_cert_grammar_refusals(self) -> None:
        pk = bytes(32)
        for sk, tn in (("bk_0123456789ABCDEFGHJKMNPQRS", "t"), ("bk_short", "t"), (bp.SDK_KEY_ID, ""),
                       (bp.SDK_KEY_ID, "t g"), (bp.SDK_KEY_ID, "x" * 129)):
            with self.assertRaises(bp.Refusal) as cm:
                bp.parse_wcert(bp.wcert(pk, 1, 2, sk, tn))
            self.assertEqual(cm.exception.reason, "cert_malformed")

    def test_cert_truncation_is_malformed(self) -> None:
        body = bytes.fromhex(load("workload_cert_golden.json")["wcert_hex"])
        for n in range(len(body)):
            with self.assertRaises(bp.Refusal) as cm:
                bp.parse_wcert(body[:n])
            self.assertEqual(cm.exception.reason, "cert_malformed", n)

    def test_chain_links_and_genesis(self) -> None:
        c = load("receipt_chain_golden.json")
        self.assertEqual([ch["layout"] for ch in c["chains"]], ["L2", "L3"])
        for ch in c["chains"]:
            rs = ch["receipts"]
            self.assertEqual([x["receipt"]["seq"] for x in rs], list(range(len(rs))))
            self.assertEqual(rs[0]["receipt"]["prev_hash"], ch["genesis_prev_hash"])
            for prev, cur in zip(rs, rs[1:]):
                self.assertEqual(cur["receipt"]["prev_hash"], prev["receipt_hash"])
            for x in rs:
                self.assertEqual(len(x["receipt"]), 13)
                self.assertIsInstance(x["receipt"]["propensity_bp"], int)
                self.assertEqual(x["receipt"]["experiment_id"], ch["experiment_id"])

    def test_holdout_chain_signs_held_out_and_served(self) -> None:
        ch = load("receipt_chain_golden.json")["chains"][1]
        got = {(x["receipt"]["variant_id"], x["receipt"]["propensity_bp"]) for x in ch["receipts"]}
        self.assertEqual(got, {("", 2500), ("T", 7500)})
        self.assertTrue(all(x["receipt"]["mode"] == "holdout" for x in ch["receipts"]))

    def test_row8_layouts_are_paused_in_goldens(self) -> None:
        g = load("bpa1_golden.json")
        for lay in ("L5", "L6"):
            rows = [e for e in g["evaluations"] if e["layout"] == lay and e["unit"]]
            self.assertTrue(rows)
            for e in rows:
                self.assertEqual((e["outcome"], e.get("reason"), e["receipt"], e["propensity_bp"]),
                                 ("default", "paused", False, 10000), e)

    def _neg(self) -> tuple[dict, dict[str, bytes], dict[str, dict]]:
        n = load("receipt_negative_golden.json")
        pinned = {k: bytes.fromhex(v) for k, v in n["pinned_cp_keys"].items()}
        return n, pinned, {c["name"]: c for c in n["cases"]}

    def test_negative_cases(self) -> None:
        n, pinned, by = self._neg()
        self.assertEqual(len(by), len(n["cases"]), "case names are unique")
        for case in n["cases"]:
            with self.subTest(case["name"]):
                self.assertEqual(len(case["batches"]), len(case["expect"]))
                self.assertEqual(bp.run_negative_case(case, pinned), case["expect"])

    def test_every_reason_code_is_exercised(self) -> None:
        n, _, _ = self._neg()
        exp = [e for c in n["cases"] for e in c["expect"]]
        seen = {e["cert"] for e in exp} | {r for e in exp for r in e["results"]}
        want = {"ok", "cert_malformed", "cert_window_invalid", "cert_issuer_unknown", "cert_sig_invalid",
                "receipt_schema", "receipt_noncanonical", "receipt_cert_mismatch", "receipt_sig_invalid",
                "receipt_outside_cert_window", "duplicate_receipt_id", "duplicate_seq", "seq_out_of_order",
                "chain_break"}
        self.assertEqual(seen, want)

    def test_multi_batch_cases_present(self) -> None:
        _, _, by = self._neg()
        for name in ("late_predecessor", "late_predecessor_forward_break", "replay_next_batch"):
            self.assertGreaterEqual(len(by[name]["batches"]), 2, name)

    def test_refused_receipt_changes_no_state(self) -> None:
        _, pinned, by = self._neg()
        valid = by["valid_chain"]["batches"][0]
        v = bp.Verifier(pinned)
        bad = copy.deepcopy(valid)
        bad["receipts"] = [{**valid["receipts"][0], "sig_hex": "00" * 64}]
        self.assertEqual(v.verify_batch(bad)["results"], ["receipt_sig_invalid"])
        self.assertEqual((v.receipt_ids, v.hashes), (set(), {}))
        self.assertEqual(v.verify_batch(valid)["results"], ["ok", "ok", "ok"])

    def test_state_persists_across_batches(self) -> None:
        _, pinned, by = self._neg()
        valid = by["valid_chain"]["batches"][0]
        v = bp.Verifier(pinned)
        first = {**valid, "receipts": valid["receipts"][:1]}
        rest = {**valid, "receipts": valid["receipts"][1:]}
        self.assertEqual(v.verify_batch(first), {"cert": "ok", "gaps": [], "results": ["ok"]})
        self.assertEqual(v.verify_batch(rest), {"cert": "ok", "gaps": [], "results": ["ok", "ok"]})
        self.assertEqual(v.verify_batch(first)["results"], ["duplicate_receipt_id"])

    def test_malformed_input_never_crashes(self) -> None:
        _, pinned, by = self._neg()
        valid = by["valid_chain"]["batches"][0]
        r0 = valid["receipts"][0]
        v = bp.Verifier(pinned)
        cert_cases = [{}, {**valid["cert"], "body_hex": "zz"}, {**valid["cert"], "sig_hex": "0"},
                      {**valid["cert"], "body_hex": 7}]
        for cert in cert_cases:
            with self.subTest(cert=cert):
                self.assertEqual(v.verify_batch({"cert": cert, "receipts": [r0]})["cert"], "cert_malformed")
        for item, want in ((7, "receipt_schema"), ({}, "receipt_schema"), ({**r0, "canonical": 5}, "receipt_schema"),
                           ({**r0, "sig_hex": "xy" * 64}, "receipt_sig_invalid"),
                           ({**r0, "sig_hex": "00" * 65}, "receipt_sig_invalid"),
                           ({"canonical": "{", "sig_hex": r0["sig_hex"]}, "receipt_schema"),
                           ({"canonical": "[" * 100000, "sig_hex": r0["sig_hex"]}, "receipt_schema")):
            with self.subTest(item=item):
                self.assertEqual(v.verify_batch({**valid, "receipts": [item]})["results"], [want])
        self.assertEqual(v.verify_batch({"cert": valid["cert"]})["results"], [])
        for receipts in (5, None, "abc", {"a": 1}):
            with self.subTest(receipts=receipts):
                self.assertEqual(v.verify_batch({**valid, "receipts": receipts}),
                                 {"cert": "cert_malformed", "gaps": [], "results": []})
        for batch in (None, [], "x"):
            self.assertEqual(v.verify_batch(batch)["cert"], "cert_malformed")
        self.assertEqual((v.receipt_ids, v.hashes), (set(), {}))

    def test_unhex_is_strict(self) -> None:
        for bad in ("0", "zz", " 00", "0x00", "AA", "aB", 5):
            with self.assertRaises(ValueError):
                bp.unhex(bad)
        self.assertEqual(bp.unhex("00ff"), b"\x00\xff")

    def test_strict_json(self) -> None:
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}'):
            with self.assertRaises(ValueError):
                bp._strict_load(raw)


if __name__ == "__main__":
    unittest.main(verbosity=1)
