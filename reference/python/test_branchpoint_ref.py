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
    def test_bpa1_golden_pins_every_fail_soft_row(self) -> None:
        # Rows 3-9 of the spec §3 table, so the cross-language gate pins the evaluation order, not just Python.
        reasons = {e.get("reason") for e in load("bpa1_golden.json")["evaluations"]}
        want = {"ASSIGNED_BY_RUNTIME", "paused", "unsupported_bucket_version", "salt_absent", "config_invalid",
                "empty_unit"}
        self.assertTrue(want <= reasons, want - reasons)

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


# --- AS-2 wires (spec §8–§10), golden group contract/golden/branchpoint-sdk/ -------------------------------------
SDK_GOLDEN = bp.SDK_GOLDEN_DIR


def sdk_load(name: str) -> dict:
    return json.loads((SDK_GOLDEN / name).read_text("utf-8"))


# Every §8 vector case and the outcome it must produce: pinned here independently of the generator.
DOC_EXPECT = {
    "valid": "accepted", "valid_previous_key": "accepted", "valid_newer_than_cache": "accepted",
    "unchanged_same_bytes": "unchanged", "expiry_boundary": "accepted",
    "non_string_doc": "envelope_malformed", "malformed_sig_hex": "envelope_malformed",
    "short_sig_hex": "envelope_malformed", "envelope_duplicate_member": "envelope_malformed",
    "envelope_extra_member": "envelope_malformed", "lone_surrogate_doc": "envelope_malformed",
    "envelope_missing_member": "envelope_malformed", "envelope_not_object": "envelope_malformed",
    "envelope_bom": "envelope_malformed", "kid_not_base64url": "envelope_malformed", "kid_short": "envelope_malformed",
    "oversized": "document_too_large", "at_cap": "accepted", "tenant_newline": "tenant_invalid",
    "unknown_kid": "kid_unknown", "forged_sig": "sig_invalid", "wrong_tenant": "sig_invalid",
    "wrong_domain": "sig_invalid", "doc_duplicate_member": "doc_malformed", "doc_not_object": "doc_malformed",
    "v2": "doc_unsupported", "wrong_kind": "doc_unsupported", "body_tenant_mismatch": "tenant_mismatch",
    "version_too_large": "version_invalid", "version_not_integer": "version_invalid", "rollback": "rollback",
    "version_conflict": "version_conflict", "window_invalid": "window_invalid", "expired": "expired",
    "experiments_not_array": "doc_malformed", "unindexable_missing_key": "unindexable",
    "unindexable_experiment_id": "unindexable", "duplicate_key": "ambiguous_lookup",
    "duplicate_experiment_id": "ambiguous_lookup", "duplicate_decision_point": "ambiguous_lookup",
    "key_collides_decision_point": "ambiguous_lookup", "unknown_enum": "accepted", "bad_salt_hex": "accepted",
    "bad_arm_bundle": "accepted",
}


class SdkGolden(unittest.TestCase):
    def test_sdk_group_bytes_match_generator(self) -> None:
        self.assertEqual(sorted(p.name for p in SDK_GOLDEN.iterdir()),
                         ["SHA256SUMS", "sdk_document_golden.json", "sdk_key_token_golden.json",
                          "upload_batch_golden.json"])
        for name, data in bp.render_sdk().items():
            self.assertEqual((SDK_GOLDEN / name).read_bytes(), data, name)
        self.assertEqual(bp.verify_sdk_committed(), [])

    def test_check_sdk_detects_one_byte_edit(self) -> None:
        self.assertEqual(bp.check_sdk(), [])
        for name in sorted(p.name for p in SDK_GOLDEN.iterdir()):
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                d = Path(tmp)
                for f in SDK_GOLDEN.iterdir():
                    shutil.copy(f, d / f.name)
                raw = bytearray((d / name).read_bytes())
                raw[raw.index(b"0")] = ord("1")
                (d / name).write_bytes(bytes(raw))
                self.assertEqual(bp.check_sdk(d), [name])

    def test_hub_pinned_goldens_untouched(self) -> None:
        # Every golden vector here (AS-0 and the SDK set) is hub-pinned, and its bytes equal the vendored manifest's sha256.
        manifest = json.loads((bp.REPO / "contract" / "golden-manifest.json").read_text("utf-8"))
        pinned = [(g["sha256"], p) for g in manifest["groups"] for p in g["copies"].get("seam-branchpoint", [])]
        on_disk = {str(f.relative_to(bp.REPO)) for d in (GOLDEN, SDK_GOLDEN) for f in d.glob("*.json")}
        self.assertEqual({p for _, p in pinned}, on_disk)
        for sha, path in pinned:
            self.assertEqual(hashlib.sha256((bp.REPO / path).read_bytes()).hexdigest(), sha, path)
        self.assertEqual(set(bp.render()), {p.name for p in GOLDEN.iterdir()})


class SdkDocument(unittest.TestCase):
    def setUp(self) -> None:
        self.g = sdk_load("sdk_document_golden.json")
        self.pinned = {k: bytes.fromhex(v) for k, v in self.g["pinned_doc_keys"].items()}
        self.by = {c["name"]: c for c in self.g["cases"]}

    def run_case(self, c: dict) -> dict:
        return bp.verify_document(bp.doc_case_body(c), c.get("tenant", self.g["tenant"]), self.pinned, c["now_ms"],
                                  c["cached"])

    def test_every_case_has_its_named_outcome(self) -> None:
        self.assertEqual(set(self.by), set(DOC_EXPECT))
        for name, want in DOC_EXPECT.items():
            with self.subTest(name):
                got = self.run_case(self.by[name])
                self.assertEqual(got, self.by[name]["expect"])
                self.assertEqual(got.get("reason", got["outcome"]), want)

    def test_experiment_level_failures_mark_only_that_experiment(self) -> None:
        for name, bad in (("unknown_enum", "checkout-flow"), ("bad_salt_hex", "ranker-holdout"),
                          ("bad_arm_bundle", "ranker-holdout")):
            ex = self.run_case(self.by[name])["experiments"]
            self.assertEqual(ex[bad], "config_invalid", name)
            self.assertEqual([k for k, v in ex.items() if v == "ok"], [k for k in ex if k != bad], name)

    def test_positive_document(self) -> None:
        doc = self.g["document"]
        db = doc["doc_bytes"].encode("utf-8")
        self.assertEqual(bytes.fromhex(doc["message_hex"]), b"seam.branchpoint.sdk-doc.v1\nt-golden\n" + db)
        self.assertEqual(doc["config_digest"], hashlib.sha256(db).hexdigest())
        self.assertEqual(json.loads(doc["envelope"]), {"doc": doc["doc_bytes"], "kid": doc["kid"], "sig": doc["sig"]})
        self.assertIn(bp.key_id(bytes.fromhex(self.g["doc_public_key_hex"])), self.pinned)
        self.assertEqual(len(self.pinned), 2, "current plus one previous key")
        self.assertTrue(any(ord(ch) > 0x7F for ch in doc["doc_bytes"]), "non-ASCII payload is allowed")

    def test_document_evaluates_like_the_as0_layouts(self) -> None:
        ev = {(e["key"], e["unit"]): e for e in self.g["document"]["evaluations"]}
        for e in load("bpa1_golden.json")["evaluations"]:
            if e["layout"] == "L1":
                got = {k: v for k, v in ev[("checkout-flow", e["unit"])].items() if k not in ("key", "unit")}
                self.assertEqual(got, {k: v for k, v in e.items() if k not in ("layout", "unit")}, e["unit"])
        self.assertEqual({e["outcome"] for (k, _), e in ev.items() if k == "ranker-holdout"},
                         {"held_out", "variant", "default"})

    def test_refusal_keeps_the_cache(self) -> None:
        cache = bp.refresh_cache(None, self.run_case(self.by["valid"]))
        self.assertEqual(cache, {"config_digest": self.g["document"]["config_digest"], "version": 7})
        for name, want in DOC_EXPECT.items():
            r = self.run_case(self.by[name])
            if r["outcome"] == "refused":
                self.assertIs(bp.refresh_cache(cache, r), cache, name)
        self.assertEqual(bp.refresh_cache(cache, self.run_case(self.by["unchanged_same_bytes"])), cache)

    def test_size_cap_applies_before_parsing(self) -> None:
        env = self.by["valid"]["envelope"].encode("utf-8")
        at_cap = env + b" " * (bp.DOC_MAX_BYTES - len(env))
        r = bp.verify_document(at_cap, bp.TENANT, self.pinned, bp.DOC_NOW_MS)
        self.assertEqual(r["outcome"], "accepted")
        r = bp.verify_document(at_cap + b" ", bp.TENANT, self.pinned, bp.DOC_NOW_MS)
        self.assertEqual(r, {"outcome": "refused", "reason": "document_too_large"})
        self.assertEqual(bp.verify_document(b"{" * (bp.DOC_MAX_BYTES + 1), bp.TENANT, self.pinned, 0)["reason"],
                         "document_too_large")

    def test_size_cap_vectors_are_compact(self) -> None:
        for name, n in (("oversized", bp.DOC_MAX_BYTES + 1), ("at_cap", bp.DOC_MAX_BYTES)):
            c = self.by[name]
            self.assertEqual((c["pad_to_bytes"], c["envelope"]), (n, self.by["valid"]["envelope"]))
            self.assertEqual(len(bp.doc_case_body(c)), n)

    def test_tenant_grammar_before_signature(self) -> None:
        c = self.by["tenant_newline"]
        self.assertIn("\n", c["tenant"])
        # The envelope is validly signed for that tenant, so only the grammar check can refuse it.
        env = json.loads(c["envelope"])
        msg = bp.doc_message(c["tenant"], env["doc"].encode("utf-8"))
        bp.Ed25519PublicKey.from_public_bytes(self.pinned[env["kid"]]).verify(bytes.fromhex(env["sig"]), msg)
        for bad in ("", "t" * 129, "t.golden", "t golden", "t-golden\n", "tënant"):
            self.assertEqual(bp.verify_document(self.by["valid"]["envelope"].encode("utf-8"), bad, self.pinned,
                                                bp.DOC_NOW_MS)["reason"], "tenant_invalid", repr(bad))
        self.assertEqual(bp.TENANT_RE.pattern, "[A-Za-z0-9_-]{1,128}")  # the control plane's tenant grammar

    def test_envelope_bytes_must_be_utf8(self) -> None:
        env = self.by["valid"]["envelope"].encode("utf-8")
        for raw in (b"\xef\xbb\xbf" + env, env.replace(b"concise", b"conc\xffse")):
            self.assertEqual(bp.verify_document(raw, bp.TENANT, self.pinned, bp.DOC_NOW_MS)["reason"],
                             "envelope_malformed")

    def test_unknown_enum_keeps_fail_soft_row_order(self) -> None:
        e = json.loads(self.g["document"]["doc_bytes"])["experiments"][0]
        paused = bp.parse_experiment({**e, "mode": "canary", "state": "paused"})
        self.assertEqual(bp.evaluate(paused, "subj-a").reason, "paused")  # row 4 precedes row 7
        self.assertEqual(bp.evaluate(bp.parse_experiment({**e, "mode": "canary"}), "subj-a").reason, "config_invalid")
        no_salt = {k: v for k, v in e.items() if k != "salt_hex"}
        self.assertEqual(bp.evaluate(bp.parse_experiment(no_salt), "subj-a").reason, "salt_absent")  # row 6
        self.assertEqual(bp.evaluate(bp.parse_experiment({**e, "budget_bp": "0"}), "subj-a").reason, "config_invalid")

    def test_freshness(self) -> None:
        for f in self.g["freshness"]:
            self.assertEqual(bp.is_stale(f["since_refresh_ms"], f["now_ms"], f["expires_at_ms"]), f["stale"], f)
        self.assertEqual([f["stale"] for f in self.g["freshness"]], [False, False, True, False, True])
        self.assertEqual((self.g["max_staleness_ms"], self.g["expiry_skew_ms"]), (600000, 300000))


class SdkUploadBatch(unittest.TestCase):
    def setUp(self) -> None:
        self.u = sdk_load("upload_batch_golden.json")

    def test_batch_carries_the_golden_chain_and_one_outcome(self) -> None:
        b = self.u["batch"]
        chain = load("receipt_chain_golden.json")["chains"][0]["receipts"]
        self.assertEqual(b["receipts"], [{"canonical": c["canonical"], "sig_hex": c["sig_hex"]} for c in chain])
        self.assertEqual(len(b["outcomes"]), 1)
        self.assertTrue(bp.outcome_ok(b["outcomes"][0]))
        self.assertEqual(self.u["batch_json"], bp.compact(b).decode("utf-8"))
        self.assertEqual(json.loads(self.u["batch_json"]), b)
        v = bp.Verifier({k: bytes.fromhex(x) for k, x in self.u["collector"]["pinned_cp_keys"].items()})
        self.assertEqual(v.verify_batch(b), {"cert": "ok", "gaps": [], "results": ["ok"] * 3})

    def pinned_col(self) -> bp.Collector:
        return bp.Collector(bp.Verifier({k: bytes.fromhex(x) for k, x in self.u["collector"]["pinned_cp_keys"].items()}))

    def test_batch_signature(self) -> None:
        b, wl = self.u["batch"], bp._keys()[1]
        self.assertEqual(bp.sign_batch(wl, b), b)
        self.assertRegex(b["batch_sig_hex"], "^[0-9a-f]{128}$")
        msg = self.u["batch_signing_input"].encode("utf-8")
        self.assertTrue(msg.startswith(b"seam.branchpoint.upload-batch.v1\n{"))
        self.assertEqual(msg, bp.batch_message(b))
        self.assertNotIn(b"batch_sig_hex", msg)
        cert = bp.parse_wcert(bytes.fromhex(b["cert"]["body_hex"]))
        bp.Ed25519PublicKey.from_public_bytes(cert.pk).verify(bytes.fromhex(b["batch_sig_hex"]), msg)
        self.assertTrue(bp.batch_sig_ok(b, cert.pk))
        changed = {**b, "outcomes": [{**b["outcomes"][0], "reward": 2}]}  # outcomes are covered by the signature
        self.assertFalse(bp.batch_sig_ok(changed, cert.pk))

    def test_jcs_tree(self) -> None:
        self.assertEqual(bp.jcs_tree({"b": [1, -2, "é\n\"\\\x01"], "a": {}}),
                         '{"a":{},"b":[1,-2,"é\\n\\"\\\\\\u0001"]}'.encode("utf-8"))
        for bad in (1.0, 0.5, True, None, 2 ** 53, -(2 ** 53), "\ud800", {"\ud800": 1}, {1: 1}):
            with self.assertRaises(bp.JcsError, msg=repr(bad)):
                bp.jcs_tree({"x": bad} if not isinstance(bad, dict) else bad)

    def test_non_empty_batch_needs_cert_and_batch_sig(self) -> None:
        oo = self.u["outcomes_only_batch"]
        self.assertEqual(set(oo), {"batch_sig_hex", "cert", "dropped", "outcomes", "receipts"})
        self.assertTrue(bp.batch_shape_ok(oo))
        for k in ("cert", "batch_sig_hex"):
            self.assertFalse(bp.batch_shape_ok({x: v for x, v in oo.items() if x != k}), k)
        self.assertTrue(bp.batch_shape_ok({"receipts": []}))
        self.assertFalse(bp.batch_shape_ok({"receipts": [], "dropped": oo["dropped"]}))  # dropped alone is non-empty
        self.assertFalse(bp.batch_shape_ok({**oo, "dropped": {next(iter(oo["dropped"])): [[2, 1]]}}))
        self.assertFalse(bp.batch_shape_ok({**oo, "zz": 1}))

    def test_dropped_key_form(self) -> None:
        oo = self.u["outcomes_only_batch"]
        cd = bp.sha256(bytes.fromhex(oo["cert"]["body_hex"])).hex()
        self.assertEqual(list(oo["dropped"]), [f"{cd}:{bp.EXPERIMENT_ID}"])
        for k in (bp.EXPERIMENT_ID, f"{cd}{bp.EXPERIMENT_ID}", f"{cd.upper()}:{bp.EXPERIMENT_ID}",
                  f"{cd}:{bp.EXPERIMENT_ID.lower()}", f"{cd[:-1]}:{bp.EXPERIMENT_ID}", f"{cd}:{bp.EXPERIMENT_ID}:x"):
            self.assertFalse(bp.batch_shape_ok({**oo, "dropped": {k: [[4, 9]]}}), k)

    def test_collector_steps(self) -> None:
        steps = {s["name"]: s for s in self.u["collector"]["steps"]}
        ans = {n: (s["status"], s["response"]) for n, s in steps.items()}
        self.assertEqual([r["status"] for r in ans["retry_with_more"][1]["results"]],
                         ["duplicate", "accepted", "receipt_sig_invalid"])
        self.assertEqual(ans["retry_with_more"][1]["outcomes"][0]["status"], "accepted")  # receipt stored first
        self.assertEqual([o["status"] for o in ans["outcomes_only"][1]["outcomes"]], ["accepted"])
        self.assertEqual([o["status"] for o in ans["outcomes_only_retry"][1]["outcomes"]], ["duplicate"])
        self.assertEqual({o["status"] for o in ans["outcome_receipt_unknown"][1]["outcomes"]},
                         {"outcome_receipt_unknown"})
        self.assertEqual(len(ans["outcome_receipt_unknown"][1]["outcomes"]), 3)
        self.assertEqual(ans["outcome_other_cert"][1]["outcomes"][0]["status"], "outcome_receipt_unknown")
        self.assertEqual(ans["empty_batch"], (200, {"outcomes": [], "results": []}))
        for n in ("batch_sig_missing", "cert_missing", "receipts_without_cert", "batch_sig_uppercase", "bad_outcome",
                  "dropped_bad_key"):
            self.assertEqual(ans[n], (400, {"error": "batch_malformed"}), n)
        for n in ("batch_sig_invalid", "batch_sig_wrong_key"):
            self.assertEqual(ans[n], (400, {"error": "batch_sig_invalid"}), n)
        self.assertEqual(ans["cert_sig_invalid"], (400, {"error": "cert_sig_invalid"}))
        for n, s in steps.items():
            self.assertEqual(set(s["response"]), {"outcomes", "results"} if s["status"] == 200 else {"error"}, n)

    def test_refused_batch_stores_nothing(self) -> None:
        col = self.pinned_col()
        steps = {s["name"]: s for s in self.u["collector"]["steps"]}
        for n in ("batch_sig_invalid", "batch_sig_wrong_key", "batch_sig_missing"):
            self.assertEqual(col.receive(steps[n]["batch"])[0], 400)
        self.assertEqual((col.stored, col.scope, col.verifier.receipt_ids), ({}, {}, set()))

    def test_duplicate_requires_identical_bytes(self) -> None:
        wl = bp._keys()[1]
        col = self.pinned_col()
        b = self.u["batch"]
        self.assertEqual(col.receive(bp.sign_batch(wl, {"cert": b["cert"], "receipts": b["receipts"][:1]}))[0], 200)
        other = {**b["receipts"][0], "sig_hex": "00" * 64}  # same receipt_id, different bytes: not a duplicate
        got = col.receive(bp.sign_batch(wl, {"cert": b["cert"], "receipts": [other]}))
        self.assertEqual(got[1]["results"][0]["status"], "receipt_sig_invalid")

    def test_outcome_cases(self) -> None:
        want_ok = {"full", "minimal", "reward_negative", "sixteen_metrics", "metric_key_63"}
        floats = {"reward_fraction", "reward_integral_float", "reward_exponent", "reward_2p53", "metric_value_fraction"}
        self.assertTrue(floats <= {oc["name"] for oc in self.u["outcome_cases"]})
        for oc in self.u["outcome_cases"]:
            o = oc["outcome"] if "outcome" in oc else bp._strict_load(oc["outcome_json"].encode("utf-8"))
            self.assertEqual(("outcome_json" in oc), oc["name"] in floats, oc["name"])
            self.assertEqual(bp.outcome_ok(o), oc["name"] in want_ok, oc["name"])
            self.assertEqual(oc["ok"], oc["name"] in want_ok, oc["name"])
        for v in (0.5, 1.0, float("inf"), 2 ** 53):
            self.assertFalse(bp.outcome_ok({"experiment_id": bp.EXPERIMENT_ID, "receipt_id": bp._rid("", 1),
                                            "reward": v}), v)

    def test_sdk_admits_only_valid_outcomes(self) -> None:
        a = self.u["sdk_admit_outcomes"]
        self.assertEqual(bp.sdk_admit_outcomes(a["outcomes"]), a["expect"])
        self.assertEqual(a["expect"]["invalid_dropped"], len(a["outcomes"]) - len(a["expect"]["admitted"]))
        self.assertEqual(a["expect"]["invalid_dropped"], 10)
        self.assertTrue(all(bp.outcome_ok(o) for o in a["expect"]["admitted"]))
        # Admitted outcomes never 400 a batch: the collector check is the same function.
        wl = bp._keys()[1]
        b = bp.sign_batch(wl, {"cert": self.u["batch"]["cert"], "outcomes": a["expect"]["admitted"], "receipts": []})
        self.assertEqual(self.pinned_col().receive(b)[0], 200)

    def test_sdk_dispositions(self) -> None:
        got = {d["name"]: d["expect"] for d in self.u["sdk_dispositions"]}
        retry = {"outcomes_rejected": 0, "outcomes_succeeded": 0, "rejected": 0, "retry": True, "succeeded": 0}
        self.assertEqual(got["ok"], {"outcomes_rejected": 0, "outcomes_succeeded": 1, "rejected": 1, "retry": False,
                                     "succeeded": 2})
        self.assertEqual(got["bad_request"], {"outcomes_rejected": 1, "outcomes_succeeded": 0, "rejected": 3,
                                              "retry": False, "succeeded": 0})
        malformed = [n for n in got if n.startswith("malformed_")]
        self.assertEqual(len(malformed), 10)
        for n in malformed + ["unauthorized", "forbidden", "timeout", "rate_limited", "server_error", "unavailable",
                              "redirect"]:
            self.assertEqual(got[n], retry, n)
        for d in self.u["sdk_dispositions"]:
            self.assertEqual(bp.sdk_disposition(d["status"], d["body"], d["receipt_ids"], d["outcome_receipt_ids"]),
                             d["expect"], d["name"])


class SdkKeyToken(unittest.TestCase):
    def setUp(self) -> None:
        self.t = sdk_load("sdk_key_token_golden.json")
        self.sk = bp.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(self.t["sdk_key_seed_hex"]))
        self.pk = bytes.fromhex(self.t["public_key_hex"])

    def test_vector_reproduces_and_verifies(self) -> None:
        t = self.t
        self.assertEqual(bp.sdk_key_token(self.sk, t["sdk_key_id"], t["aud"], t["iat"], bytes.fromhex(t["jti_bytes_hex"])),
                         t["token"])
        self.assertEqual(t["header_json"], '{"alg":"EdDSA","typ":"seam-mc+jwt","kid":"%s"}' % t["sdk_key_id"])
        self.assertEqual(list(json.loads(t["claims_json"])), ["iss", "sub", "aud", "iat", "exp", "jti"])
        self.assertEqual(t["exp"] - t["iat"], 60)
        self.assertEqual(t["token"], t["signing_input"] + "." + t["signature_b64u"])
        claims = bp.verify_token(t["token"], self.pk, t["aud"], t["iat"])
        self.assertEqual((claims["iss"], claims["sub"], claims["jti"]), (t["sdk_key_id"], t["sdk_key_id"], t["jti"]))

    def test_token_refusals(self) -> None:
        t = self.t
        for tok, aud, now in ((t["token"], "other-aud", t["iat"]), (t["token"], t["aud"], t["exp"] + 31),
                              (t["token"][:-2] + "AA", t["aud"], t["iat"]), (t["token"] + ".x", t["aud"], t["iat"])):
            with self.assertRaises(bp.Refusal):
                bp.verify_token(tok, self.pk, aud, now)

    def test_fresh_jti_per_token(self) -> None:
        a = bp.sdk_key_token(self.sk, bp.SDK_KEY_ID, "a", 1, bytes(16))
        b = bp.sdk_key_token(self.sk, bp.SDK_KEY_ID, "a", 1, bytes(15) + b"\x01")
        self.assertNotEqual(a, b)

    def test_cp_dispositions(self) -> None:
        got = {(d["status"], d["error"], d["retried"]): d["expect"] for d in self.t["cp_dispositions"]}
        self.assertEqual(got[(401, "token_replayed", False)]["action"], "retry_fresh_token")
        self.assertEqual(got[(401, "token_replayed", True)], {"action": "fail", "reason": "token_replayed"})
        self.assertEqual(got[(429, "token_rate_limited", False)]["action"], "backoff")
        self.assertEqual(got[(401, "credential_inactive", False)], {"action": "fail", "reason": "credential_inactive"})
        self.assertEqual(got[(403, None, False)], {"action": "fail", "reason": "forbidden"})
        self.assertEqual(got[(503, "identity_unavailable", False)]["action"], "backoff")
        self.assertEqual(got[(302, None, False)]["action"], "fail")
        for d in self.t["cp_dispositions"]:
            self.assertEqual(bp.cp_disposition(d["status"], d["error"], d["retried"]), d["expect"])

    def test_routes_send_the_token_to_the_cp_only(self) -> None:
        t = json.loads((bp.SDK_GOLDEN_DIR / "sdk_key_token_golden.json").read_text("utf-8"))
        self.assertIs(t["follow_redirects"], False)
        self.assertEqual({k: (r["base"], r["auth"]) for k, r in t["routes"].items()},
                         {"certificates": ("cp", "sdk_key_token"), "document": ("cp", "sdk_key_token"),
                          "receipts": ("collector", "certificate")})
        self.assertEqual(t["routes"]["document"]["path"], "/v1/branchpoint/sdk/document")
        self.assertEqual(t["routes"]["certificates"]["path"], "/v1/branchpoint/sdk/certificates")
        self.assertEqual(t["routes"]["receipts"]["path"], "/v1/branchpoint/receipts")


if __name__ == "__main__":
    unittest.main(verbosity=1)
