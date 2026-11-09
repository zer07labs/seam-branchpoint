// §10 SDK-key token (fresh jti, claims, refusals), key secrecy, and the issued-certificate check.

import assert from "node:assert/strict";
import { verify } from "node:crypto";
import { inspect } from "node:util";
import { describe, test } from "node:test";
import {
  AUD_RE,
  DEFAULT_AUDIENCE,
  Refusal,
  SdkKey,
  TOKEN_LIFETIME_S,
  TOKEN_TYP,
  TokenInputError,
  WorkloadKey,
  buildWcert,
  certEnvelope,
  checkIssuedCert,
  keyId,
  pinKeys,
  privateKeyFromSeed,
  publicKeyFromRaw,
  rawPublicKey,
  sdkKeyToken,
  signCert,
} from "../src/index.ts";
import { fromHex, sdkg } from "./_golden.ts";

const tk = sdkg("sdk_key_token_golden.json");
const SEED = fromHex(tk.sdk_key_seed_hex);
const KID = tk.sdk_key_id as string;

const decode = (part: string) => JSON.parse(Buffer.from(part, "base64url").toString("utf8"));

describe("SdkKey tokens", () => {
  test("one fresh jti per token from the CSPRNG; claims and lifetime", () => {
    const key = new SdkKey(KID, SEED, { now: () => 1762560000123 });
    const seen = new Set<string>();
    for (let k = 0; k < 200; k++) {
      const [h, c, s] = key.token().split(".");
      const header = decode(h!);
      const claims = decode(c!);
      assert.deepEqual(header, { alg: "EdDSA", typ: TOKEN_TYP, kid: KID });
      assert.deepEqual(Object.keys(claims), ["iss", "sub", "aud", "iat", "exp", "jti"]);
      assert.deepEqual([claims.iss, claims.sub, claims.aud, claims.iat, claims.exp], [KID, KID, DEFAULT_AUDIENCE,
        1762560000, 1762560000 + TOKEN_LIFETIME_S]);
      assert.match(claims.jti, /^[A-Za-z0-9_-]{22}$/);
      assert.ok(!seen.has(claims.jti));
      seen.add(claims.jti);
      assert.ok(verify(null, Buffer.from(`${h}.${c}`), publicKeyFromRaw(key.publicKey), Buffer.from(s!, "base64url")));
    }
  });

  test("audience is carried through; base64url without padding", () => {
    const t = new SdkKey(KID, SEED).token("seam-collector");
    assert.equal(decode(t.split(".")[1]!).aud, "seam-collector");
    assert.ok(!t.includes("=") && !t.includes("+") && !t.includes("/"));
  });

  test("refuses a bad kid, audience, iat or jti up front with TokenInputError", () => {
    const sk = privateKeyFromSeed(SEED);
    const jti = new Uint8Array(16);
    for (const kid of ["", "bk_", `bk_${"0".repeat(25)}`, `BK_${"0".repeat(26)}`, `bk_${"U".repeat(26)}`,
      `bk_${"u".repeat(26)}`, `bk_${"0".repeat(25)}\u00e9`, `bk_${"0".repeat(26)}\n`]) {
      assert.throws(() => sdkKeyToken(sk, kid, "a", 0, jti), TokenInputError, kid);
      assert.throws(() => new SdkKey(kid, SEED), TokenInputError, kid);
    }
    // aud: 1..256 visible ASCII (0x21..0x7E) minus '"' and '\\'; no space, no DEL, nothing non-ASCII.
    for (const aud of ["", "\u00e9", "seam-\u00e9", "\ud800", "a b", 'a"b', "a\\b", "a\u007fb", "a\tb", "x".repeat(257),
      "\u{1F600}"]) {
      assert.throws(() => sdkKeyToken(sk, KID, aud, 0, jti), TokenInputError, JSON.stringify(aud));
      assert.throws(() => new SdkKey(KID, SEED).token(aud), TokenInputError, JSON.stringify(aud));
    }
    for (const aud of ["!", "~", "x".repeat(256), "seam-collector", "a#[]{}"]) sdkKeyToken(sk, KID, aud, 0, jti);
    assert.ok(AUD_RE.test("seam-collector") && !AUD_RE.test("\u00e9"));
    for (const iat of [-1, 1.5, Number.NaN, Infinity, Number.MAX_SAFE_INTEGER - 59]) {
      assert.throws(() => sdkKeyToken(sk, KID, "a", iat, jti), TokenInputError, String(iat));
    }
    sdkKeyToken(sk, KID, "a", Number.MAX_SAFE_INTEGER - 60, jti);
    for (const j of [new Uint8Array(15), new Uint8Array(17), "0".repeat(16) as never]) {
      assert.throws(() => sdkKeyToken(sk, KID, "a", 0, j), TokenInputError);
    }
    assert.throws(() => new SdkKey(KID, SEED.subarray(0, 31)));
    const e = (() => { try { sdkKeyToken(sk, KID, "\u00e9", 0, jti); } catch (x) { return x; } })();
    assert.ok(e instanceof TokenInputError && e instanceof Error && e.name === "TokenInputError");
  });

  test("private keys never appear in JSON, inspect output or enumerable state", () => {
    const seedHex = SEED.toString("hex");
    const key = new SdkKey(KID, SEED);
    const wl = WorkloadKey.fromSeed(SEED);
    for (const obj of [key, wl]) {
      const dumps = [JSON.stringify(obj), inspect(obj, { showHidden: true, depth: 5 }), String(Object.keys(obj)),
        JSON.stringify(Object.getOwnPropertyNames(obj))];
      for (const d of dumps) {
        assert.ok(!d.includes(seedHex), d);
        assert.ok(!d.includes(SEED.toString("base64url")), d);
      }
    }
    assert.deepEqual(JSON.parse(JSON.stringify(key)), { kid: KID });
    assert.deepEqual(JSON.parse(JSON.stringify(wl)), { keyId: wl.keyId });
  });
});

describe("checkIssuedCert", () => {
  const cp = privateKeyFromSeed(Buffer.alloc(32, 3));
  const pinned = pinKeys([rawPublicKey(cp)]);
  const wl = WorkloadKey.fromSeed(Buffer.alloc(32, 4));
  const expect = { publicKey: wl.publicKey, sdkKeyId: KID, tenant: "t1" };
  const issue = (pk: Uint8Array, sdk = KID, tenant = "t1", nb = 1000, na = 2000) => {
    const body = buildWcert(pk, nb, na, sdk, tenant);
    return certEnvelope(body, signCert(cp, body), keyId(rawPublicKey(cp)));
  };

  test("accepts a current certificate for this workload, SDK key and tenant", () => {
    const c = checkIssuedCert(issue(wl.publicKey), pinned, expect, 1500);
    assert.equal(c.tenant, "t1");
    assert.ok(c.pk.equals(wl.publicKey));
  });

  test("refuses a certificate for another key, SDK key or tenant, or outside its window", () => {
    const reason = (f: () => unknown) => {
      try {
        f();
        return "ok";
      } catch (e) {
        assert.ok(e instanceof Refusal);
        return e.reason;
      }
    };
    const other = WorkloadKey.fromSeed(Buffer.alloc(32, 5)).publicKey;
    assert.equal(reason(() => checkIssuedCert(issue(other), pinned, expect, 1500)), "cert_mismatch");
    assert.equal(reason(() => checkIssuedCert(issue(wl.publicKey, `bk_${"1".repeat(26)}`), pinned, expect, 1500)),
      "cert_mismatch");
    assert.equal(reason(() => checkIssuedCert(issue(wl.publicKey, KID, "t2"), pinned, expect, 1500)), "cert_mismatch");
    assert.equal(reason(() => checkIssuedCert(issue(wl.publicKey), pinned, expect, 999)), "cert_not_current");
    assert.equal(reason(() => checkIssuedCert(issue(wl.publicKey), pinned, expect, 2000)), "cert_not_current");
    assert.equal(reason(() => checkIssuedCert(issue(wl.publicKey), pinKeys([]), expect, 1500)).startsWith("cert_"), true);
    for (const now of [Number.NaN, Infinity, -Infinity, "1500" as never, undefined as never]) {
      assert.equal(reason(() => checkIssuedCert(issue(wl.publicKey), pinned, expect, now)), "cert_not_current", String(now));
    }
  });
});
