// Wire primitives: toMicros (table + properties + refusals), strict JSON, JCS refusals, hex/key helpers, ULIDs.

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";
import {
  JcsError,
  JsonFloat,
  ULID_RE,
  UlidGenerator,
  bucket,
  ed25519Verify,
  isJsonObject,
  jcsFlat,
  jcsTree,
  pinKeys,
  privateKeyFromSeed,
  publicKeyFromRaw,
  rawPublicKey,
  strictParse,
  toMicros,
  toPlainFrozen,
  unhex,
  unitTag,
} from "../src/index.ts";
import { REPO, SDK_DIR, type G } from "./_golden.ts";

// The Python SDK's shared table pins both SDKs and must exist (a missing file fails the test); this package's own
// independently generated copy also runs.
const PY_TABLE = join(REPO, "sdk", "python", "tests", "micros_table.json");
const TS_TABLE = join(SDK_DIR, "test", "micros_table.json");
const TABLES = [PY_TABLE, TS_TABLE];
const NON_FINITE: Record<string, number> = { NaN: Number.NaN, Infinity: Infinity, "-Infinity": -Infinity };

describe("toMicros", () => {
  for (const path of TABLES) test(`table (${path === PY_TABLE ? "sdk/python/tests" : "sdk/ts/test"}/micros_table.json)`, () => {
    assert.ok(existsSync(path), `missing shared micros table: ${path}`);
    const table: G = JSON.parse(readFileSync(path, "utf8"));
    // Python format: {rows: [{kind, x: "<decimal text>", micros | error}]}; local format: {cases: [{x: number, ...}]}.
    const cases: G[] = table.rows ?? table.cases;
    assert.ok(cases.length >= 30);
    for (const c of cases) {
      const x = typeof c.x === "number" ? c.x : (NON_FINITE[c.x] ?? Number(c.x));
      assert.ok(typeof c.x === "number" || c.x in NON_FINITE || !Number.isNaN(x), String(c.x));
      if (c.error !== undefined) assert.throws(() => toMicros(x), RangeError, String(c.x));
      else assert.equal(toMicros(x), c.micros, String(c.x));
    }
  });

  test("named rounding cases", () => {
    assert.equal(toMicros(0.29), 290000); // 0.29 * 1e6 === 289999.99999999994 in float arithmetic
    assert.equal(toMicros(0.1234565), 123456); // exact half, rounds to even
    assert.equal(toMicros(0.1234575), 123458); // exact half, rounds to even (up)
    assert.equal(toMicros(-0.0000025), -2);
    assert.ok(Object.is(toMicros(-0), 0));
    assert.ok(Object.is(toMicros(-1e-9), 0)); // never -0
  });

  test("property: toMicros(n / 1e6) === n for integers |n| <= 2^40", () => {
    let s = 0x9e3779b9;
    const rnd = (): number => {
      s = (Math.imul(s ^ (s >>> 15), 0x2c1b3c6d) + 0x6d2b79f5) >>> 0;
      return s;
    };
    for (let k = 0; k < 20000; k++) {
      const n = ((rnd() % 2 ** 20) * 2 ** 20 + (rnd() % 2 ** 20)) * (rnd() & 1 ? -1 : 1);
      assert.equal(toMicros(n / 1e6), n === 0 ? 0 : n, String(n));
    }
  });

  test("property: integers scale exactly up to the range limit", () => {
    for (const n of [0, 1, -1, 7, 9007199254, -9007199254]) assert.equal(toMicros(n), n * 1e6);
  });

  test("refusals: non-number, NaN, Infinity, out of range; the value never appears in the error", () => {
    for (const bad of ["1", null, undefined, 1n, true, {}]) {
      assert.throws(() => toMicros(bad as unknown as number), TypeError);
    }
    for (const bad of [Number.NaN, Infinity, -Infinity, 1e10, -1e10, 9007199254.8, 1.7976931348623157e308]) {
      assert.throws(() => toMicros(bad, "reward"), (e: Error) => e instanceof RangeError && e.message.startsWith("reward:") &&
        !e.message.includes(String(bad)));
    }
  });
});

describe("strictParse", () => {
  test("refuses duplicate members, NaN/Infinity, trailing data, bad escapes, control characters, BOM", () => {
    for (const bad of ['{"a":1,"a":2}', "NaN", "Infinity", "-Infinity", "[1,]", '{"a":1}x', '"\\x"', '"\u0001"',
      "﻿{}", "01", "1.", ".5", "+1", '{"a"}', "", " ", "[", '"\\u12"', "tru", "{'a':1}"]) {
      assert.throws(() => strictParse(bad), SyntaxError, JSON.stringify(bad));
    }
  });

  test("floats are JsonFloat (never a valid integer), integers are numbers, -0 is 0", () => {
    const v = strictParse('{"a":1.0,"b":1e0,"c":7,"d":-0,"e":[2.5]}') as Record<string, unknown>;
    assert.ok(v.a instanceof JsonFloat && v.b instanceof JsonFloat);
    assert.equal(v.c, 7);
    assert.ok(Object.is(v.d, 0));
    assert.equal(((v.e as unknown[])[0] as JsonFloat).value, 2.5);
  });

  test("objects have a null prototype; __proto__ is plain data", () => {
    const v = strictParse('{"__proto__":{"x":1},"constructor":2}') as Record<string, unknown>;
    assert.equal(Object.getPrototypeOf(v), null);
    assert.ok(Object.hasOwn(v, "__proto__"));
    const plain = toPlainFrozen(v) as Record<string, unknown>;
    assert.equal(Object.getPrototypeOf(plain), Object.prototype);
    assert.ok(Object.hasOwn(plain, "__proto__"));
    assert.equal(({} as Record<string, unknown>).x, undefined); // nothing polluted
    assert.ok(Object.isFrozen(plain) && Object.isFrozen(plain.__proto__));
  });

  test("agrees with JSON.parse on valid documents and is linear on long input", () => {
    for (const t of ['{"a":[1,"x",{"b":null}],"c":true,"d":false}', '"\\u00e9\\ud83d\\ude00\\n"', "[]", "{}", "-12"]) {
      assert.deepEqual(JSON.parse(JSON.stringify(toPlainFrozen(strictParse(t)))), JSON.parse(t));
    }
    const big = `[${"1234567890,".repeat(200000)}1]`;
    const t0 = performance.now();
    assert.equal((strictParse(big) as unknown[]).length, 200001);
    assert.ok(performance.now() - t0 < 2000);
  });

  test("nesting depth is bounded (no stack overflow)", () => {
    assert.throws(() => strictParse("[".repeat(100000)), SyntaxError);
  });
});

describe("JCS", () => {
  test("jcsFlat refuses floats, negatives, non-ASCII, nested, booleans, null, unsafe ints, escapes", () => {
    for (const bad of [{ a: 1.5 }, { a: -1 }, { a: "é" }, { a: { b: 1 } }, { a: [1] }, { a: true }, { a: null },
      { a: 2 ** 53 }, { a: 'q"' }, { a: "b\\" }, { a: "\n" }, { é: "a" }, { a: new JsonFloat("1.0") }, [], "x"]) {
      assert.throws(() => jcsFlat(bad), JcsError, JSON.stringify(bad));
    }
    assert.equal(jcsFlat({ b: 2, a: "x", c: 0 }).toString(), '{"a":"x","b":2,"c":0}');
  });

  test("jcsTree: sorted keys, nested values, safe ints both signs; refuses floats, bools, null, lone surrogates", () => {
    assert.equal(jcsTree({ b: [1, -2, { d: "é", c: "" }], a: {} }).toString(), '{"a":{},"b":[1,-2,{"c":"","d":"é"}]}');
    for (const bad of [{ a: 1.5 }, { a: true }, { a: null }, { a: 2 ** 53 }, { a: "\ud800" }, { "\udc00": 1 },
      { a: new JsonFloat("1") }, undefined]) {
      assert.throws(() => jcsTree(bad), JcsError, String(JSON.stringify(bad)));
    }
  });
});

describe("helpers", () => {
  test("unhex is strict", () => {
    assert.deepEqual([...unhex("00ff")], [0, 255]);
    for (const bad of ["0", "0g", "AB", " 00", null, 1]) assert.throws(() => unhex(bad));
  });

  test("Ed25519 helpers; verify never throws", () => {
    const sk = privateKeyFromSeed(Buffer.alloc(32, 7));
    const pk = publicKeyFromRaw(rawPublicKey(sk));
    assert.ok(!ed25519Verify(pk, Buffer.from("m"), Buffer.alloc(63)));
    assert.ok(!ed25519Verify(pk, Buffer.from("m"), Buffer.alloc(64)));
    assert.throws(() => privateKeyFromSeed(Buffer.alloc(31)));
    assert.throws(() => publicKeyFromRaw(Buffer.alloc(33)));
    assert.equal(pinKeys([rawPublicKey(sk)]).size, 1);
  });

  test("bucket and unitTag refuse units with no UTF-8 encoding; NUL and non-ASCII are valid units", () => {
    const salt = Buffer.alloc(32, 1);
    assert.throws(() => bucket(salt, "01JBP9000000000000000000AB", "a\ud800"), TypeError);
    assert.throws(() => unitTag(salt, "\udc00"), TypeError);
    assert.ok(bucket(salt, "01JBP9000000000000000000AB", "a\u0000b") >= 0);
    assert.equal(unitTag(salt, "ü").length, 32);
  });

  test("isJsonObject", () => {
    assert.ok(isJsonObject({}) && !isJsonObject([]) && !isJsonObject(null) && !isJsonObject(new JsonFloat("1.0")));
  });
});

describe("UlidGenerator", () => {
  test("grammar, strictly increasing within a millisecond and when the clock goes backwards", () => {
    let now = 1762560000000;
    const g = new UlidGenerator({ now: () => now });
    let prev = "";
    for (let k = 0; k < 5000; k++) {
      if (k === 2000) now -= 10_000; // clock steps back
      if (k === 3000) now += 20_000;
      const id = g.next();
      assert.match(id, ULID_RE);
      assert.ok(id > prev, `${id} <= ${prev}`);
      prev = id;
    }
  });

  test("timestamp prefix encodes the clock; random part from the injected source", () => {
    const g = new UlidGenerator({ now: () => 0, randomFill: (b) => b.fill(0) });
    assert.equal(g.next(), "00000000000000000000000000");
    assert.equal(g.next(), "00000000000000000000000001");
    const h = new UlidGenerator({ now: () => 2 ** 48 - 1, randomFill: (b) => b.fill(0) });
    assert.equal(h.next().slice(0, 10), "7ZZZZZZZZZ");
  });

  test("random-part overflow advances the timestamp instead of blocking", () => {
    const g = new UlidGenerator({ now: () => 5, randomFill: (b) => b.fill(0xff) });
    const a = g.next();
    assert.equal(a.slice(10), "ZZZZZZZZZZZZZZZZ");
    const b = g.next();
    assert.ok(b > a);
    assert.equal(b.slice(0, 10), "0000000006");
  });

  test("refuses a bad clock", () => {
    assert.throws(() => new UlidGenerator({ now: () => -1 }).next(), RangeError);
    assert.throws(() => new UlidGenerator({ now: () => 2 ** 48 }).next(), RangeError);
    assert.throws(() => new UlidGenerator({ now: () => 1.5 }).next(), RangeError);
  });
});
