// Static guarantees: no import of the reference implementations, src imports only node:crypto and local modules (the
// openfeature subpath adds only its peer),
// zero runtime dependencies, and importing the package does no network, process or timer work.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";
import { SDK_DIR } from "./_golden.ts";

const files = (dir: string) => readdirSync(join(SDK_DIR, dir)).filter((f) => f.endsWith(".ts")).map((f) => join(SDK_DIR, dir, f));
const specifiers = (path: string) =>
  [...readFileSync(path, "utf8").matchAll(/(?:^|\n)\s*(?:import|export)\b[^;]*?\bfrom\s+["']([^"']+)["']|import\(\s*["']([^"']+)["']|(?:^|\n)\s*import\s+["']([^"']+)["']/g)]
    .map((m) => m[1] ?? m[2] ?? m[3]!);

describe("static", () => {
  test("the specifier scanner sees every import form, including a bare side-effect import", () => {
    const tmp = join(SDK_DIR, "test", "_specifier_probe.tmp");
    writeFileSync(tmp, 'import "a";\nimport b from "b";\nexport { c } from "c";\nawait import("d");\nimport \'e\';\n');
    try {
      assert.deepEqual(specifiers(tmp).sort(), ["a", "b", "c", "d", "e"]);
    } finally {
      rmSync(tmp);
    }
  });

  test("nothing in src or test imports the reference implementations", () => {
    for (const f of [...files("src"), ...files("test")]) {
      for (const s of specifiers(f)) assert.ok(!/reference|branchpoint_ref/.test(s), `${f}: ${s}`);
      if (!f.endsWith("static.test.ts")) assert.ok(!readFileSync(f, "utf8").includes("branchpoint_ref"), f);
    }
  });

  test("src imports only node:crypto and local .ts modules", () => {
    for (const f of files("src")) {
      for (const s of specifiers(f)) assert.ok(s === "node:crypto" || /^\.\/[a-z]+\.ts$/.test(s), `${f}: ${s}`);
    }
  });

  test("src/openfeature imports only @openfeature/server-sdk and the core's local modules; the core never imports it", () => {
    for (const f of files("src/openfeature")) {
      for (const s of specifiers(f)) assert.ok(s === "@openfeature/server-sdk" || /^\.\.\/[a-z]+\.ts$/.test(s), `${f}: ${s}`);
    }
    for (const f of files("src")) {
      for (const s of specifiers(f)) assert.ok(!/openfeature|otel/.test(s), `${f}: ${s}`);
    }
    // otel.ts reaches @opentelemetry/api only through its guarded lazy import (a variable specifier)
    assert.match(readFileSync(join(SDK_DIR, "src", "otel.ts"), "utf8"), /const OTEL_API = "@opentelemetry\/api";/);
  });

  test("package.json: the ./openfeature export and its peers (OpenFeature and OTel both optional)", () => {
    const pkg = JSON.parse(readFileSync(join(SDK_DIR, "package.json"), "utf8"));
    assert.deepEqual(pkg.exports["./openfeature"], { types: "./dist/openfeature/index.d.ts",
      default: "./dist/openfeature/index.js" });
    assert.ok(pkg.peerDependencies["@openfeature/server-sdk"]);
    assert.ok(pkg.peerDependencies["@opentelemetry/api"]);
    assert.deepEqual(pkg.peerDependenciesMeta, {
    "@openfeature/server-sdk": { optional: true },
    "@opentelemetry/api": { optional: true },
  });
    for (const d of ["@openfeature/server-sdk", "@opentelemetry/api", "@opentelemetry/sdk-trace-base"]) {
      assert.match(pkg.devDependencies[d], /^\d+\.\d+\.\d+$/, `${d} is pinned exactly`);
    }
  });

  test("package.json: ESM, node >= 22, zero runtime dependencies", () => {
    const pkg = JSON.parse(readFileSync(join(SDK_DIR, "package.json"), "utf8"));
    assert.equal(pkg.type, "module");
    assert.equal(pkg.engines.node, ">=22");
    assert.equal(pkg.dependencies, undefined);
    assert.ok(pkg.exports["."]);
  });

  test("importing the package does no network, process or timer work", () => {
    const probe = `
      const boom = (what) => () => { throw new Error("side effect at import: " + what); };
      const { createRequire } = await import("node:module");
      const require = createRequire(import.meta.url);
      const patch = (m, names) => { const mod = require("node:" + m); for (const k of names) mod[k] = boom(m + "." + k); };
      patch("net", ["connect", "createConnection", "createServer"]);
      require("node:net").Socket.prototype.connect = boom("net.Socket.connect");
      patch("http", ["request", "get", "createServer"]);
      patch("https", ["request", "get", "createServer"]);
      patch("dns", ["lookup", "resolve", "resolve4", "resolve6"]);
      patch("tls", ["connect"]);
      patch("dgram", ["createSocket"]);
      patch("child_process", ["spawn", "exec", "execFile", "fork", "spawnSync", "execSync", "execFileSync"]);
      globalThis.fetch = boom("fetch");
      globalThis.setTimeout = boom("setTimeout");
      globalThis.setInterval = boom("setInterval");
      require("node:module").syncBuiltinESMExports(); // make the patches visible to ESM named imports too
      const m = await import(${JSON.stringify(join(SDK_DIR, "src", "index.ts"))});
      if (typeof m.evaluate !== "function" || typeof m.verifyDocument !== "function") throw new Error("exports");
      console.log("clean");
    `;
    const out = execFileSync(process.execPath, ["--input-type=module", "-e", probe], { encoding: "utf8" });
    assert.equal(out.trim(), "clean");
  });
});
