// HttpTransport against a real node:http server on 127.0.0.1 that fronts the in-repo FakeCP / FakeCollector.

import assert from "node:assert/strict";
import { type IncomingMessage, type Server, type ServerResponse, createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, describe, test } from "node:test";
import { DEFAULT_ROUTES } from "../src/auth.ts";
import { HttpTransport, TransportError } from "../src/transport.ts";
import type { FakeCP, FakeCollector } from "../src/fake.ts";
import { harness, units } from "./_harness.ts";
import { verifyBatches } from "./_verifier.ts";

type Mode = "normal" | "redirect" | "hang" | "429" | "malformed" | "big" | "garbage";

interface Seen {
  method: string;
  path: string;
  headers: IncomingMessage["headers"];
  body: string;
}

let server: Server;
let base = "";
let mode: Mode = "normal";
let target: { cp: FakeCP; collector: FakeCollector } | null = null;
const seen: Seen[] = [];

function reply(res: ServerResponse, status: number, body: Uint8Array, headers: Record<string, string> = {}): void {
  res.writeHead(status, { "Content-Type": "application/json", "Content-Length": String(body.length), ...headers });
  res.end(body);
}

before(async () => {
  server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      seen.push({ method: req.method!, path: req.url!, headers: req.headers, body });
      if (req.url === "/elsewhere") return reply(res, 200, Buffer.from("{}"));
      if (mode === "redirect") return reply(res, 302, Buffer.alloc(0), { Location: "/elsewhere" });
      if (mode === "hang") { // answers long after the client's AbortSignal.timeout fired
        setTimeout(() => reply(res, 503, Buffer.alloc(0)), 400).unref();
        return;
      }
      if (mode === "429") return reply(res, 429, Buffer.from('{"error":"rate_limited"}'));
      if (mode === "big") return reply(res, 200, Buffer.alloc(4096, 0x61));
      if (mode === "garbage") {
        req.socket.end("HTTP/1.1 9x9 nope\r\nbroken header\r\n\r\n");
        return;
      }
      if (mode === "malformed" && req.url === DEFAULT_ROUTES.receipts.path) return reply(res, 200, Buffer.from("[1,"));
      const t = target!;
      const auth = req.headers.authorization;
      const token = typeof auth === "string" && auth.startsWith("Bearer ") ? auth.slice(7) : null;
      try {
        let r;
        if (req.url === DEFAULT_ROUTES.document.path && req.method === "GET") {
          const inm = req.headers["if-none-match"];
          r = t.cp.handleDocument(token, typeof inm === "string" ? inm : null);
        } else if (req.url === DEFAULT_ROUTES.certificates.path && req.method === "POST") {
          r = t.cp.handleCertificate(token, body);
        } else if (req.url === DEFAULT_ROUTES.receipts.path && req.method === "POST") {
          r = t.collector.receive(body);
        } else r = { status: 404, body: Buffer.from('{"error":"not_found"}') };
        reply(res, r.status, r.body);
      } catch {
        res.socket?.destroy();
      }
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  server.closeAllConnections();
  await new Promise<void>((r) => server.close(() => r()));
});

const http = (o: { timeoutMs?: number; maxDocumentBytes?: number } = {}): HttpTransport =>
  new HttpTransport({ cpUrl: base, collectorUrl: `${base}/`, allowInsecureHttp: true, ...o });

/** A client whose transport is HttpTransport to the local server (fronting this harness's fakes). */
function wired(o: { timeoutMs?: number } = {}) {
  const h = harness({ wrap: () => http(o) });
  target = { cp: h.cp, collector: h.collector };
  return h;
}

const reset = (m: Mode = "normal"): void => {
  mode = m;
  seen.length = 0;
};

describe("HttpTransport against 127.0.0.1", () => {
  test("end to end: headers, token on CP routes only, If-None-Match + 304, receipts verify", async () => {
    reset();
    const h = wired();
    await h.client.start();
    assert.ok(h.client.ready && h.client.attested);
    for (const u of units(40)) h.client.evaluate("checkout", u, 0);
    await h.client.flush();
    await h.client.refresh();
    const doc = seen.filter((s) => s.path === DEFAULT_ROUTES.document.path);
    const cert = seen.find((s) => s.path === DEFAULT_ROUTES.certificates.path)!;
    const batch = seen.find((s) => s.path === DEFAULT_ROUTES.receipts.path)!;
    for (const s of [...doc, cert]) {
      assert.match(String(s.headers.authorization), /^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
      assert.equal(s.headers["user-agent"], "seam-branchpoint-ts");
    }
    assert.equal(batch.headers.authorization, undefined, "the collector request carries no Authorization");
    assert.equal(batch.headers["content-type"], "application/json");
    assert.equal(cert.method, "POST");
    assert.equal(doc[0]!.headers["if-none-match"], undefined);
    assert.equal(doc[1]!.headers["if-none-match"], h.cp.configDigest);
    assert.notEqual(doc[0]!.headers.authorization, doc[1]!.headers.authorization, "fresh token per request");
    assert.equal(h.client.stats().document_fetch_failure, null, "the 304 was accepted");
    assert.equal(h.client.stats().receipts_uploaded, 40);
    const rep = verifyBatches(h.collector.batches, [h.cp.issuerPublicKey]);
    assert.equal(rep.accepted, 40);
    await h.client.close();
  });

  test("a redirect is never followed, on CP and collector routes", async () => {
    reset("redirect");
    const t = http();
    assert.equal((await t.getDocument("tok", null)).status, 302, "reported as an answer, not followed");
    assert.equal((await t.postBatch("{}")).status, 302);
    assert.ok(!seen.some((s) => s.path === "/elsewhere"));
    reset();
    const h = wired();
    await h.client.start();
    h.client.evaluate("checkout", "user-1", 0);
    mode = "redirect";
    await h.client.refresh();
    await h.client.flush();
    assert.equal(h.client.stats().document_fetch_failure, "redirect_refused");
    assert.equal(h.client.stats().upload_failure, "http_302");
    assert.ok(!seen.some((s) => s.path === "/elsewhere"));
    mode = "normal";
    await h.client.close();
  });

  test("a timeout is a `timeout` TransportError and is counted by the client", async () => {
    reset("hang");
    const t = http({ timeoutMs: 100 });
    await assert.rejects(t.postCertificate("tok", "{}"), (e: unknown) => e instanceof TransportError && e.kind === "timeout");
    const h = wired({ timeoutMs: 100 });
    await h.client.start();
    assert.equal(h.client.stats().document_fetch_failure, "timeout");
    assert.equal(h.client.stats().certificate_failure, "timeout");
    mode = "normal";
    await h.client.close();
  });

  test("429 backs off and keeps the cache; 401 token_replayed is retried once with a fresh token", async () => {
    reset();
    const h = wired();
    await h.client.start();
    assert.ok(h.client.ready);
    mode = "429";
    await h.client.refresh();
    assert.equal(h.client.stats().document_fetch_failure, "rate_limited");
    assert.ok(h.client.ready);
    mode = "normal";
    seen.length = 0;
    h.cp.script("document", "replay");
    await h.client.refresh();
    const doc = seen.filter((s) => s.path === DEFAULT_ROUTES.document.path);
    assert.equal(doc.length, 2);
    assert.notEqual(doc[0]!.headers.authorization, doc[1]!.headers.authorization);
    assert.equal(h.client.stats().document_fetch_failure, null);
    seen.length = 0;
    h.cp.script("document", "replay", "replay");
    await h.client.refresh();
    assert.equal(seen.filter((s) => s.path === DEFAULT_ROUTES.document.path).length, 2, "only one retry");
    assert.equal(h.client.stats().document_fetch_failure, "token_replayed");
    await h.client.close();
  });

  test("a malformed 200 from the collector is retried with nothing counted", async () => {
    reset();
    const h = wired();
    await h.client.start();
    h.client.evaluate("checkout", "user-1", 0);
    mode = "malformed";
    await h.client.flush();
    let s = h.client.stats();
    assert.equal(s.upload_failure, "malformed_answer");
    assert.equal(s.batches_malformed_answer, 1);
    assert.equal(s.receipts_uploaded + s.receipts_rejected, 0);
    mode = "normal";
    await h.client.flush();
    s = h.client.stats();
    assert.equal(s.receipts_uploaded, 1);
    await h.client.close();
  });

  test("the response body is capped at cap+1 octets", async () => {
    reset("big");
    const r = await http({ maxDocumentBytes: 64 }).getDocument("tok", null);
    assert.equal(r.status, 200);
    assert.equal(r.body.length, 65);
    const c = await http().postBatch("{}");
    assert.equal(c.body.length, 4096);
    mode = "normal";
  });

  test("error classes: connection refused is `network`, a broken response is `protocol` or `network`", async () => {
    reset("garbage");
    const kinds = new Set(["network", "protocol"]);
    await assert.rejects(http().getDocument("tok", null), (e: unknown) => e instanceof TransportError && kinds.has(e.kind));
    mode = "normal";
    const dead = createServer();
    await new Promise<void>((r) => dead.listen(0, "127.0.0.1", r));
    const port = (dead.address() as AddressInfo).port;
    await new Promise<void>((r) => dead.close(() => r()));
    const t = new HttpTransport({ cpUrl: `http://127.0.0.1:${port}`, collectorUrl: `http://127.0.0.1:${port}`,
      allowInsecureHttp: true });
    const err = await t.getDocument("secret-token", null).then(() => null, (e: unknown) => e);
    assert.ok(err instanceof TransportError);
    assert.equal(err.kind, "network");
    assert.ok(!String(err.message).includes("127.0.0.1") && !String(err.message).includes(String(port)));
    assert.ok(!String(err.stack).includes("secret-token"));
  });

  test("construction: TLS only unless allowInsecureHttp; credentials refused; errors never echo the URL", () => {
    const msgs: string[] = [];
    for (const o of [{ cpUrl: "http://127.0.0.1:9", collectorUrl: "https://127.0.0.1:9" },
      { cpUrl: "https://u:p@127.0.0.1:9", collectorUrl: "https://127.0.0.1:9" },
      { cpUrl: "not a url", collectorUrl: "https://127.0.0.1:9" },
      { cpUrl: "https://127.0.0.1:9", collectorUrl: "https://127.0.0.1:9", timeoutMs: 0 },
      { cpUrl: "https://127.0.0.1:9", collectorUrl: "https://127.0.0.1:9", routes: { document: "no-slash" } }]) {
      assert.throws(() => new HttpTransport(o), (e: unknown) => {
        msgs.push(String(e));
        return e instanceof TypeError || e instanceof RangeError;
      });
    }
    for (const m of msgs) assert.ok(!m.includes("127.0.0.1") && !m.includes("u:p") && !m.includes("not a url"), m);
    assert.doesNotThrow(() => new HttpTransport({ cpUrl: "https://127.0.0.1:9", collectorUrl: "https://127.0.0.1:9" }));
  });

  test("client logs never carry the URL, port or a token", async () => {
    reset("hang");
    const h = wired({ timeoutMs: 50 });
    await h.client.start();
    mode = "normal";
    const port = base.split(":").at(-1)!;
    assert.ok(h.logs.length > 0);
    for (const l of h.logs) assert.ok(!l.includes("127.0.0.1") && !l.includes(port) && !l.includes("Bearer"), l);
    assert.ok(!JSON.stringify(h.client.stats()).includes("127.0.0.1"));
    await h.client.close();
  });
});
