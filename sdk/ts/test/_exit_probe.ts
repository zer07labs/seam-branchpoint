// Child-process probe for client.test.ts: start a client and never close it. The process must still exit on its own,
// which proves every poll / renew / flush timer is unref()ed.

import { harness } from "./_harness.ts";

const h = harness();
await h.client.start();
h.client.evaluate("checkout", "user-1", 0);
process.stdout.write(`probe: attested=${h.client.attested}\n`);
