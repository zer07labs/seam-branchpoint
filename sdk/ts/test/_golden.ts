// Test helper: loads the committed golden vectors from the repo (never the reference implementations).

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const SDK_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const REPO = resolve(SDK_DIR, "..", "..");
export const AS0_DIR = join(REPO, "contract", "golden", "branchpoint");
export const SDK_GOLDEN_DIR = join(REPO, "contract", "golden", "branchpoint-sdk");

// The golden files are trusted test data; `any` keeps the vector walks readable.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type G = any;

export const load = (dir: string, name: string): G => JSON.parse(readFileSync(join(dir, name), "utf8"));
export const as0 = (name: string): G => load(AS0_DIR, name);
export const sdkg = (name: string): G => load(SDK_GOLDEN_DIR, name);

export const fromHex = (h: string): Buffer => Buffer.from(h, "hex");
