# Lake House asks (seam-connectors plan 49) — seam-experiments#5

Spec (source of truth, not paraphrased here): seam-connectors `plans/cross-repo/seam-experiments-lakehouse.md` and
`plans/49-lakehouse.md` (Rule 1, PG5, PG7, DC4). Docs only. Line anchors that plan 49 cites in `branchpoint.md`
(`:625-629`, `:627`, `:658`, `:1138`, `:1163`, `:1170-1171`, `:1193`) and `DECISIONS.md:7` keep their line numbers.
Every edit above `:1193` replaces a line in place; new text goes after `:1193`.

### P1 — E1..E4 in the Branchpoint plan
- **Status:** DONE
- **E1** (BP-5 evidence is tenant-free): already resolved by #3 (`branchpoint.md:627`,
  `cross-repo/seam-control-plane-branchpoint.md:118`). Recorded in D14 only. No edit.
- **E2** (Hindsight lookback): D14, plus a new bullet in § _Erasure & retention_ (after `:1193`) and pointers in BP-5 (`:639`) and BP-11 (`:1015`).
- **E3** (BP-17 on per-tenant tables): `:1137-1138` rewritten in place. OD-4 (the shared-table purge) stays open.
- **E4** (citation): an amendment line on D1 in `DECISIONS.md` that points to `:1170-1171` and to BP-17.
- **Not decided here:** plan 49 OD-4 and OD-8a.
- **Acceptance:** the anchors above are unchanged in number. D14 cites real CP code anchors (`experiments.ts:49-51,99,494-497`,
  `decision-points.ts:53`) and seam-learning `hindsight.py:92-96`. Nothing live is applied.

### P2 — D14 amendment: lookback 245 d, floor 365 d (lakehouse wave 27)
- **Status:** DONE
- **Owner, 2026-11-05:** "Keep 365d, shorten lookback". `learning_events_days` = 365 stays for the shared raw class,
  so 120 d + `L` ≤ 365 d gives `L` = 245 d.
- **Edits:** an amendment bullet appended to D14 (`DECISIONS.md` is append-only; the evidence hold and the optional
  per-tenant floor kept, the latter now capped at 365 d − the tenant's longest horizon; floor 365 d; what 245 d cannot
  answer). `branchpoint.md` § _Erasure & retention_ bullet (from `:1194`) rewritten; pointers at BP-5 (`:639`)
  and BP-11 (`:1015`) replaced in place.
- **Acceptance:** the anchors plan 49 cites (`branchpoint.md:625-629`, `:627`, `:658`, `:1138`, `:1170-1171`,
  `:1193`; `DECISIONS.md:7`) are unchanged. Nothing live is applied.

