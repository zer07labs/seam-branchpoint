# Assumptions — seam-experiments (Branchpoint)

Defaults taken by `plans/branchpoint.md`. Each is logged UNCONFIRMED and closed by `/reconcile` into `DECISIONS.md`.

| ID | Phase | Assumption | Status |
|----|-------|-----------|--------|
| A-1 | BP-4b | Tier caps and modes as in the design (low 2000 bp all modes / medium 500 bp no contextual / high 100 bp shadow, holdout, split) | UNCONFIRMED |
| A-2 | BP-7 | Identifiability floor placeholder 50 bp until derived from partner volume | UNCONFIRMED |
| A-3 | BP-7 | One experiment per decision point; overlap refused (`overlapping_experiment`) | UNCONFIRMED |
| A-4 | BP-10b/11 | Auto-pause only on non-provisional (horizon-complete) guardrail breaches | UNCONFIRMED |
| A-5 | BP-11 | Pause on stale evidence for high tier only | UNCONFIRMED |
| A-6 | BP-11 | High-tier fetch interval equals the 300 s default | UNCONFIRMED |
| A-7 | BP-9 | Split stickiness per allocation unit (default the admitted subject, D8), not per session | UNCONFIRMED |
| A-8 | BP-2 | Metric key grammar `^[a-z][a-z0-9_]{0,62}$`, ≤ 16 entries | UNCONFIRMED |
| A-9 | BP-3-Q (DEFERRED) | RD: local-linear, triangular kernel, MSE-optimal bandwidth; McCrary refusal at p<0.01 | UNCONFIRMED |
| A-10 | BP-4b/BP-10a/BP-11 | Distinct-unit floor ~50 units per arm (design-effect-adjusted effective n), enforced CP-side: declared `min_units_per_arm` ≥ floor at draft, `promote` verdict refused below it, auto-conclude `insufficient_units` at max duration. Not a runtime refusal (no `unit_tag` exists before Live). | UNCONFIRMED |
| A-11 | AS-4 | Attested receipt-chain completeness floor 99.5% per (experiment, window); below it the window is refused `receipt_chain_incomplete` | UNCONFIRMED |
| A-12 | AS-1/AS-2 | SDK config poll interval 60 s (the attested stop latency) | UNCONFIRMED |
