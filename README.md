# seam-branchpoint

The neutral `branchpoint.v1` contract and the SDK cores and OpenFeature providers for **attested-grade
experiments**: the SDK assigns variants locally (`bpa1` buckets over a CP-signed config) and writes Ed25519-signed,
hash-chained receipts that the Seam collector verifies.

The contract, golden vectors, SDK cores and OpenFeature providers (`sdk/python`, `sdk/ts`) are available;
the first functional SDK release, **0.1.0**, is published on PyPI and npm.

## Names

| Registry | Name | Status |
|---|---|---|
| PyPI | `seam-branchpoint` (import `seam_branchpoint`) | 0.1.0 published: SDK core and optional OpenFeature/OTel extras |
| npm | `@zer07labs/seam-branchpoint` | 0.1.0 published: SDK core and OpenFeature/OTel integration |
| Buf (BSR) | `buf.build/zer07labs/branchpoint` | module `branchpoint.v1` |

The OpenFeature providers ship as `seam_branchpoint.openfeature` and `@zer07labs/seam-branchpoint/openfeature`.

## Document versions each SDK release reads

| SDK release | `branchpoint-sdk` document `v` |
|---|---|
| 0.0.0 (placeholder) | none — reads no document |
| 0.1.0 (Python and TypeScript) | `v = 1` |

Every release's notes repeat its row.

## Contents

| Path | What |
|---|---|
| [`docs/spec/branchpoint-v1.md`](docs/spec/branchpoint-v1.md) | normative spec: bucket, tag, certificate, receipt, chain, verification |
| [`proto/branchpoint/v1/branchpoint.proto`](proto/branchpoint/v1/branchpoint.proto) | typed schema (buf module) |
| [`docs/mapping.md`](docs/mapping.md) | field map to `seam.event.v1` and the sealed Allocation trailer |
| [`contract/golden/branchpoint/`](contract/golden/branchpoint/) | golden vectors shared by every SDK and the collector |
| `reference/python`, `reference/ts` | independent reference implementations that regenerate the vectors byte-identically |
| [`contract/golden/branchpoint-sdk/`](contract/golden/branchpoint-sdk/) | golden vectors for the §8–§10 SDK wires |
| [`sdk/python`](sdk/python/README.md), [`sdk/ts`](sdk/ts/README.md) | the SDKs: client, uploader, OpenFeature provider, OTel hook |
| [`docs/sdk/overview.md`](docs/sdk/overview.md) | SDK architecture: evaluate path vs background worker, failure semantics, privacy |
| `tests/conformance/` | cross-SDK conformance: identical receipt bytes, uploads verify against the reference |

## Running an experiment

Branchpoint is an opt-in add-on on a tenant that already holds `runtime`.
Use Python 3.11+ and install the management CLI from your organization's authenticated Seam package index:

```sh
pip install seam-control-plane-client==0.4.0
# Supply your CP origin and tenant through CP_ORIGIN and TENANT first.
export SEAM_CP_URL="$CP_ORIGIN" SEAM_CP_TENANT="$TENANT"
export SEAM_CP_TOKEN_FILE="$HOME/.config/seam/human-token"
seam-cp branchpoint list
seam-cp branchpoint create --file experiment.json
seam-cp branchpoint status "$EXPERIMENT_ID"
seam-cp branchpoint update "$EXPERIMENT_ID" --expected-experiment-rev "$EXPERIMENT_REV" --file experiment-update.json
seam-cp branchpoint transition "$EXPERIMENT_ID" shadow --file shadow.json
seam-cp branchpoint transition "$EXPERIMENT_ID" live --expected-experiment-rev "$EXPERIMENT_REV" --file live.json
```

Configure exactly one credential source. For people, prefer `SEAM_CP_TOKEN_FILE` (or the global
`--token-file` flag before `branchpoint`): an existing owner-only regular file, mode 0600, with no symlink.
Other sources are `SEAM_CP_TOKEN`, machine credentials, or OAuth client credentials; tokens are never CLI arguments.
Machine credentials cannot create or approve experiments. `create` creates Draft; take `EXPERIMENT_ID` from
its response. Prepare JSON request files using the installed client's `seam_control_plane.types` request types;
`--file -` reads stdin. `shadow.json` and `live.json` carry the reviewed record's `content_sha256`.
Read the current revision with `status` before each update, Live or verdict submission and set `EXPERIMENT_REV`;
`expected_experiment_rev` may instead be in the JSON. The CLI never refreshes revisions or retries conflicts.

Live submits a pending approval. A second person must review `pending_live` from `status`, put its
`submission_id` and `content_sha256` in `approve-live.json`, and run this with **their own token file**:

```sh
seam-cp --token-file "$APPROVER_TOKEN_FILE" branchpoint transition "$EXPERIMENT_ID" approve-live --file approve-live.json
seam-cp branchpoint evidence "$EXPERIMENT_ID"
seam-cp branchpoint transition "$EXPERIMENT_ID" paused --file pause.json
```

The server enforces separation of duties. `pause.json` carries the record's `content_sha256` and optionally
`reason: "manual"`; resuming uses `live` and a second approval again. Concluded is set by the server's stop
rules/sweeper; there is no manual Concluded transition. Inspect `status`, then submit and approve a verdict:

```sh
seam-cp branchpoint transition "$EXPERIMENT_ID" verdict --expected-experiment-rev "$EXPERIMENT_REV" --file verdict.json
seam-cp --token-file "$APPROVER_TOKEN_FILE" branchpoint transition "$EXPERIMENT_ID" approve-verdict --file approve-verdict.json
```

`verdict.json` carries `verdict: "stop"`, `"promote"` (with `arm`), or `"extend"` (with `extend_max_duration_s`).
The second person reviews `pending_verdict` from `status` and supplies its `verdict_id` and `content_sha256`
in `approve-verdict.json`: stop/promote closes the experiment; extend returns it to Live.
To close Draft / server-assigned Shadow where permitted, use
`seam-cp branchpoint transition "$EXPERIMENT_ID" closed --file close.json` with the record's `content_sha256`.

Decision points use `--resource point` on `list`, `status`, `create`, and `update`:

```sh
seam-cp branchpoint create "$POINT_ID" --resource point --file point.json
seam-cp branchpoint update "$POINT_ID" --resource point --expected-point-rev "$POINT_REV" --file point-update.json
```

Point create sends revision 0; read `POINT_REV` with `status --resource point` before updating.
Exit codes: 0 success, 1 CP refusal (stderr JSON with `status`, plus `error` / `message` / `request_id` when present),
2 invalid configuration/input. SDK evaluation, receipts and the uploader are covered elsewhere in this README
and in [`sdk/python/README.md`](sdk/python/README.md) and [`sdk/ts/README.md`](sdk/ts/README.md).

## License

Apache-2.0.
