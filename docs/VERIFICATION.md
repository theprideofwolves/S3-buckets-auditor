# Verification workflow

The differentiator is a small, explicit evidence model for the existing two S3 checks—not a new exposure-analysis engine or an industry-first claim.

## Example: concern through an inspection gap

**Try the verification walkthrough** saves four synthetic scans in its own scope. It makes no AWS or Jira calls. Select each labeled stage in history.

| Stage | Policy status | Public Access Block | Interpretation |
| --- | --- | --- | --- |
| 1. Concern observed | Public | BlockPublicPolicy disabled; other flags enabled | Two aggregate concerns open |
| 2. Inspection denied | Unknown | Unknown | Both concerns remain unresolved; last known evidence is stage 1 |
| 3. Bucket not assessed | Missing | Missing | Not assessed, not resolved; absence does not establish deletion |
| 4. Controls verified clear | Not public | All four flags enabled | Successful observations close the earlier episodes |

At stage 4, policy changes from **public → not public**, and BlockPublicPolicy changes from **disabled → enabled**. Both compare with stage 1, not with the denied/missing stages. Expanding a control shows every observation and its scan ID. The successful stage closes episodes without changing Jira ticket status.

A public-policy observation can coexist with enabled blocking controls. This is not contradictory: policy status and blocking configuration answer different questions. Their interaction alone does not establish effective anonymous access. See [AWS Public Access Block semantics](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html).

## Evidence rules

- `nil`/JSON `null` is unobserved; `false` is an observed value. They are not interchangeable.
- Policy public=true is a concern. Overall block complete=false is a concern. Individual disabled flags explain that block concern; the unresolved count does not double-count them.
- A successful concern observation starts an episode, or updates its last-observed point while it is still open.
- A successful clear observation for that control closes its episode. Another concern after clearing starts a new episode.
- Unknown or missing observations never close an episode or replace the last known value. A successful read can clear one control while another read remains unknown; the bucket-level assessment still stays incomplete.
- NoSuchBucketPolicy is a known absence of policy, not a failed read. Missing block configuration is a known incomplete configuration. It does not invent individual flag values.
- If block configuration exists but a flag is missing from a response, that flag remains unknown. Successfully returned flags are retained; the inspection error prevents a clean bucket assessment or Jira evidence delivery.

## Replay and history

`verification.go` rebuilds the evidence from saved observations. There is no second mutable ledger to get out of sync with history.

Replay follows **saved append order**, stops at the selected scan and matches **both scope and Demo flag**. Later scans cannot rewrite an older view. Buckets first encountered later do not appear in an earlier record. Once a bucket has appeared, omissions from subsequent scans in that scope are recorded as not assessed. This is scoped assessment history, not a complete asset inventory.

Timestamps are scan observation timestamps, not the exact moment a setting changed. Collection can span time. Episode age is measured at the selected scan, or at verification for a closed episode; it is an observed duration, not continuous proof of exposure. Negative duration from clock skew is clamped to zero. Equal timestamps are permitted; append order still determines replay.

### Older history

New observations add nullable `Controls` to `BucketReport`; old scans remain unchanged and readable. Existing explicit summary states can support the aggregate checks. An old all-flags-enabled summary supports four true flags; an old incomplete summary cannot identify which flag was false. Individual details remain unknown rather than being fabricated. No conversion writes occur merely by viewing or exporting.

## Export contract

- **Download JSON evidence** (`GET /export?id=...`): the original selected scan, including nullable control observations and existing report fields.
- **Download verification record** (`GET /verification?id=...`): version 1, selected `Scan`, ordered `Buckets`, per-control `Timeline`, `LastKnown`, `ComparedWith`, `Change`, concern `Episodes`, and explicit `Limitations`.
- `CurrentTicketLinks` contains only current local Jira mappings for matching buckets/scope. It is deliberately separate: Jira links have no historical revision log, so this is not Jira status as of the scan. Linking an issue later can change this field in an older export; observation history remains unchanged.

Both endpoints require the current private launcher token and exact local Host, and are GET-only. Exports contain account/bucket identifiers and may include selected-scan diagnostics. Tokens are not included. Local files are editable and are not an authenticated or tamper-proof audit ledger.

## Jira and CLI boundaries

A complete selected bucket observation is required to create or comment; unknown or missing results cannot provide verification evidence. The comment includes selected-scan context and derived changes/episode references, without raw API error messages. Synthetic scans cannot create, comment or link real issues. Existing delivery-intent and uncertain-outcome protections remain.

CLI reports share the collector and now retain flag details internally, but CLI does not save UI history, replay concern episodes or create Jira issues. Do not claim CLI provides the GUI verification workflow.

## Evidence for the implementation

- `verification_test.go`: gaps, recurrence, partial success, absent configuration, legacy detail, scope/as-of isolation, restart/export equality and failed batch rollback.
- `aws_workflow_test.go`, `app_test.go`, `main_test.go`, `edge_cases_test.go`: fake SDK, API failures, all flag combinations, persistence, request guards and mock Jira delivery.
- `.github/scripts/smoke.py`: packaged first run and the entire four-stage verification walkthrough, including restart and exports.
- `.github/scripts/browser_smoke.cjs`: optional real-browser offline checks for themes, navigation, downloads and verification details.

Mocks establish these contracts, not live compatibility. Human acceptance and explicitly authorized live integration remain separate.

Recorded metrics and feature-to-test traceability are in [VALIDATION.md](VALIDATION.md) and [results](results/README.md). They are offline evidence, not proof of live compatibility.
