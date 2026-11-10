# Architecture

## Data flow

Local browser → loopback Go HTTP server → serialized application action → offline fixture or STS identity plus two S3 reads → atomic JSON history → selected-scan replay → escaped HTML / JSON evidence. Jira requests occur only through explicit handoff actions.

| File | Responsibility |
| --- | --- |
| `main.go` | CLI, bounded worker pool, policy status and bucket Public Access Block reads |
| `app.go` | Local server, saved scans, two synthetic demos, persistence and Jira delivery |
| `verification.go` | Nullable controls, scoped replay, control changes, concern episodes and verification export |
| `ui.go` | Server-rendered workspace and expandable observation history |
| `internal/onboarding` | Welcome, non-destructive identity checks and guide progress |
| `internal/webui` | Shared white/teal and black/teal themes; fixed CSP-hashed theme script |

## Observation and replay model

`BucketReport.Controls` preserves policy public status, configuration presence and four nullable flags. `nil` is unknown, not false. The overall block check is derived from configuration presence and flag observations; individual flag detail does not add new API scope.

Saved scans are the source of truth. `verification` replays only the selected scope and synthetic/live class, in saved order, through the selected scan. Each control retains a last successful observation, comparison baseline, observation timeline and concern episodes. Denied/missing observations retain unresolved episodes; observed clearing closes only that control. Recurrence opens another episode. The UI and verification export use the same function.

The original scan export remains separate. Verification records include explicit limitations and current Jira mappings labeled as current—not historical ticket state. See [the full contract](docs/VERIFICATION.md) and `verification_test.go`.

Older scans need no destructive migration. Summary states support only what they actually establish; unknown historical flag details are never invented. The derived ledger is not persisted separately, so failed history writes cannot leave a stale second database.

## Concurrency, persistence and scale

UI scans use eight workers, up to 1,000 buckets, 30 seconds per bucket and a three-minute overall deadline. CLI workers are 1–64; CLI has no GUI history, overall UI deadline or 1,000-bucket bound.

The app mutex serializes actions. History writes use a same-directory temporary file, sync and replacement; failed appends roll back in memory. The four-stage demo is one atomic batch. A single-writer lock prevents normal concurrent instances against the same data directory.

History and derived evidence are in memory and unbounded. Replay costs O(S × B × C) in the worst case, where S is same-scope scans through selection, B is buckets seen and C is six derived control views (two aggregate checks plus four flags). Timelines also retain missing observations. Whole-history rewrites and replay cost are accepted for a local student tool; representative large-history measurements remain unperformed. There is no enterprise-scale claim.

## Trust boundaries

Loopback binding, random per-launch bearer URL, exact Host, POST Origin checks, request limits, escaped templates, CSP and no-store responses. The OS user is trusted. Do not expose the server on a network. A privileged local process can read history/memory; history is editable and not an authenticated ledger.

No remote UI assets or frontend build. A fixed hash permits only the theme script; theme preference is a non-secret browser cookie. Forms remain usable without JavaScript. Browser closure does not stop the server.

STS setup confirms caller identity, not S3 permissions or bucket ownership. Jira setup checks identity, not project permissions. Neither setup check collects observations or completes an assessment.

## Jira failure semantics

The app saves create intent before sending. Lost/ambiguous responses block blind repeat creates. Reconciliation explicitly links a verified issue key. Existing links receive evidence comments, never automatic status changes. Comments are not exactly-once after lost responses. Failed intent persistence sends nothing. Unknown/synthetic observations cannot send inappropriate evidence. Tokens are request-only and not persisted.

The selected-scan verification summary is included in reviewed handoff. Current issue mappings are separated from observation history because historical Jira mapping revisions are not stored.

## Explicit limits

Two S3 configuration checks only. No ACL/account/access-point/object collection, anonymous access tests, automatic remediation, continuous monitoring, shared deployment or claim of effective exposure. API mocks and offline browser checks do not establish live AWS/Jira behavior. User-owned manual acceptance remains in [docs/TESTING.md](docs/TESTING.md).
