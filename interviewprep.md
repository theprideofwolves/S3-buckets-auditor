# Interview study guide

## 30 seconds
I improved a Go S3 reviewer into a local evidence workflow. It checks policy
public status and bucket Public Access Block, records scan history, compares
reassessments, and explicitly hands selected findings to Jira. API failures stay
unknown; ticket closure is independent from verified configuration evidence.

## Two minutes
Trace `launch` -> `handler` -> `action` -> `collect` -> STS identity -> AWS
worker pool -> `inspect` -> durable history. Then `compare` uses the previous
matching scope. Jira first saves intent, sends a create, and saves the returned
key. Lost replies trigger manual reconciliation, not duplicate creation.

## Five minutes
Demonstrate offline data, unknown states, an evidence export, restart persistence,
then explain an authorized live scan and the Jira disclosure. Explain that tests
use fake AWS/TLS Jira and cannot establish live permission compatibility.

## Concepts and questions
- Why not call this a public exposure scanner? Account controls, ACLs, access
points and anonymous object access are not evaluated.
- What is evidence vs conclusion? Timestamped API observations support only
specific checks; they do not certify the bucket or company.
- Why does bool false not mean pass? If a call failed, its state is unknown.
- What is backpressure? Workers consume bounded jobs rather than creating a
goroutine per bucket. Results are retained for deterministic sorting.
- Why random launch token? Prevent ordinary unrelated local web pages from
invoking authenticated local actions. Not protection against a privileged OS user.
- Why not retry Jira POST automatically? The remote write could have succeeded
before its response was lost. Local and remote transactions are not atomic.
- Can SHA/file hashes guarantee integrity? Not implemented as an integrity ledger;
the local OS user can edit history. Do not claim tamper-proof audit evidence.
- Why JSON over SQLite? Simple local distribution; whole-file rewrites and memory
are explicit limitations. Test disk and history scale before broadening deployment.
- What does remediation verification mean? A successful fresh result for these
checks, with account/region and timestamp. Not proof of all access paths.

## Exercises
1. Trace one public result through inspect, Status, compare and export.
2. Change a fake block response to nil: predict unknown, then run the test.
3. Simulate Jira 429: inspect intent state and show repeat-create protection.
4. Remove a bucket from the next scan: explain not-assessed versus resolved.
5. Explain why losing history invalidates cross-run duplicate prevention.
6. Read each test and describe what it does NOT establish.

## Honest resume wording
Built a Go S3 configuration evidence tool with bounded workers, local scan
history, reassessment comparison, and reviewer-triggered Jira handoff; tested
incomplete scans, local request boundaries, and uncertain remote-write outcomes.
Use live-deployment claims only after documented actual validation.

## Onboarding design and study notes

The internal/onboarding package owns the welcome/setup routes, escaped progress
panel, declared non-secret session fields, and a versioned completion preference.
Core handlers explicitly call Complete only after a successful domain operation.
A failing policy evaluation is still a successful task; a partial LogFlow report
is not marked complete. Guide status is not a security/compliance conclusion.

GET/sample/setup routes do not run scans or create tickets. POST setup checks
use bounded read-only requests; Jira identity is not project authorization. Native
folder selection is explicit, bounded and has a manual fallback. Preflight checks
never store tokens, and Jira checks preserve previously selected local fields.

Why not a JS tour library? Server-rendered forms and a small guide keep packaging
light, work offline and are keyboard accessible. Each independent repository
contains its own internal copy and tests; no cross-project service is required.
That trades centralized updates for simpler standalone distribution.

Practice: explain a fresh launch, a failed check, a successful demo, persistence
after restart, and why restarting the guide cannot delete assessment data. Read
onboarding_test.go and the packaged smoke script to distinguish a connection
check from an end-to-end live integration test.
