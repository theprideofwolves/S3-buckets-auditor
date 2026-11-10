# S3 Auditor v1.3.0: release preparation

Source includes the verification workflow and recorded offline results. Portable release publication is a separate step; a passing source build is not a new published ZIP.

## Automated
Unit/integration tests cover scope comparisons, missing/denied observations,
empty responses, missing flags, cancellation, duplicate targets, malformed input,
corrupt history, replacement writes, report write failures, local Host/token/
Origin boundaries, unsupported methods, oversized requests, HTML escaping,
demo-to-live isolation, JSON export, Jira success/error responses, pending-create
reconciliation, and token non-persistence.

Run go test -race and go vet as well as regular tests. CI builds Windows/Linux
portable artifacts. Version tags or explicit [release] commits on main publish
the VERSION-selected release after test jobs pass. Version-tag
publishing does not independently prove live AWS/Jira compatibility.

## Manual acceptance still required
- Real AWS SSO/profile, discovery, region mismatch, throttling and permissions.
- Real Jira project with issue types/custom fields and required permissions.
- Human browser accessibility and clean machine double-click on each OS.
- Upgrade/backup restore with representative user history.
- Representative startup, peak memory and large-history measurement.

No claim that all conceivable edge cases are covered. Mocks establish defined
contracts, not production service behavior. Do not market as enterprise-wide,
a full CIS scanner, or proof of effective public exposure.

## Release packaging
Portable ZIP includes executable, README, RELEASE, architecture/interview/decision
docs and dependency build metadata. SHA256SUMS covers downloadable assets.
The CLI reporting fixture is included at testdata/demo.json.
Full license inventory and signed installers are not implemented in this release.
No custom application license has been added without the repository owner's choice.

## v1.2.1 scope cleanup and workflow checks

Removed unrelated project references and test branches, unused folder selection,
sample download and multipart setup code. Kept AWS/Jira identity checks and
profile/region/target prefill. Clarified UI versus CLI bounds and STS identity
permissions. The Go module now uses this repository's canonical import path.
Default data directory, S3_AUDITOR_* overrides and saved history format remain.

The S3-only packaged smoke test covers welcome/setup, the four synthetic buckets,
unknown evidence, blocked demo handoff, export, guide restart, remembered
completion, process restart, invalid scan input and preserving earlier scans.
Unit tests cover read-only setup contracts, input preservation, credential
non-retention and progress-save failures. Live AWS/Jira credentials and project
permissions still require authorized validation; the demo makes no AWS calls.
SDK workflow tests use a local fake STS/S3 service with synthetic credentials to
check identity-only setup, paginated discovery, bucket reads and denied checks.
Additional tests cover unknown observations blocking Jira creates/comments and
failed history saves retaining earlier scans without marking guide completion.


## v1.3.0 verification workflow

Added nullable control observations, last-successful comparisons, concern episodes
through denied/missing scans, recurrence, and an as-of-selected verification record.
The UI and export share pure replay; the original raw scan export remains available.
Older history loads conservatively without inventing individual disabled flags.
Current Jira mappings are explicitly distinguished from historical observations.

The separate synthetic four-stage walkthrough saves atomically and cannot contact
AWS/Jira. Race/unit, SDK, packaged workflow and optional browser checks cover
replay, partial success, scope isolation, persistence and delivery guards. These
fake-service checks do not establish live compatibility. Human acceptance remains
in docs/TESTING.md. Earlier releases may not contain this new workflow.
