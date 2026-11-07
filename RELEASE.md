# Release verification

## Automated
Unit/integration tests cover scope comparisons, missing/denied observations,
empty responses, missing flags, cancellation, duplicate targets, malformed input,
corrupt history, replacement writes, report write failures, local Host/token/
Origin boundaries, unsupported methods, oversized requests, HTML escaping,
demo-to-live isolation, JSON export, Jira success/error responses, pending-create
reconciliation, and token non-persistence.

Run go test -race and go vet as well as regular tests. CI builds Windows/Linux
portable artifacts. Tags publish a release after test jobs pass. Version-tag
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
Full license inventory and signed installers are not implemented in this release.
No custom application license has been added without the repository owner's choice.
