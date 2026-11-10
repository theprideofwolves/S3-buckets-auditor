# Validation map and metric methodology

The results cover implemented functionality using local fakes, synthetic data and a fresh headless Chromium profile. They are not a live cloud security assessment. Human/live checks remain explicit in [TESTING.md](TESTING.md).

## Functional coverage map

| Functionality | Automated evidence |
| --- | --- |
| First-run welcome, own-account choice, completion/restart | onboarding `TestFirstRunChoiceAndPersistence`, packaged `smoke.py` |
| Profile/region/target prefill; STS identity separate from S3 permissions/assessment | `TestAWSSetupChecksAreNonDestructiveAndPrefill`, `TestS3GuideCheckAndDemo`, `TestAWSIdentityAndPaginatedAssessment` |
| Optional Jira identity check is read-only; credentials not retained | onboarding `TestJiraReadOnlyAndNoCredentialRetention` |
| Four-bucket demo: concerns, checked controls, unknown | `TestLocalBoundariesAndDemo`, packaged and browser smoke |
| Fake STS identity, pagination and bucket reads; invalid identity blocked | `TestAWSIdentityAndPaginatedAssessment`, `TestAWSInvalidIdentityCannotAssess` |
| Denied, wrong-region, empty/malformed/missing-field responses stay unknown | `TestAWSUnusableBucketResponsesStayUnknown` (10 cases), `TestEmptyAndCancellation` |
| Three policy conditions × all 16 block combinations | `TestConfigurationTruthMatrix` (48 explicit cases); not live detection accuracy |
| Missing block configuration, missing flags, actual individual flag retention | `TestEveryBlockFlag`, `TestCollectorRetainsIndividualBlockFlags`, `TestMissingConfigurationPreservesFlagUncertainty` |
| Invalid/duplicate targets, explicit/discovery bounds, cancellation/worker clamping | `TestNamesAndKeyValidation`, `TestInvalidTargetsFailBeforeAWSCalls`, `TestTargetLimit`, `TestDiscoveryLimitBeforeBucketReads`, `TestEmptyAndCancellation` |
| Concern → denied → missing → verified clear; recurrence | `TestConcernSurvivesDeniedAndMissingThenVerified`, `TestRecurrenceStartsAnotherEpisode`, packaged/browser walkthrough |
| Independent partial-control clearing without a clean bucket verdict | `TestPartialSuccessOnlyClearsObservedControl` |
| Account/region and synthetic/live isolation; selected prefix excludes future evidence | `TestVerificationScopeAndAsOfIsolation`, `TestSelectedHistoryAndScopeIsolation` |
| Legacy details not invented; explicitly unknown controls cannot fall back to friendly summaries | `TestLegacyDetailsAreNotInvented` |
| Raw and verification exports, timestamps, restart, no replay mutation, current Jira links separated | `TestVerificationExportRestartAndBatchRollback`, `TestReplayDoesNotMutateObservationsAndLinksAreSeparate`, packaged smoke |
| Corrupt/ambiguous history fails visibly | `TestStorage`, `TestInvalidHistoryCannotBecomeEmptyWorkspace`, `TestMalformedHistoryIDsRejected` |
| Failed scan/batch saves retain earlier history and guide state | `TestScanSaveFailurePreservesHistoryAndGuideProgress`, `TestVerificationExportRestartAndBatchRollback` |
| Unknown/synthetic/unrecorded observations cannot deliver inappropriate Jira evidence | `TestUnknownAssessmentCannotSendJiraEvidence`, `TestUnrecordedControlsCannotSendJiraEvidence`, synthetic packaged smoke |
| Jira uncertain/rejected/lost creates, deduplication, intent-save failure, redirects | `TestJiraCreateDedupAndUncertain`, `TestJiraLostResponseAndRedirect`, `TestPersistenceFailureDoesNotSend` |
| Jira linking validates returned key; comments contain selected evidence | `TestVerifiedLinkAndCommentPath`, `TestJiraLinkRejectsUnusableEvidence`, `TestJiraEvidenceContainsSelectedObservation` |
| Local Host/token/Origin/method/body-size boundaries; escaping | `TestLocalBoundariesAndDemo`, `TestOversizedAndEscaping`, onboarding `TestRequestBoundaries` |
| CLI offline report, error exits, prior report retention, no GUI history | `cli_smoke.py`, `TestReportWriteFailure`; CLI limits still differ from UI |
| White/black themes, unchanged teal, navigation/restart cookie, downloads, narrow tables, no-JS fallback, visible focus | optional `browser_smoke.cjs` with no external requests allowed |

This map is a traceability aid, not a claim that all possible bugs, permissions or platform combinations are tested. See the report's actual command statuses and raw events.

## Reproduce metrics

```sh
python .github/scripts/measure.py --output dist/results
```

Uses Go 1.25.5+, Python 3 and a C compiler for the race detector. The script clears inherited AWS/Jira/app overrides, uses empty AWS configuration, disables metadata, and points the default endpoint at closed loopback. Fake SDK tests explicitly supply local endpoints and synthetic keys. Temporary history is removed after each run.

Add `--browser` with existing Playwright and Chromium configured as in [TESTING.md](TESTING.md). Browser automation is explicitly NOT RUN when omitted; it is not silently counted as passing. The local recorded Windows run includes it; CI records its own Linux/Windows evidence without claiming a human browser test.

Outputs: readable README, results.json, source manifest, JSON Go test events, coverage profile/detail, raw benchmark samples and command logs. Machine usernames, temporary/workspace paths and private launcher tokens are excluded/redacted. No provider credentials or user history are collected.

## Interpreting the numbers

- Top-level tests and named leaf cases are different views of the same run; never add them together to inflate test count.
- The 48-case matrix and 10 unusable-response cases are known test inputs, not field precision/recall or a probability of detecting all public buckets.
- Statement coverage measures executed Go statements, not security assurance. Packaged CLI/browser checks are separate from Go-test coverage.
- Synthetic collection uses two fake reads, each waiting for a 1 ms timer. No AWS SDK serialization/HTTP, actual S3 latency, discovery or throttling is measured.
- Replay workloads cycle concerns, denied reads, missing buckets and clearing for 100/1,000 distinct buckets across 10/25 scans. The report names each size.
- History-save timing includes JSON encoding, local write/sync/rename over an existing history. Initial setup and reload verification are outside the timer.
- Five one-iteration samples report min/median/max. Allocation bytes are not peak RAM; no p95, SLA, production capacity or real analyst time savings is claimed.
- The LF-normalized source manifest ties measurements to code/test/workflow/fixture contents. Documentation/results are excluded to avoid self-reference. GitHub Actions separately validates the pushed commit.

## What belongs on a résumé

Use only results present in the recorded report. An appropriate claim is “validated 48 policy/flag configurations and 10 injected API-failure cases using isolated tests.” If including timing, explicitly say “synthetic,” state the workload and keep the report link nearby.

Do not claim a real cloud rollout, reduced business risk, field accuracy, analyst time savings, adoption or Microsoft endorsement without separate evidence. The best interview story is why a failed scan cannot clear an old concern and how the tests establish that contract.
