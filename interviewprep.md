# Interview guide

## Your 30-second explanation

“I built a read-only Go S3 configuration auditor with remediation verification. It checks bucket-policy public status and bucket Public Access Block. Its concern history survives denied or missing inspections, and successful observations show exactly which controls changed and which concerns were cleared. A local UI exports the evidence; Jira handoff is explicit.”

Use that wording only for code you have reviewed and can explain. This is an implemented workflow, not an industry-first research claim or a production deployment claim.

## A three-minute offline demonstration

1. Launch the app and run **Try the verification walkthrough**. All four scans are synthetic; no cloud resources or tickets are created.
2. Select **1 - Concern observed** in history. Show public policy and disabled BlockPublicPolicy; there are two aggregate concerns.
3. Select **2 - Inspection denied**, then **3 - Bucket not assessed**. Expand remediation verification: the concerns are still open and the last successful observation remains stage 1.
4. Select **4 - Controls verified clear**. Show public → not public and disabled → enabled, compared with stage 1. Expand a control to show the denied/missing events between observation and verification.
5. Export the verification record. Explain the selected scan, nullable values, episodes, limitations and separately labeled current Jira mappings.

The original **Try the guided demo** is a separate four-bucket overview. Do not conflate either demo with a live assessment.

## Follow the code

- `launch` creates the loopback server and single-writer lock, then loads history.
- `handler` enforces local request guards and selects the saved scan.
- `action` validates input, calls `collect` or an offline demo, appends observations and saves atomically. It rolls back on failure.
- `collect` uses STS for caller account identity, paginated discovery if needed, and `audit`'s bounded workers.
- `inspect` calls only GetBucketPolicyStatus and GetPublicAccessBlock. Nullable observations preserve missing/denied information.
- `verification` replays matching scope and Demo class through selection. `ControlEvidence.observe` updates last-known evidence and concern episodes.
- The workspace and `GET /verification` use that same replay. The CLI shares collection but does not store/replay GUI history.
- Jira persists intent, sends the reviewed request and stores the returned key. Ambiguous creates require reconciliation.

## Questions you should be able to answer

| Question | Explain |
| --- | --- |
| Why pointers to booleans? | false is a real observation; nil means no successful observation. Default false must never erase uncertainty. |
| Why retain history across denied scans? | Loss of visibility is not evidence that a known configuration concern was fixed. |
| Why separate aggregate checks from flags? | There are two checks; four flags explain the block result. Counting the aggregate plus every disabled flag as separate bucket findings would inflate counts. |
| Can one control clear while the bucket is unknown? | Yes. A successful policy read can clear its episode while the block read fails; overall assessment and Jira evidence delivery remain incomplete. |
| What if a concern returns? | A successful clear closes an episode; a later concern starts another episode. |
| Why replay instead of storing another ledger? | One source of truth, deterministic historical views, no second transaction to keep consistent. Tradeoff: growing CPU/memory cost. |
| What does “as of” mean? | Saved append order through selection, matching scope and Demo. Later observations are excluded. It is not wall-clock sorting or proof of continuous exposure. |
| What about old history? | Preserve it. Infer only logically established summaries; an old incomplete block summary does not reveal the disabled flag. |
| What do the timestamps prove? | Scan observation times, not exact configuration-change times. Collection spans time; episode ages are observational. |
| Why is public policy plus enabled blocking possible? | The policy and blocking settings describe different controls; neither alone proves effective anonymous access. Account-level and other access paths are out of scope. |
| Is STS identity bucket ownership? | No. It identifies the caller account, not S3 permissions or ownership of every named bucket. |
| Why no automatic Jira closure? | These checks provide limited configuration evidence; analyst review and ticket workflow remain outside automatic actions. |
| Is Jira delivery exactly once? | No. Durable intent blocks blind repeat creates, but uncertain results need reconciliation; evidence comments can repeat. |
| Are exports tamper-proof? | No. The local user can edit history. There is no authenticated audit ledger. |
| Why not replace Prowler/Access Analyzer? | This is a focused local evidence/reassessment workflow, not a broader or equivalent cloud exposure analyzer. |

## Tests and failure cases to explain

Start with `TestConcernSurvivesDeniedAndMissingThenVerified`, `TestPartialSuccessOnlyClearsObservedControl`, `TestLegacyDetailsAreNotInvented` and `TestVerificationExportRestartAndBatchRollback` in `verification_test.go`.

Then explain the fake SDK tests, all 16 block-flag combinations, unknown Jira guards, uncertain creates and failed-save rollback. Run `python .github/scripts/check.py`; distinguish those results from explicitly authorized live validation. Optional browser tests cover the available Chromium engine, not all browsers or accessibility.

Earlier reproduced bugs included malformed STS identity, invalid history opening as an empty workspace and Jira linking accepting malformed success bodies. Explain the failed cases and narrow fixes, not just that tests passed.

## Honest résumé wording

- Built a Go S3 auditor that retains unresolved configuration concerns across denied and missing assessments, compares individual Public Access Block flags, and exports selected-scan remediation-verification evidence.
- Tested scoped replay, partial-read failures, persistence rollback and uncertain Jira delivery using race tests, fake AWS/Jira services and offline browser automation.

Do not invent users, time savings, production scale, live compatibility or personal review that has not happened. Disclose AI assistance appropriately and distinguish generated code from the design/testing you understand.

## Before an interview

Explain each nullable field without looking it up; trace one episode from first concern to verified clear; predict a partial-failure result; identify where replay stops; explain the complexity and trust boundary. Finish the short manual checklist. Those explanations matter more than adding features.


## Explain the recorded metrics

The [Windows evidence report](docs/results/2026-11-10-windows/README.md) records
47 top-level tests and 129 named leaf cases, 79.29% Go statement coverage,
48 policy/flag combinations and 10 unusable-response cases. Do not add top-level
and leaf counts together. Statement coverage is not branch coverage or a
security score; packaged/browser execution is separate from that percentage.

There are five samples per synthetic timing workload. Quote the workload,
median and observed range, not an invented p95 or SLA. Collection uses two fake
1 ms timers per bucket; replay uses saved synthetic histories; persistence
replaces existing local JSON history. Allocated bytes/op are not peak RAM.
These measurements do not establish AWS throughput or analyst time savings.

To reproduce: `python .github/scripts/measure.py --output dist/results`.
Source fingerprints identify tested contents, and GitHub Actions separately
checks the published commit. For a resume, emphasize the verified uncertainty
semantics and reproducible evidence; use timing only with the synthetic qualifier.
