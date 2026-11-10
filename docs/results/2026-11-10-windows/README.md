# Offline validation results

Measured 2026-11-10T16:00:19.926021+00:00 on Windows / AMD64.

**Synthetic and fake-service evidence only. No live AWS/Jira compatibility, production throughput, real-world accuracy or time savings are established.**

## Functional results

| Check | Result | Seconds |
| --- | --- | ---: |
| Go version | PASS | 0.07 |
| Race tests and coverage | PASS | 7.73 |
| Coverage detail | PASS | 0.94 |
| Go vet | PASS | 0.93 |
| Root build | PASS | 1.64 |
| Packaged UI workflow | PASS | 1.71 |
| CLI workflow | PASS | 1.51 |
| Offline Chromium workflow | PASS | 3.97 |
| Synthetic benchmarks | PASS | 7.73 |

- Top-level tests passed: **47**.
- Named leaf cases passed: **129** (includes subtests; do not add this to the top-level count).
- Failed named cases: **0**; skipped named cases: **0**.
- Policy/flag truth matrix: **48/48** cases passed.
- Unusable SDK-response cases: **10/10** stayed unknown in the tested cases.
- Go-test statement coverage: **79.29%** (735/927 statements).

Coverage comes from Go tests with the race detector and all local packages instrumented. Separate binary/browser checks are not included in that coverage percentage. Coverage is not a security score.

## Repeated synthetic measurements

Five one-iteration samples by default, without race/coverage instrumentation. Setup is excluded. Min/median/max are observations on this machine; no p95 or production latency is inferred.

| Benchmark | Median ms | Min–max ms | Allocated bytes/op | Allocations/op |
| --- | ---: | ---: | ---: | ---: |
| `BenchmarkHistorySave/scans=10/buckets=100` | 8.280 | 7.837–8.787 | 2,004,200 | 51 |
| `BenchmarkHistorySave/scans=10/buckets=1000` | 50.435 | 44.397–56.641 | 17,784,512 | 59 |
| `BenchmarkSyntheticCollection/buckets=100/workers=1` | 301.775 | 279.488–308.380 | 162,192 | 2,937 |
| `BenchmarkSyntheticCollection/buckets=100/workers=8` | 40.079 | 39.598–40.627 | 165,408 | 2,953 |
| `BenchmarkSyntheticCollection/buckets=1000/workers=8` | 379.347 | 372.470–381.162 | 1,698,640 | 29,073 |
| `BenchmarkVerificationReplay/scans=10/buckets=100` | 2.572 | 1.755–3.261 | 2,610,960 | 13,950 |
| `BenchmarkVerificationReplay/scans=10/buckets=1000` | 25.552 | 23.477–34.127 | 27,835,136 | 138,566 |
| `BenchmarkVerificationReplay/scans=25/buckets=1000` | 60.751 | 57.861–66.742 | 61,063,984 | 303,653 |

### Workloads and interpretation

- **SyntheticCollection:** two fake reads per bucket, each waiting for a 1 ms timer; includes scheduler/runtime overhead. No AWS SDK transport, network, STS or discovery. This measures collector orchestration under a controlled delay, not AWS scanning speed.
- **VerificationReplay:** histories with 10/25 scans and 100/1,000 distinct synthetic buckets; cycles concerns, partial visibility, missing buckets and clearing. Counts refer to distinct buckets, not new findings. Timelines are materialized in memory.
- **HistorySave:** atomic JSON encode/write/sync/rename over an existing history, then reload verification outside timing; local temporary filesystem. `history_bytes/op` is retained in raw samples.
- **B/op** is allocated heap bytes per operation, not peak RAM/RSS. Timer, CPU load, Go version, filesystem, GC and runner hardware affect results. The largest workload is a test size, not a supported production capacity claim.

## Reproduce and inspect

```sh
python .github/scripts/measure.py --output dist/results
```

Add `--browser` with the Playwright/browser environment described in [testing](../../TESTING.md). Browser results are explicitly NOT RUN when omitted.

Source fingerprint: `3eccd229ae519ea103070a80c9aa3a3cee226714788f9c7935d343250272e67d`.

[Machine-readable results](results.json) contain the LF-normalized source manifest, environment, command records and every benchmark sample. [Go test events](go-tests.jsonl), [coverage profile](coverage.out), [coverage detail](coverage.log) and [benchmark output](benchmarks.log) support the summary. Report/docs themselves are excluded from the source fingerprint to avoid a self-referential hash.

The fingerprint identifies the tested code/test/fixture/workflow contents even when measured before commit. A subsequent GitHub Actions run validates the pushed commit separately.

## Not established / still manual

- Live AWS credentials/SSO, permissions, throttling/region behavior and live Jira project compatibility.
- Human screen-reader/accessibility review, OS browser auto-opening, other browser engines and clean-machine launch.
- Real-user adoption, measured analyst time savings, field precision/recall, a full security assessment or effective anonymous access.
- Performance beyond the listed local synthetic workloads. See [manual acceptance](../../TESTING.md).
