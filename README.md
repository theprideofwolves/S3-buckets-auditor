# S3 Bucket Auditor
### Concurrent public-access configuration checks in Go
An AWS security automation tool that inspects bucket policy status and bucket-level Public Access Block settings, then produces a timestamped Markdown report for review.

## What I built
- Concurrent bucket checks using goroutines and the AWS SDK for Go v2.
- AWS SDK default credential-chain integration.
- Single-bucket, bucket-list, and account-listing targeting.
- Markdown results in `audit_results.md` and separate API error details in `error.log`.

## Checks performed
| Check | Implementation |
| --- | --- |
| Public bucket policy | `GetBucketPolicyStatus` |
| Bucket-level Public Access Block | `GetPublicAccessBlock` and its four block settings |
| Account bucket discovery | `ListBuckets` when no target flag is supplied |

## Run
Requires Go 1.25.5 or newer, matching `go.mod`, and an AWS identity configured through the SDK default credential chain.

```bash
git clone https://github.com/theprideofwolves/S3-buckets-auditor.git
cd S3-buckets-auditor
go run . -bucket example-bucket
```

Other targeting options:
```bash
go run . -csv buckets.txt
go run .
```

Despite the `-csv` flag name, the implementation expects one bucket name per line, without a header or comma-separated columns. Without flags, it checks buckets returned by `ListBuckets`. Configure the AWS region and credentials for your environment.

The identity needs permission for the selected bucket checks; account discovery also requires permission to list buckets. No bucket configuration changes are performed.

## Read the report
Review `audit_results.md` with `error.log`. Results distinguish public-policy findings, incomplete block configuration, enabled checked controls, and unknown/incomplete inspection. API failures never produce a clean verdict. A public policy or missing block is not proof of effective anonymous access: account controls, ACLs, access points, and object access remain outside scope.

Concurrency defaults to eight workers (`-workers 1..64`), each bucket inspection has a 30-second timeout, and results are sorted by bucket name. Account discovery uses paginated ListBuckets. For a credential-free synthetic reporting demonstration, run `go run . -demo testdata/demo.json`.

## Resume bullets
- Built concurrent S3 bucket policy and Public Access Block checks in Go using AWS SDK v2 and the default credential chain to flag potential public-access configuration risks.
- Added single-bucket and bucket-list targeting, timestamped Markdown reports, and separate API error logging to support security review.


## Interview demonstration and verification
See [INTERVIEW.md](INTERVIEW.md) for a walkthrough, expected results, design decisions, and limitations. Run `go test ./...`, `go vet ./...`, and `go build ./...`. GitHub Actions also runs the race detector on Linux.
