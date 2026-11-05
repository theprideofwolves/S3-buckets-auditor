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
Review `audit_results.md` together with `error.log`. The current report labels a bucket `Public / High` when its policy is public or a bucket-level block setting is missing/disabled. A Public Access Block API error can also produce that label.

These labels indicate configuration concerns, not verified anonymous object access. Account-level controls, ACLs, access points, and complete effective permissions are outside these checks. A `Private / Low` row alone is not proof of isolation, particularly if a policy check failed. API errors require follow-up.

## Resume bullets
- Built concurrent S3 bucket policy and Public Access Block checks in Go using AWS SDK v2 and the default credential chain to flag potential public-access configuration risks.
- Added single-bucket and bucket-list targeting, timestamped Markdown reports, and separate API error logging to support security review.
