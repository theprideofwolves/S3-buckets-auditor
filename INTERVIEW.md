# Interview walkthrough: AWS configuration review automation

## Explain it in 45 seconds
I built concurrent S3 policy-status and bucket Public Access Block checks with the AWS SDK credential chain, Markdown reporting, and separate error logging. I improved classification so incomplete inspection cannot look like a successful clean audit.

## Demonstrate it
1. Run `go run . -demo testdata/demo.json`. This is synthetic reporting data; no AWS calls or credentials are needed.
2. Open audit_results.md and error.log. Explain the enabled-control, public-policy, incomplete-block, and AccessDenied rows.
3. Run `go test ./...`: fake AWS responses exercise the real inspection/classification code.
4. For an authorized AWS environment, run `go run . -bucket YOUR_BUCKET`. No bucket settings are changed.
5. Explain that the JSON demo exercises reporting while API-fake tests exercise inspection; neither is evidence of a live AWS scan.

## Questions to be ready for
- Why a worker pool? Bound concurrent API calls rather than spawning a goroutine for every bucket.
- Public policy versus public access? A public policy is one configuration signal; account-level blocks can still prevent access.
- Missing block means public? No. It is a configuration concern requiring review.
- AccessDenied? Unknown/incomplete, recorded separately; never a clean result.
- Scope? Bucket policy status and bucket-level blocks only; no account controls, ACLs, access points, or object retrieval. Bucket-region handling depends on SDK configuration and is not an all-region coverage claim.

## Timeline and resume consistency
The submitted resume describes the original project's core behavior. These subsequent improvements strengthen the same project. If asked, distinguish the original implementation from later hardening. Practice the demo and inspect the source before describing decisions as your own. Do not claim production deployment, measured business impact, or autonomous agents from this repository.
