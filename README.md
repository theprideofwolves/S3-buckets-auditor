# S3 Auditor

A focused, read-only AWS configuration reviewer with a local browser UI,
scan history, reassessment comparison, JSON evidence export, and explicit
Jira handoff. No Go installation, database server, or API key is needed
for the bundled offline demo.

## Download and launch
Download the ZIP for your OS from GitHub Releases, extract it, and open
`s3-auditor.exe` on Windows. On Linux run `./s3-auditor` (a desktop browser
opener is optional). A console stays open and the browser opens automatically.
Press **Ctrl+C in that console** to stop. Closing the browser does not stop it.
The program is unsigned; your OS may display a warning.

Run **offline synthetic demo** first. Synthetic results cannot create real
Jira issues. Nothing is uploaded automatically. For development: `go run .`.

## AWS assessment
Configure an authorized AWS profile using your normal AWS/SSO workflow,
then choose its name, the bucket region, and optionally bucket names in the UI.
Blank targets use paginated discovery, capped at 1000 buckets. Wrong-region
responses and denied permissions remain unknown; select the right region
and rescan. The app never changes AWS resources.

Required actions: `sts:GetCallerIdentity`, `s3:GetBucketPolicyStatus`,
`s3:GetBucketPublicAccessBlock`; add `s3:ListAllMyBuckets` for discovery.
Restrict bucket permissions to authorized bucket ARNs. See `permissions.json`.
The SDK handles transient AWS retries within the scan timeout.

Scope is **bucket policy public status and bucket Public Access Block** only.
No account-level controls, ACLs, access points, object data, anonymous probes,
full CIS assessment, or claim of effective public access. The table shows
per-check unknown states; errors take precedence over a clean classification.

## Reassessment
History is grouped by account/region; synthetic data is separate.
Only a successful observation can verify a previously flagged bucket clear
for these checks. Missing buckets are not assessed, not resolved. Historical
scans remain selectable and exports retain their observation timestamp.
Comparisons reflect the previous saved scan in the same scope, not a complete
asset-inventory lifecycle or independently authenticated audit ledger.

## Jira Cloud
Select a live scan and bucket. Supply Jira HTTPS origin, email, API token,
project key, and issue type (default Task). Review the on-screen disclosure.
A supported issue create requires project Browse/Create permissions; appending
verification requires comment permissions. Custom required fields are not
supported in this release: configure a compatible issue type or link an
existing issue. The link action validates access to the key.

The first create stores a durable intent BEFORE contacting Jira. A lost response
leaves a pending/uncertain delivery; repeat creates are blocked. Search Jira for
the correlation string in the issue description and explicitly link its key.
Existing links receive evidence comments rather than another issue. Comments
can repeat if retried after a lost response: inspect Jira first. Ticket status
is never changed automatically. API tokens are not saved, logged, or returned
to the HTML. Connection failure details exclude Jira response bodies.

Local state is single-writer locked. Do not run two instances against the same
data directory. After a crash, confirm no instance is running before removing
`application.lock`. After losing local history, link existing Jira issues before
creating replacements. Different Jira origins and AWS account/regions have
separate mappings. An origin change or state loss is NOT cross-machine dedup.

## Data and backups
Default location: OS user configuration directory / `S3Auditor`.
Override using `S3_AUDITOR_DATA_DIR`. History contains account/bucket names and
API diagnostics: treat it as confidential. It contains no Jira tokens. Stop the
app before backing up `history.json`; restore it into the same directory while
stopped. Upgrades replace the executable, not the data. This release has no
schema changes requiring migration from an earlier GUI release.
Uninstall by deleting the extracted application. User history remains until
you explicitly delete the data directory. Corrupt history fails visibly rather
than being overwritten. Writes use a same-directory temporary file and rename.
Local file permissions inherit OS user-directory protections; no encryption at rest.

## CLI compatibility
No arguments now launches the UI. Explicit flags retain CLI operation:
```
s3-auditor -bucket example-bucket
s3-auditor -csv buckets.txt -workers 8
s3-auditor -workers 8
s3-auditor -demo testdata/demo.json
```
`-csv` is a legacy flag: one name per line, not CSV columns. CLI writes
`audit_results.md` and appends `error.log` in the current working directory.
CLI does not persist UI history or create Jira issues. Exit 1 means execution
failure; configuration findings alone do not produce a failing exit code.

## Testing and release
```
go test -count=1 ./...
go test -race ./...
go vet ./...
go build -trimpath -o s3-auditor.exe .
```
CI checks Windows and Linux; tag builds produce portable ZIPs, checksums,
and embedded dependency metadata. See architecture.md, interviewprep.md,
explaining-each-decision-taken-over-others.md and RELEASE.md.
Live AWS/Jira behavior requires an authorized environment and is not proven
by mock tests. No ServiceNow, Slack, automatic remediation, or background sync.
