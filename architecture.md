# Architecture

## Request path
Browser -> localhost Go HTTP server -> serialized application actions -> AWS
worker pool or Jira REST -> durable local JSON -> escaped HTML/JSON evidence.
No external frontend runtime, database service, or telemetry.

`main.go`: CLI and two-check AWS collector; `app.go`: local app, persistence,
comparison and Jira; `ui.go`: embedded escaped template; tests use fake AWS and
TLS Jira servers. AWS SDK STS establishes account identity before live UI scans.
History entries have random IDs, UTC timestamps, account/region, demo flag,
and observations. Jira mappings are keyed by origin/account/region/bucket.

## Concurrency and memory
Eight workers in UI scans, 1-64 in CLI. Names deduplicated; UI caps discovery
and explicit targets at 1000. Each bucket has a 30-second context. UI scans
have a three-minute deadline. App mutex serializes local operations and writes;
requests wait during scans. Results and history are in memory. History is not
bounded or indexed: very large histories require archiving while stopped.
No high-scale claim is made. Saved files are atomic replacements, not append logs.

## Trust boundaries
Loopback listener, random per-launch bearer URL, exact Host check, POST Origin
check, request limits, HTML escaping, CSP and no-store responses. No user roles:
the OS user is trusted. A local privileged process can read memory/history.
Do not expose this server to a network. Jira origin is user supplied; credentials
are sent only to it, redirects are disabled. Verify the origin before submission.
No raw object data is collected. Browser close does not end the app.

## Failure semantics
Unknown collection never becomes a pass. Missing scope never resolves findings.
Disk corruption stops load; failed saves roll back in-memory scan append.
Jira create intent must persist before send; ambiguous responses block repeats.
Crash after remote creation but before key save requires manual reconciliation.
Explicit link validates an existing issue; it does not prove the human chose the
correct issue. Clear observations append evidence, not automatic ticket closure.

## Boundaries
Two checks only, selected-region handling, no effective-exposure determination.
No continuous scanning, shared deployment, automatic retries of Jira creates,
provider credential storage, or immutable evidence claims.

## S3 onboarding and saved evidence

initGuide declares only AWS profile, region and optional targets. Setup checks
STS account identity through checkAWSIdentity or Jira identity through the
read-only adapter. No folder picker, source upload or sample-download route is
needed. Setup checks never collect bucket observations or change history.

Non-secret inputs prefill the assessment form within the current session. Jira
credentials are never retained. After collection and durable save, the guide
records completion; a saved scan can contain unknown bucket checks. Collection
or persistence failure does not mark completion. onboarding.json is independent
of history.json, so restarting the guide cannot remove saved scans or mappings.

The packaged smoke test runs the binary, checks all four synthetic observations,
blocks demo ticket creation, exports evidence, restarts and verifies immutable
observation fields, rejects a missing-region scan, and retains earlier history
after a second demo. HTTP smoke tests do not verify an interactive OS browser.

The CLI shares inspect/audit/reporting with the UI but writes Markdown/error.log
without GUI history or Jira. Its discovery/list input is not capped at 1000 and
it lacks the UI's overall deadline; avoid interpreting the UI bounds as CLI bounds.
