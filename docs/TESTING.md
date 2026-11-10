# Manual acceptance

Automated checks use fake services and synthetic credentials. No live AWS/Jira compatibility is claimed. The following is the remaining human acceptance checklist.

## Quick offline pass (about five minutes)

1. Open `dist/s3-auditor.exe` (Windows), or build and launch for your OS. Confirm the welcome screen opens. Toggle light/dark; white becomes actual black and teal remains teal.
2. Choose **Try the guided demo**. Confirm four buckets: two concerns, one checked-controls result and one unknown policy inspection. Download raw JSON; no Jira form should appear for synthetic data.
3. Click **Try the verification walkthrough**. Select the four labeled stages in history. Concern → denied → missing must retain two unresolved aggregate checks. Stage 4 must show verified clear. Expand remediation verification and a control's observation history.
4. At stage 4, verify public → not public and BlockPublicPolicy disabled → enabled. Both baselines should be stage 1, not the gap stages. Download the verification record and check the four-event timeline and final VerifiedClear reference. Select stage 2 and export again: its episode must still be unresolved, without future evidence.
5. Restart the guide. Open **Use my data**, leave region blank and check identity. Expect a region message without a scan. Do not enter real credentials during this offline pass.
6. Check Tab/Shift+Tab focus, labels and table scrolling at a narrow width and 200% zoom in both themes. Expand/collapse the verification timelines.
7. Stop with Ctrl+C, relaunch and confirm history, stage-specific exports and theme persist. Closing only the browser leaves the server running.

## Optional live integration — separate stage

Only in an explicitly authorized existing environment; do not create or change AWS resources for testing.

- AWS: existing profile/SSO identity, named buckets, discovery permission, denied reads and a bucket in another region. Verify account/region scope and unknown states.
- Jira: authorized test project/issue type, identity check, reviewed finding creation, link and evidence comment. Check required fields/permissions. Inspect Jira before retrying uncertain writes.
- Operations: backup/restore while stopped, clean-machine launch and representative large-history behavior.

## Automated coverage

`python .github/scripts/check.py` runs race tests, vet, root build, packaged HTTP smoke and CLI checks. AWS environment variables are removed, empty shared configuration files are used, metadata is disabled, and the default endpoint is closed loopback. SDK tests replace it with local fake services and synthetic credentials.

Tests cover concern episodes through denied/missing scans, partial-control clearing, recurrence, legacy details, historical export/restart equality, failed batch rollback, denied/wrong-region/malformed/empty observations, all 16 Public Access Block combinations, cancellation, deduplication and limits, reassessment/scope separation, saved/exported observation timestamps, save failures, request boundaries, and uncertain Jira creates/linking/comments. Tests cannot cover every possible service or operating-system failure.

### Optional browser automation

With Playwright and its Chromium browser available to Node.js:

```sh
node .github/scripts/browser_smoke.cjs dist/s3-auditor.exe
```

Use the executable path for your OS. `S3_AUDITOR_BROWSER` can select an existing
Chromium-based browser; `PLAYWRIGHT_MODULE` can select an existing Playwright
installation. An optional third argument saves screenshots in that directory.
The script uses a fresh temporary browser profile and isolated application data,
checks both themes, navigation/restart persistence, demo export, keyboard focus,
mobile overflow and JavaScript-disabled forms, four-stage verification, historical downloads, and rejects external requests.
Human accessibility and OS browser-launch checks remain on the manual list.


## Record your own evidence

```sh
python .github/scripts/measure.py --output dist/results
```

Produces a readable report, raw Go events/coverage, five samples for each of eight
synthetic workloads, and a normalized source manifest. Add `--browser` when
Playwright/Chromium are available. See [the functional coverage map](VALIDATION.md)
and [recorded runs](results/README.md). The output explicitly distinguishes a
skipped browser check from a pass. No live accounts are required or contacted.
