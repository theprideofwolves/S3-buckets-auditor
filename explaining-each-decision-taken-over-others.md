# Decisions and alternatives

1. **Retain Go modular monolith.** Existing AWS implementation is Go. Embedded
HTML and standard HTTP avoid Python/Node runtime distribution. Tradeoff: fewer
UI components and manual forms. Revisit if interaction complexity grows.
2. **JSON history instead of SQLite.** Small single-user scope and no new runtime
or driver. Atomic replacement is simple to inspect/back up. Tradeoff: rewrite
cost and whole-history memory. Revisit after measuring growth. Single instance
lock prevents normal competing writers; deliberate file tampering is out of scope.
3. **Serial UI actions, bounded AWS workers.** Consistent state without a job
queue. Tradeoff: UI waits during scans; app has deadline rather than a cancel
button. Revisit if actual users need background jobs.
4. **Unknown before clean.** Failed API calls cannot prove control state. Separate
check states preserve successful partial observations without a false clean label.
5. **Limited S3 scope.** Two correct checks over a larger invented benchmark.
Missing block settings alone do not prove anonymous access. No CIS IDs claimed.
6. **User-selected region.** Avoid extra discovery permissions. Wrong-region
results remain explicit errors. Tradeoff: users may need regional reruns.
7. **Jira durable intent + manual reconciliation.** External create is not an
atomic local transaction. Blind retry risks duplicates. Pending intent survives
crashes. Comments are not exactly-once; users inspect uncertain updates.
8. **Request-only Jira credentials.** Avoid credential persistence and new keychain
dependencies. Tradeoff: re-enter token each action. No claim of secure vault support.
9. **Account/region scoped comparisons.** Avoid mixing environments. Missing
buckets are not resolved. Historical scans can append timestamped historical
evidence, not automatically update issue status.
10. **Portable builds rather than installer.** One executable, no administrator
requirement. Tradeoff: unsigned warning and visible launcher. Platform CI verifies
compilation/tests, not an interactive install on every distribution.

All decisions are accepted for this release. Test evidence is in app_test.go and
main_test.go; limitations and revisiting conditions are described in architecture.md.

## S3 onboarding decisions

Expose profile/region/target setup because these are the AWS assessment inputs.
Keep STS and Jira identity checks separate from permissions and actual work:
successful authentication must not be presented as a completed bucket assessment.
There is no local source folder or upload workflow to configure.

Use the offline four-bucket demo to teach concern versus unknown without
requiring an AWS account. Save its evidence in a clearly synthetic scope and
block its Jira handoff. Keep old scans when the demo runs again.

Remember guide completion after durable assessment save, including unknown
observations worth reviewing. Keep that preference separate from history and
ticket intent. Server-rendered forms avoid an extra frontend runtime. Use
Referrer-Policy same-origin to preserve ordinary local form submissions while
strict guards continue to reject foreign and opaque origins.


## Remediation verification decisions (v1.3.0)

- **Replay observations rather than persist another ledger.** One source of truth and atomic history saves prevent ledger/history divergence. The cost is repeated replay and larger in-memory timelines; this is a local tool, not a high-scale service.
- **Track per-control episodes.** A known clearing observation closes that control; a gap does not. Partial success can clear one control while the overall bucket stays unknown. A recurrence creates a new episode rather than rewriting the first.
- **Separate aggregate checks and flag details.** Policy status and overall bucket block configuration are the two concerns; four flags explain the latter. Counting each flag and its parent as independent findings would inflate results.
- **Nullable observations and conservative legacy support.** An incomplete old summary cannot reveal the disabled flag. Preserve the old scan and leave per-flag history unknown. No guessed historical values or automatic rewrite.
- **Append order, selected prefix and scope/class isolation.** Historical views exclude future observations and other scopes, even when timestamps collide or clocks skew. Timestamps are observations, not precise configuration-change times.
- **Current Jira links are not historical Jira state.** Existing mappings have no revision history. Export them under CurrentTicketLinks with an explicit limitation; never silently label them as state at the selected scan.
- **Demonstrate with a separate synthetic sequence.** Save concern/denied/missing/clear in one atomic batch, retaining the original four-bucket demo. All synthetic stages block real Jira handoff.

These are implementation tradeoffs, not a claim of an industry-first algorithm. See docs/VERIFICATION.md and verification_test.go.
