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

## Onboarding design and study notes

The internal/onboarding package owns the welcome/setup routes, escaped progress
panel, declared non-secret session fields, and a versioned completion preference.
Core handlers explicitly call Complete only after a successful domain operation.
A failing policy evaluation is still a successful task; a partial LogFlow report
is not marked complete. Guide status is not a security/compliance conclusion.

GET/sample/setup routes do not run scans or create tickets. POST setup checks
use bounded read-only requests; Jira identity is not project authorization. Native
folder selection is explicit, bounded and has a manual fallback. Preflight checks
never store tokens, and Jira checks preserve previously selected local fields.

Why not a JS tour library? Server-rendered forms and a small guide keep packaging
light, work offline and are keyboard accessible. Each independent repository
contains its own internal copy and tests; no cross-project service is required.
That trades centralized updates for simpler standalone distribution.

Practice: explain a fresh launch, a failed check, a successful demo, persistence
after restart, and why restarting the guide cannot delete assessment data. Read
onboarding_test.go and the packaged smoke script to distinguish a connection
check from an end-to-end live integration test.

Browser regression: use Referrer-Policy same-origin rather than no-referrer.
The latter can make a browser emit an opaque Origin on ordinary form posts,
which correctly fails strict origin checks. Same-origin preserves legitimate
local form submission while suppressing cross-origin referrers. Null and foreign
origins remain rejected. This was verified through a real browser interaction.
