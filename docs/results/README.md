# Recorded validation runs

- [2026-11-10 Windows / AMD64](2026-11-10-windows/README.md): offline functional tests, statement coverage, packaged UI/CLI, actual headless Chromium, and repeated synthetic collection/replay/persistence measurements. Includes raw logs, coverage and every timing sample.
- [GitHub Actions](https://github.com/theprideofwolves/S3-buckets-auditor/actions/workflows/go.yml): independent Linux/Windows run summaries and downloadable evidence artifacts for each pushed commit. Browser automation is explicitly not run in those jobs.

Use the [validation map and methodology](../VALIDATION.md) to interpret these results. Manual and live checks remain separate; no fabricated accuracy, users or business-impact metrics.
