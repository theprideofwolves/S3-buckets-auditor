"""Publishable offline evidence: functional checks, coverage and synthetic timings.

No credentials or account discovery. Benchmark latency is simulated; it is not
AWS throughput. Results are tied to a normalized source manifest, not a guessed
commit hash for an uncommitted working tree.
"""
import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import sys
import tempfile
import time

from offline_env import offline_environment

ROOT = Path(__file__).resolve().parents[2]


def source_manifest():
    paths = list(ROOT.glob("*.go")) + list((ROOT / "internal").rglob("*.go"))
    paths += [ROOT / name for name in ("go.mod", "go.sum", "VERSION")]
    paths += list((ROOT / "testdata").glob("*.json"))
    paths += [p for p in (ROOT / ".github").rglob("*") if p.suffix in (".py", ".cjs", ".yml")]
    files = []
    digest = hashlib.sha256()
    for path in sorted(set(paths), key=lambda p: p.relative_to(ROOT).as_posix()):
        relative = path.relative_to(ROOT).as_posix()
        content = path.read_bytes().replace(b"\r\n", b"\n")
        files.append({"path": relative, "sha256": hashlib.sha256(content).hexdigest()})
        digest.update(relative.encode() + b"\0" + content + b"\0")
    return {"algorithm": "SHA256(sorted relative path + NUL + LF-normalized contents + NUL)",
            "fingerprint": digest.hexdigest(), "files": files}


def coverage_metrics(path):
    blocks = {}
    for line in path.read_text(encoding="utf-8").splitlines()[1:]:
        location, statements, hits = line.rsplit(" ", 2)
        previous = blocks.get(location, (int(statements), 0))
        blocks[location] = (int(statements), previous[1] + int(hits))
    packages = defaultdict(lambda: [0, 0])
    for location, (statements, hits) in blocks.items():
        filename = location.rsplit(":", 1)[0]
        package = filename.rsplit("/", 1)[0]
        packages[package][0] += statements
        if hits:
            packages[package][1] += statements
    def row(total, covered):
        return {"statements": total, "covered": covered,
                "percent": round(100 * covered / total, 2) if total else 0}
    return {"total": row(sum(v[0] for v in packages.values()), sum(v[1] for v in packages.values())),
            "packages": {key: row(*value) for key, value in sorted(packages.items())}}


def test_metrics(output):
    passed, failed, skipped = set(), set(), set()
    package_results = {}
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        name = event.get("Test")
        key = (event.get("Package"), name)
        action = event.get("Action")
        if name and action == "pass": passed.add(key)
        if name and action == "fail": failed.add(key)
        if name and action == "skip": skipped.add(key)
        if not name and action in ("pass", "fail", "skip"):
            package_results[event["Package"]] = action
    leaves = {key for key in passed if not any(other[0] == key[0] and other[1].startswith(key[1] + "/") for other in passed)}
    return {"top_level_passed": sum("/" not in name for _, name in passed),
            "named_leaf_cases_passed": len(leaves), "failed_named_cases": len(failed),
            "skipped_named_cases": len(skipped), "packages": package_results,
            "truth_matrix_cases_passed": sum(name.startswith("TestConfigurationTruthMatrix/") for _, name in leaves),
            "unusable_sdk_response_cases_passed": sum(name.startswith("TestAWSUnusableBucketResponsesStayUnknown/") for _, name in leaves)}


def benchmark_metrics(output):
    samples = defaultdict(list)
    for line in output.splitlines():
        if not line.startswith("Benchmark"):
            continue
        fields = line.split()
        if len(fields) < 4 or not fields[1].isdigit():
            continue
        name = re.sub(r"-\d+$", "", fields[0])
        sample = {"iterations": int(fields[1])}
        for index in range(2, len(fields) - 1, 2):
            try: sample[fields[index + 1]] = float(fields[index])
            except ValueError: pass
        if "ns/op" in sample:
            samples[name].append(sample)
    result = []
    for name, runs in sorted(samples.items()):
        times = [item["ns/op"] / 1e6 for item in runs]
        result.append({"name": name, "samples": runs, "repetitions": len(runs),
                       "median_ms": statistics.median(times), "min_ms": min(times), "max_ms": max(times),
                       "median_allocated_bytes": statistics.median(item.get("B/op", 0) for item in runs),
                       "median_allocations": statistics.median(item.get("allocs/op", 0) for item in runs)})
    return result


def markdown(result):
    tests = result.get("tests", {})
    coverage = result.get("coverage", {}).get("total", {})
    lines = ["# Offline validation results", "", f"Measured {result['measured_at_utc']} on {result['environment']['system']} / {result['environment']['architecture']}.", "",
             "**Synthetic and fake-service evidence only. No live AWS/Jira compatibility, production throughput, real-world accuracy or time savings are established.**", "",
             "## Functional results", "", "| Check | Result | Seconds |", "| --- | --- | ---: |"]
    for check in result["checks"]:
        lines.append(f"| {check['name']} | {check['status']} | {check.get('seconds', 0):.2f} |")
    lines += ["", f"- Top-level tests passed: **{tests.get('top_level_passed', 0)}**.",
              f"- Named leaf cases passed: **{tests.get('named_leaf_cases_passed', 0)}** (includes subtests; do not add this to the top-level count).",
              f"- Failed named cases: **{tests.get('failed_named_cases', 0)}**; skipped named cases: **{tests.get('skipped_named_cases', 0)}**.",
              f"- Policy/flag truth matrix: **{tests.get('truth_matrix_cases_passed', 0)}/48** cases passed.",
              f"- Unusable SDK-response cases: **{tests.get('unusable_sdk_response_cases_passed', 0)}/10** stayed unknown in the tested cases.",
              f"- Go-test statement coverage: **{coverage.get('percent', 0):.2f}%** ({coverage.get('covered', 0)}/{coverage.get('statements', 0)} statements).", "",
              "Coverage comes from Go tests with the race detector and all local packages instrumented. Separate binary/browser checks are not included in that coverage percentage. Coverage is not a security score.", "",
              "## Repeated synthetic measurements", "",
              "Five one-iteration samples by default, without race/coverage instrumentation. Setup is excluded. Min/median/max are observations on this machine; no p95 or production latency is inferred.", "",
              "| Benchmark | Median ms | Min–max ms | Allocated bytes/op | Allocations/op |", "| --- | ---: | ---: | ---: | ---: |"]
    for bench in result.get("benchmarks", []):
        lines.append(f"| `{bench['name']}` | {bench['median_ms']:.3f} | {bench['min_ms']:.3f}–{bench['max_ms']:.3f} | {bench['median_allocated_bytes']:,.0f} | {bench['median_allocations']:,.0f} |")
    lines += ["", "### Workloads and interpretation", "",
              "- **SyntheticCollection:** two fake reads per bucket, each waiting for a 1 ms timer; includes scheduler/runtime overhead. No AWS SDK transport, network, STS or discovery. This measures collector orchestration under a controlled delay, not AWS scanning speed.",
              "- **VerificationReplay:** histories with 10/25 scans and 100/1,000 distinct synthetic buckets; cycles concerns, partial visibility, missing buckets and clearing. Counts refer to distinct buckets, not new findings. Timelines are materialized in memory.",
              "- **HistorySave:** atomic JSON encode/write/sync/rename over an existing history, then reload verification outside timing; local temporary filesystem. `history_bytes/op` is retained in raw samples.",
              "- **B/op** is allocated heap bytes per operation, not peak RAM/RSS. Timer, CPU load, Go version, filesystem, GC and runner hardware affect results. The largest workload is a test size, not a supported production capacity claim.", "",
              "## Reproduce and inspect", "", "```sh", "python .github/scripts/measure.py --output dist/results", "```", "",
              "Add `--browser` with the Playwright/browser environment described in [testing](../../TESTING.md). Browser results are explicitly NOT RUN when omitted.", "",
              f"Source fingerprint: `{result['source']['fingerprint']}`.", "",
              "[Machine-readable results](results.json) contain the LF-normalized source manifest, environment, command records and every benchmark sample. [Go test events](go-tests.jsonl), [coverage profile](coverage.out), [coverage detail](coverage.log) and [benchmark output](benchmarks.log) support the summary. Report/docs themselves are excluded from the source fingerprint to avoid a self-referential hash.", "",
              "The fingerprint identifies the tested code/test/fixture/workflow contents even when measured before commit. A subsequent GitHub Actions run validates the pushed commit separately.", "",
              "## Not established / still manual", "", "- Live AWS credentials/SSO, permissions, throttling/region behavior and live Jira project compatibility.",
              "- Human screen-reader/accessibility review, OS browser auto-opening, other browser engines and clean-machine launch.",
              "- Real-user adoption, measured analyst time savings, field precision/recall, a full security assessment or effective anonymous access.",
              "- Performance beyond the listed local synthetic workloads. See [manual acceptance](../../TESTING.md).", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="dist/results")
    parser.add_argument("--browser", action="store_true")
    parser.add_argument("--repeats", type=int, default=5)
    args = parser.parse_args()
    if args.repeats < 3: parser.error("use at least three timing samples")
    destination = (ROOT / args.output).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    result = {"measured_at_utc": datetime.now(timezone.utc).isoformat(),
              "environment": {"system": platform.system(), "release": platform.release(), "architecture": platform.machine(),
                              "logical_processors": os.cpu_count(), "python": platform.python_version()},
              "source": source_manifest(), "checks": []}
    failed = False
    with tempfile.TemporaryDirectory(prefix="s3-measure-") as temporary:
        env = offline_environment(temporary)
        executable = Path(temporary, "s3-auditor.exe" if os.name == "nt" else "s3-auditor")
        def clean(text):
            for value, replacement in ((str(ROOT), "<repo>"), (temporary, "<temporary>"), (str(Path.home()), "<home>")):
                text = text.replace(value, replacement).replace(value.replace("\\", "/"), replacement)
            return re.sub(r"(http://(?:127\.0\.0\.1|localhost):\d+/[^\s\"']*token=)[^\s&\"']+", r"\1<redacted>", text)
        def run(name, command, logfile):
            nonlocal failed
            print("Running " + name, flush=True)
            started = time.perf_counter()
            completed = subprocess.run(command, cwd=ROOT, env=env, text=True, encoding="utf-8", errors="replace", stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            output = clean(completed.stdout)
            (destination / logfile).write_text(output, encoding="utf-8")
            display = clean(" ".join(str(x) for x in command)).replace(sys.executable, "python")
            result["checks"].append({"name": name, "status": "PASS" if completed.returncode == 0 else "FAIL", "exit_code": completed.returncode,
                                     "seconds": round(time.perf_counter() - started, 4), "command": display, "log": logfile})
            if completed.returncode: failed = True
            print(name + ": " + ("PASS" if completed.returncode == 0 else "FAIL"), flush=True)
            return completed.returncode, output
        _, version = run("Go version", ["go", "version"], "go-version.log")
        result["environment"]["go"] = version.strip()
        _, test_output = run("Race tests and coverage", ["go", "test", "-race", "-count=1", "-json", "-coverpkg=./...", "-coverprofile=" + str(destination / "coverage.out"), "./..."], "go-tests.jsonl")
        result["tests"] = test_metrics(test_output)
        if result["tests"]["truth_matrix_cases_passed"] != 48 or result["tests"]["unusable_sdk_response_cases_passed"] != 10:
            failed = True
            result["measurement_error"] = "Expected all 48 matrix and 10 unusable-response cases to pass"
        if (destination / "coverage.out").exists():
            result["coverage"] = coverage_metrics(destination / "coverage.out")
            run("Coverage detail", ["go", "tool", "cover", "-func=" + str(destination / "coverage.out")], "coverage.log")
        run("Go vet", ["go", "vet", "./..."], "vet.log")
        build_code, _ = run("Root build", ["go", "build", "-trimpath", "-o", str(executable), "."], "build.log")
        if build_code == 0:
            result["binary_bytes"] = executable.stat().st_size
            run("Packaged UI workflow", [sys.executable, str(ROOT / ".github/scripts/smoke.py"), str(executable)], "ui-smoke.log")
            run("CLI workflow", [sys.executable, str(ROOT / ".github/scripts/cli_smoke.py"), str(executable)], "cli-smoke.log")
            if args.browser:
                # Browser paths configure the test harness, never the application.
                env["PLAYWRIGHT_MODULE"] = os.environ.get("PLAYWRIGHT_MODULE", "playwright")
                if os.environ.get("S3_AUDITOR_BROWSER"): env["S3_AUDITOR_BROWSER"] = os.environ["S3_AUDITOR_BROWSER"]
                run("Offline Chromium workflow", ["node", str(ROOT / ".github/scripts/browser_smoke.cjs"), str(executable)], "browser-smoke.log")
            else:
                result["checks"].append({"name": "Offline Chromium workflow", "status": "NOT RUN", "reason": "optional --browser not supplied"})
        _, bench_output = run("Synthetic benchmarks", ["go", "test", "-run=^$", "-bench=Benchmark(SyntheticCollection|VerificationReplay|HistorySave)$", "-benchmem", "-benchtime=1x", "-count=" + str(args.repeats), "."], "benchmarks.log")
        result["benchmarks"] = benchmark_metrics(bench_output)
        if len(result["benchmarks"]) != 8 or any(b["repetitions"] != args.repeats for b in result["benchmarks"]):
            failed = True
            result["measurement_error"] = "Expected eight benchmark workloads with the requested repetitions"
    if result["source"] != source_manifest():
        failed = True
        result["measurement_error"] = "Source changed during measurement; rerun before publishing"
    result["status"] = "FAIL" if failed else "PASS"
    (destination / "results.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    (destination / "README.md").write_text(markdown(result), encoding="utf-8")
    print("Measurements: " + result["status"], flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
