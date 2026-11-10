"""Exercise CLI reporting and error exits against the built executable only."""
from pathlib import Path
import subprocess
import sys
import tempfile

from offline_env import offline_environment


def main():
    executable = str(Path(sys.argv[1]).resolve())
    fixture = str(Path(__file__).resolve().parents[2] / "testdata/demo.json")
    with tempfile.TemporaryDirectory(prefix="s3-cli-") as temporary:
        root = Path(temporary)
        env = offline_environment(root)
        result = subprocess.run([executable, "-demo", fixture], cwd=root, env=env, capture_output=True, text=True)
        assert result.returncode == 0, "offline CLI demo failed"
        report = (root / "audit_results.md").read_text()
        assert report.count("| demo-") == 4, "CLI demo lost a bucket"
        assert "Unknown / incomplete" in report and "Checked controls enabled" in report
        assert "synthetic AccessDenied" in (root / "error.log").read_text()
        assert not (root / "data" / "history.json").exists(), "CLI wrote GUI history"
        original = report
        malformed = root / "malformed.json"
        malformed.write_text("[broken", encoding="utf-8")
        for flags in (
            ["-workers", "0"], ["-workers", "65"],
            ["-bucket", "example", "-csv", "example.txt"],
            ["-demo", fixture, "-bucket", "example"],
            ["-demo", str(malformed)], ["-demo", str(root / "missing.json")],
            ["-unknown-option"], ["-demo", fixture, "unexpected-positional-argument"],
        ):
            failed = subprocess.run([executable, *flags], cwd=root, env=env, capture_output=True, text=True)
            assert failed.returncode != 0, "invalid CLI flags accepted: " + repr(flags)
            assert (root / "audit_results.md").read_text() == original, "failed command replaced the prior report"
    print("PASS: CLI fixture, unknown evidence, validation exits and GUI-history separation.")


if __name__ == "__main__":
    main()
