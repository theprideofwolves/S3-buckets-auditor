"""Run free checks without inheriting AWS credentials or modifying user data."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile

from offline_env import offline_environment

ROOT = Path(__file__).resolve().parents[2]


def main():
    with tempfile.TemporaryDirectory(prefix="s3-offline-") as temporary:
        env = offline_environment(temporary)
        executable = Path(temporary, "s3-auditor.exe" if os.name == "nt" else "s3-auditor")
        for command in (
            ["go", "version"],
            ["go", "test", "-race", "-count=1", "./..."],
            ["go", "vet", "./..."],
            ["go", "build", "-trimpath", "-o", str(executable), "."],
            [sys.executable, str(ROOT / ".github/scripts/smoke.py"), str(executable)],
            [sys.executable, str(ROOT / ".github/scripts/cli_smoke.py"), str(executable)],
        ):
            # Do not print launcher output or environment values.
            print("Running " + " ".join(command[:4]), flush=True)
            subprocess.run(command, cwd=ROOT, env=env, check=True)
    print("PASS: isolated offline checks (fake services; no live compatibility claim).")


if __name__ == "__main__":
    try:
        main()
    except (subprocess.CalledProcessError, OSError) as error:
        print("Checks failed: " + str(error), file=sys.stderr)
        sys.exit(1)
