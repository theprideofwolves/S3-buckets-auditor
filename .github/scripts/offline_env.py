"""Credential isolation shared by the offline checks and packaged smoke test."""
from pathlib import Path
import os


def offline_environment(root):
    empty = Path(root, "empty-aws-config")
    empty.write_text("", encoding="utf-8")
    env = {
        key: value for key, value in os.environ.items()
        if not key.upper().startswith(("AWS_", "JIRA_", "S3_AUDITOR_"))
    }
    env.update(
        AWS_CONFIG_FILE=str(empty),
        AWS_SHARED_CREDENTIALS_FILE=str(empty),
        AWS_EC2_METADATA_DISABLED="true",
        AWS_ENDPOINT_URL="http://127.0.0.1:1",
        AWS_MAX_ATTEMPTS="1",
        S3_AUDITOR_DATA_DIR=str(Path(root, "data")),
        S3_AUDITOR_NO_BROWSER="1",
    )
    return env
