"""Load raw IAM data from a fixture file or an in-memory dict.

Later, a boto3 collector will produce the same dict shape (via
`get_account_authorization_details`), so the rest of the pipeline never
needs to know whether the data came from a file or a live account.
"""
import json
from pathlib import Path
from typing import Any

from .raw_models import RawIamAccount


def parse_account(data: dict[str, Any]) -> RawIamAccount:
    return RawIamAccount.model_validate(data)


def load_account_file(path: str | Path) -> RawIamAccount:
    with open(path, encoding="utf-8") as handle:
        return parse_account(json.load(handle))
