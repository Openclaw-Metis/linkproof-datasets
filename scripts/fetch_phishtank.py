#!/usr/bin/env python3
"""Fetch and normalize PhishTank online-valid phishing URLs."""

from __future__ import annotations

import argparse
import bz2
import json
import os
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from normalize_domain import normalize_dataset_domain


PHISHTANK_SOURCE_ID = "src_phishtank"
PHISHTANK_URL = "https://data.phishtank.com/data/{key}/online-valid.json.bz2"
TIMEOUT_SECONDS = 60
MAX_RETRIES = 3
MIN_RECORDS = 1000
USER_AGENT = "LinkProofDatasetBuilder/0.2 (https://github.com/Openclaw-Metis/linkproof-datasets)"


def fetch_phishtank(api_key: str) -> list[dict]:
    if not api_key:
        raise ValueError("PHISHTANK_API_KEY is required")

    request = Request(PHISHTANK_URL.format(key=api_key), headers={"User-Agent": USER_AGENT})

    for attempt in range(MAX_RETRIES):
        try:
            with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
                status = getattr(response, "status", 200)
                if status != 200:
                    raise RuntimeError(f"PhishTank returned HTTP {status}")
                payload = response.read()
                return json.loads(bz2.decompress(payload).decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError) as error:
            if attempt == MAX_RETRIES - 1:
                raise RuntimeError(f"could not fetch PhishTank feed: {error}") from error
            time.sleep(2**attempt)

    raise RuntimeError("unreachable PhishTank retry state")


def transform(raw_records: list[dict]) -> list[dict]:
    output: list[dict] = []
    seen_domains: set[str] = set()

    for record in raw_records:
        if record.get("verified") != "yes" or record.get("online") != "yes":
            continue

        domain = normalize_dataset_domain(record.get("url"))
        if domain is None or domain in seen_domains:
            continue

        dataset_date = _date_part(record.get("verification_time")) or _date_part(record.get("submission_time"))
        if dataset_date is None:
            continue

        seen_domains.add(domain)
        output.append(
            {
                "domain": domain,
                "pathPrefix": "",
                "sourceID": PHISHTANK_SOURCE_ID,
                "datasetDate": dataset_date,
            }
        )

    return sorted(output, key=lambda record: (record["domain"], record["pathPrefix"]))


def write_records(records: list[dict], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(records, handle, ensure_ascii=False, sort_keys=True, indent=2)
        handle.write("\n")


def _date_part(value: object) -> str | None:
    if not isinstance(value, str) or len(value) < 10:
        return None
    date_part = value[:10]
    if len(date_part) == 10 and date_part[4] == "-" and date_part[7] == "-":
        return date_part
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch and normalize the PhishTank online-valid feed.")
    parser.add_argument("--output", default=Path("sources/phishtank.json"), type=Path)
    parser.add_argument("--fixture", default=None, type=Path)
    parser.add_argument("--allow-small-fixture", action="store_true")
    args = parser.parse_args()

    if args.fixture:
        with args.fixture.open("r", encoding="utf-8") as handle:
            raw_records = json.load(handle)
    else:
        raw_records = fetch_phishtank(os.environ.get("PHISHTANK_API_KEY", ""))

    records = transform(raw_records)
    if len(records) < MIN_RECORDS and not args.allow_small_fixture:
        print(f"ERROR: PhishTank produced {len(records)} records; expected at least {MIN_RECORDS}", file=sys.stderr)
        sys.exit(1)

    write_records(records, args.output)
    print(f"Wrote {len(records)} PhishTank records to {args.output}")


if __name__ == "__main__":
    main()
