#!/usr/bin/env python3
"""Fetch and normalize PhishTank online-valid phishing URLs."""

from __future__ import annotations

import argparse
import bz2
import csv
import gzip
import io
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from normalize_domain import normalize_dataset_domain, normalize_dataset_path


PHISHTANK_SOURCE_ID = "src_phishtank"
PHISHTANK_KEYED_URL = "https://data.phishtank.com/data/{key}/online-valid.json.bz2"
PHISHTANK_PUBLIC_URL = "https://data.phishtank.com/data/online-valid.json.bz2"
PHISHTANK_PUBLIC_CSV_GZ_URL = "https://data.phishtank.com/data/online-valid.csv.gz"
TIMEOUT_SECONDS = 60
MAX_RETRIES = 3
MIN_RECORDS = 1000
USER_AGENT = (
    "LinkProofDatasetBuilder/0.2 "
    "(anti-fraud public service for Taiwan citizens; "
    "https://github.com/Openclaw-Metis/linkproof-datasets)"
)

SHARED_PLATFORM_DOMAINS = {
    "google.com",
    "sites.google.com",
    "docs.google.com",
    "drive.google.com",
    "forms.gle",
    "appspot.com",
    "microsoft.com",
    "office.com",
    "live.com",
    "outlook.com",
    "sharepoint.com",
    "onedrive.live.com",
    "forms.office.com",
    "github.com",
    "github.io",
    "gist.github.com",
    "firebaseapp.com",
    "web.app",
    "vercel.app",
    "netlify.app",
    "pages.dev",
    "amazonaws.com",
    "cloudfront.net",
    "azurewebsites.net",
    "weebly.com",
    "wix.com",
    "wordpress.com",
    "squarespace.com",
    "notion.site",
    "notion.so",
    "medium.com",
    "linkedin.com",
    "typeform.com",
    "jotform.com",
    "dropbox.com",
    "box.com",
    "blogspot.com",
}


@dataclass(frozen=True)
class PhishTankFeed:
    url: str
    mode: str
    format: str


def phishtank_feed_candidates(api_key: str | None) -> list[PhishTankFeed]:
    trimmed = (api_key or "").strip()
    if trimmed:
        return [PhishTankFeed(PHISHTANK_KEYED_URL.format(key=trimmed), "keyed", "json-bz2")]
    return [
        PhishTankFeed(PHISHTANK_PUBLIC_URL, "public", "json-bz2"),
        PhishTankFeed(PHISHTANK_PUBLIC_CSV_GZ_URL, "public", "csv-gz"),
    ]


def phishtank_feed_url(api_key: str | None) -> tuple[str, str]:
    candidate = phishtank_feed_candidates(api_key)[0]
    return candidate.url, candidate.mode


def fetch_phishtank(api_key: str | None = None) -> list[dict]:
    errors: list[str] = []
    for candidate in phishtank_feed_candidates(api_key):
        try:
            return _fetch_candidate(candidate)
        except RuntimeError as error:
            errors.append(str(error))
            print(f"WARNING: {error}", file=sys.stderr)

    raise RuntimeError("; ".join(errors) if errors else "no PhishTank feed candidates configured")


def _fetch_candidate(candidate: PhishTankFeed) -> list[dict]:
    request = Request(candidate.url, headers={"User-Agent": USER_AGENT})
    for attempt in range(MAX_RETRIES):
        try:
            with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
                status = getattr(response, "status", 200)
                if status != 200:
                    raise RuntimeError(f"PhishTank returned HTTP {status}")
                payload = response.read()
                records = _parse_payload(payload, candidate.format)
                last_modified = response.headers.get("Last-Modified", "unknown")
                print(
                    "PhishTank dump: "
                    f"{len(records)} records, mode={candidate.mode}, "
                    f"format={candidate.format}, last-modified={last_modified}"
                )
                return records
        except HTTPError as error:
            if error.code in {404, 410}:
                raise RuntimeError(f"PhishTank feed unavailable at {candidate.url}: HTTP {error.code}") from error
            if error.code not in {408, 429, 500, 502, 503, 504}:
                raise RuntimeError(f"PhishTank returned HTTP {error.code}") from error
            if attempt == MAX_RETRIES - 1:
                raise RuntimeError(
                    f"could not fetch PhishTank feed {candidate.url} after retryable HTTP {error.code}"
                ) from error
            time.sleep(2**attempt)
        except (URLError, TimeoutError, OSError, json.JSONDecodeError, ValueError) as error:
            if attempt == MAX_RETRIES - 1:
                raise RuntimeError(f"could not fetch PhishTank feed {candidate.url}: {error}") from error
            time.sleep(2**attempt)

    raise RuntimeError("unreachable PhishTank retry state")


def _parse_payload(payload: bytes, feed_format: str) -> list[dict]:
    if feed_format == "json-bz2":
        records = json.loads(bz2.decompress(payload).decode("utf-8"))
        if not isinstance(records, list):
            raise ValueError("PhishTank JSON feed must decode to a list")
        return records

    if feed_format == "csv-gz":
        text = gzip.decompress(payload).decode("utf-8", errors="replace")
        reader = csv.DictReader(io.StringIO(text))
        return [dict(row) for row in reader]

    raise ValueError(f"unsupported PhishTank feed format: {feed_format}")


def transform(raw_records: list[dict]) -> list[dict]:
    output_by_key: dict[tuple[str, str], dict] = {}

    for record in raw_records:
        if record.get("verified") != "yes" or record.get("online") != "yes":
            continue

        url = record.get("url")
        domain = normalize_dataset_domain(_hostname(url))
        path_prefix = _path_prefix(url)
        if domain is None or path_prefix is None:
            continue
        if is_shared_platform_domain(domain) and not path_prefix:
            continue

        dataset_date = _date_part(record.get("verification_time")) or _date_part(record.get("submission_time"))
        if dataset_date is None:
            continue

        key = (domain, path_prefix)
        candidate = {
            "domain": domain,
            "pathPrefix": path_prefix,
            "sourceID": PHISHTANK_SOURCE_ID,
            "datasetDate": dataset_date,
        }
        existing = output_by_key.get(key)
        if existing is None or dataset_date > existing["datasetDate"]:
            output_by_key[key] = candidate

    return sorted(output_by_key.values(), key=lambda record: (record["domain"], record["pathPrefix"]))


def is_shared_platform_domain(domain: str) -> bool:
    return any(domain == shared or domain.endswith(f".{shared}") for shared in SHARED_PLATFORM_DOMAINS)


def _hostname(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = urlparse(value)
    except ValueError:
        return None
    return parsed.hostname


def _path_prefix(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = urlparse(value)
    except ValueError:
        return None

    segments = [segment for segment in parsed.path.split("/") if segment]
    if not segments:
        return ""
    return normalize_dataset_path("/" + "/".join(segments[:2]))


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
