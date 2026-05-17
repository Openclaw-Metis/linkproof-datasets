#!/usr/bin/env python3
"""Manual URLhaus overlap spike.

This script is intentionally not used by the production dataset build. It only
answers one question: how many currently known LinkProof scam domains overlap
with a URLhaus URL list sample?
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.request import Request, urlopen

from normalize_domain import normalize_dataset_domain


URLHAUS_TEXT_URL = "https://urlhaus.abuse.ch/downloads/text/"
USER_AGENT = "LinkProofDatasetSpike/0.1 (https://github.com/Openclaw-Metis/linkproof-datasets)"


def domains_from_urlhaus_text(text: str) -> set[str]:
    domains: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        for token in line.split():
            domain = normalize_dataset_domain(token)
            if domain:
                domains.add(domain)
    return domains


def sample_domains_from_dataset(dataset_path: Path, sample_size: int) -> list[str]:
    with dataset_path.open("r", encoding="utf-8") as handle:
        dataset = json.load(handle)

    records = dataset.get("records")
    if not isinstance(records, list):
        raise ValueError("dataset records must be an array")

    domains: list[str] = []
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        domain = normalize_dataset_domain(record.get("domain"))
        if domain and domain not in seen:
            seen.add(domain)
            domains.append(domain)
        if len(domains) >= sample_size:
            break

    return domains


def compute_overlap(sample_domains: list[str], urlhaus_domains: set[str]) -> dict:
    sample_set = set(sample_domains)
    hits = sorted(sample_set & urlhaus_domains)
    return {
        "sampleCount": len(sample_set),
        "urlhausDomainCount": len(urlhaus_domains),
        "hitCount": len(hits),
        "hitRate": 0 if not sample_set else len(hits) / len(sample_set),
        "hits": hits,
    }


def fetch_live_urlhaus_text(timeout: int) -> str:
    request = Request(URLHAUS_TEXT_URL, headers={"User-Agent": USER_AGENT})
    with urlopen(request, timeout=timeout) as response:
        status = getattr(response, "status", 200)
        if status < 200 or status >= 300:
            raise RuntimeError(f"URLhaus returned HTTP {status}")
        return response.read().decode("utf-8", errors="replace")


def main() -> None:
    parser = argparse.ArgumentParser(description="Compute LinkProof dataset overlap with a URLhaus text URL list.")
    parser.add_argument("--dataset", default=Path("scam-datasets.json"), type=Path)
    parser.add_argument("--sample-size", default=100, type=int)
    parser.add_argument("--urlhaus-text", default=None, type=Path)
    parser.add_argument("--fetch-live", action="store_true")
    parser.add_argument("--timeout", default=30, type=int)
    args = parser.parse_args()

    if args.sample_size <= 0:
        parser.error("--sample-size must be positive")
    if args.fetch_live and args.urlhaus_text:
        parser.error("--fetch-live and --urlhaus-text are mutually exclusive")
    if not args.fetch_live and args.urlhaus_text is None:
        parser.error("provide --urlhaus-text for offline evaluation, or pass --fetch-live explicitly")

    if args.fetch_live:
        text = fetch_live_urlhaus_text(args.timeout)
    else:
        text = args.urlhaus_text.read_text(encoding="utf-8")

    urlhaus_domains = domains_from_urlhaus_text(text)
    sample_domains = sample_domains_from_dataset(args.dataset, args.sample_size)
    result = compute_overlap(sample_domains, urlhaus_domains)
    json.dump(result, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
