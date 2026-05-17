#!/usr/bin/env python3
import argparse
import datetime as dt
import hashlib
import json
import re
from pathlib import Path

RISK_LEVELS = {
    "confirmedScam",
    "highRisk",
    "needsVerification",
    "noPublicReport",
}


def load_json(path: Path) -> object:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def require_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def validate_localized_copy(value: object, field: str) -> None:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    require_string(value.get("zhTW"), f"{field}.zhTW")
    require_string(value.get("enUS"), f"{field}.enUS")


def validate_dataset(dataset: object) -> dict:
    if not isinstance(dataset, dict):
        raise ValueError("dataset must be an object")

    require_string(dataset.get("bundleVersion"), "bundleVersion")
    require_string(dataset.get("fetchedAt"), "fetchedAt")
    schema_version = dataset.get("schemaVersion", 1)
    if schema_version not in (1, 2):
        raise ValueError("schemaVersion must be 1 or 2")

    if schema_version == 2:
        validate_compact_dataset(dataset)
        return dataset

    validate_legacy_dataset(dataset)
    return dataset


def validate_legacy_dataset(dataset: dict) -> None:
    records = dataset.get("records")
    if not isinstance(records, list):
        raise ValueError("records must be an array")

    seen_keys: set[tuple[str, str]] = set()
    for index, record in enumerate(records):
        validate_full_record(record, f"records[{index}]")
        key = (record["domain"], record["pathPrefix"])
        if key in seen_keys:
            raise ValueError(f"duplicate domain/pathPrefix pair: {record['domain']}{record['pathPrefix']}")
        seen_keys.add(key)



def validate_compact_dataset(dataset: dict) -> None:
    sources = dataset.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError("sources must be a non-empty array")

    source_ids: set[str] = set()
    for index, source in enumerate(sources):
        if not isinstance(source, dict):
            raise ValueError(f"sources[{index}] must be an object")
        source_id = require_string(source.get("id"), f"sources[{index}].id")
        if source_id in source_ids:
            raise ValueError(f"duplicate source id: {source_id}")
        source_ids.add(source_id)

        risk_level = require_string(source.get("riskLevel"), f"sources[{index}].riskLevel")
        if risk_level not in RISK_LEVELS:
            raise ValueError(f"sources[{index}].riskLevel is invalid")
        validate_localized_copy(source.get("sourceName"), f"sources[{index}].sourceName")
        require_string(source.get("sourceURL"), f"sources[{index}].sourceURL")
        validate_localized_copy(source.get("category"), f"sources[{index}].category")

    records = dataset.get("records")
    if not isinstance(records, list):
        raise ValueError("records must be an array")

    seen_keys: set[tuple[str, str]] = set()
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ValueError(f"records[{index}] must be an object")

        domain = validate_domain(record.get("domain"), f"records[{index}].domain")

        path_prefix = record.get("pathPrefix", "")
        if not isinstance(path_prefix, str):
            raise ValueError(f"records[{index}].pathPrefix must be a string")
        if path_prefix and not path_prefix.startswith("/"):
            raise ValueError(f"records[{index}].pathPrefix must start with /")

        source_id = require_string(record.get("sourceID"), f"records[{index}].sourceID")
        if source_id not in source_ids:
            raise ValueError(f"records[{index}].sourceID references unknown source")
        require_string(record.get("datasetDate"), f"records[{index}].datasetDate")

        key = (domain, path_prefix)
        if key in seen_keys:
            raise ValueError(f"duplicate domain/pathPrefix pair: {domain}{path_prefix}")
        seen_keys.add(key)


def validate_full_record(record: object, field: str) -> None:
    if not isinstance(record, dict):
        raise ValueError(f"{field} must be an object")

    validate_domain(record.get("domain"), f"{field}.domain")

    path_prefix = record.get("pathPrefix")
    if not isinstance(path_prefix, str):
        raise ValueError(f"{field}.pathPrefix must be a string")
    if path_prefix and not path_prefix.startswith("/"):
        raise ValueError(f"{field}.pathPrefix must start with /")

    risk_level = require_string(record.get("riskLevel"), f"{field}.riskLevel")
    if risk_level not in RISK_LEVELS:
        raise ValueError(f"{field}.riskLevel is invalid")

    validate_localized_copy(record.get("sourceName"), f"{field}.sourceName")
    require_string(record.get("sourceURL"), f"{field}.sourceURL")
    require_string(record.get("datasetDate"), f"{field}.datasetDate")
    validate_localized_copy(record.get("category"), f"{field}.category")


def validate_domain(value: object, field: str) -> str:
    domain = require_string(value, field).lower()
    domain_pattern = re.compile(r"^[a-z0-9.-]+$")
    if not domain_pattern.match(domain) or ".." in domain or "." not in domain:
        raise ValueError(f"{field} is not a valid lowercase domain")
    return domain


def iso_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate LinkProof dataset and update manifest.")
    parser.add_argument("--dataset", default="scam-datasets.json")
    parser.add_argument("--manifest", default="manifest.json")
    parser.add_argument("--dataset-url", default="scam-datasets.json")
    parser.add_argument("--minimum-app-version", default=None)
    parser.add_argument("--published-at", default=None)
    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    manifest_path = Path(args.manifest)
    dataset_bytes = dataset_path.read_bytes()
    dataset = validate_dataset(load_json(dataset_path))

    existing_manifest = {}
    if manifest_path.exists():
        loaded_manifest = load_json(manifest_path)
        if isinstance(loaded_manifest, dict):
            existing_manifest = loaded_manifest

    minimum_app_version = (
        args.minimum_app_version
        or existing_manifest.get("minimumAppVersion")
        or "0.1.0"
    )
    if args.published_at:
        published_at = args.published_at
    elif existing_manifest.get("datasetVersion") == dataset["bundleVersion"]:
        published_at = (
            existing_manifest.get("publishedAt")
            or dataset.get("fetchedAt")
            or iso_now()
        )
    else:
        published_at = dataset.get("fetchedAt") or iso_now()

    manifest = {
        "schemaVersion": 1,
        "datasetVersion": dataset["bundleVersion"],
        "datasetURL": args.dataset_url,
        "sha256": hashlib.sha256(dataset_bytes).hexdigest(),
        "publishedAt": published_at,
        "minimumAppVersion": minimum_app_version,
    }

    with manifest_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")


if __name__ == "__main__":
    main()
