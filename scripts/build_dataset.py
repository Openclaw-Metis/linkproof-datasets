#!/usr/bin/env python3
import argparse
import csv
import datetime as dt
import hashlib
import io
import json
import os
import re
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from fetch_phishtank import MIN_RECORDS as PHISHTANK_MIN_RECORDS
from fetch_phishtank import PHISHTANK_SOURCE_ID, fetch_phishtank, transform as transform_phishtank
from merge_sources import merge_records
from normalize_domain import normalize_dataset_domain, normalize_dataset_path


@dataclass(frozen=True)
class SourceSpec:
    source_id: str
    raw_url: str
    page_url: str
    source_name_zh: str
    source_name_en: str
    category_zh: str
    category_en: str
    risk_level: str
    priority: int
    min_records: int
    parser: str
    compact_source_id: str | None = None
    cache_filename: str | None = None


SOURCES = [
    SourceSpec(
        source_id="npa-stopped-resolution",
        raw_url=(
            "https://opdadm.moi.gov.tw/api/v1/no-auth/resource/api/dataset/"
            "29E8E643-88ED-4952-B21E-BD42A3B7108C/resource/"
            "8736A700-44F5-4E7E-8F74-16B4E8CAD13B/download"
        ),
        page_url="https://data.gov.tw/dataset/176455",
        source_name_zh="165反詐騙諮詢專線_遭停止解析涉詐網站",
        source_name_en="165 anti-fraud stopped-resolution scam websites",
        category_zh="遭停止解析涉詐網站",
        category_en="Stopped-resolution scam website",
        risk_level="confirmedScam",
        priority=300,
        min_records=1000,
        parser="npa_stopped_resolution",
        cache_filename="165-stopped-resolution.json",
    ),
    SourceSpec(
        source_id="moda-ecommerce-rpz",
        raw_url="https://www-api.moda.gov.tw/OpenData/Files/16352",
        page_url="https://data.gov.tw/dataset/165027",
        source_name_zh="數位發展部數位產業署聲請詐騙網域名稱停止解析網址清單",
        source_name_en="MODA Administration for Digital Industries scam-domain stop-resolution list",
        category_zh="電商詐騙停止解析網域",
        category_en="E-commerce scam stopped-resolution domain",
        risk_level="confirmedScam",
        priority=250,
        min_records=500,
        parser="moda_ecommerce_rpz",
        cache_filename="digi-gov-tw.json",
    ),
    SourceSpec(
        source_id="npa-fake-investment",
        raw_url=(
            "https://opdadm.moi.gov.tw/api/v1/no-auth/resource/api/dataset/"
            "033197D4-70F4-45EB-9FB8-6D83532B999A/resource/"
            "FEAA1683-4483-4FDC-B861-BC530789E2AB/download"
        ),
        page_url="https://data.gov.tw/dataset/160055",
        source_name_zh="165反詐騙諮詢專線_假投資(博弈)網站",
        source_name_en="165 anti-fraud fake investment and gambling websites",
        category_zh="假投資/博弈網站",
        category_en="Fake investment or gambling website",
        risk_level="confirmedScam",
        priority=200,
        min_records=1000,
        parser="npa_fake_investment",
        cache_filename="165-fake-investment.json",
    ),
]

PHISHTANK_SOURCE = SourceSpec(
    source_id=PHISHTANK_SOURCE_ID,
    raw_url="https://www.phishtank.com/",
    page_url="https://www.phishtank.com/",
    source_name_zh="PhishTank 社群釣魚情資",
    source_name_en="PhishTank community phishing data",
    category_zh="釣魚網站",
    category_en="Phishing site",
    risk_level="highRisk",
    priority=100,
    min_records=PHISHTANK_MIN_RECORDS,
    parser="phishtank",
    compact_source_id=PHISHTANK_SOURCE_ID,
    cache_filename="phishtank.json",
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def taipei_date_part(iso_value: str) -> str:
    parsed = dt.datetime.fromisoformat(iso_value.replace("Z", "+00:00"))
    taipei = parsed.astimezone(dt.timezone(dt.timedelta(hours=8)))
    return taipei.date().isoformat().replace("-", ".")


def load_json(path: Path) -> object | None:
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, value: object) -> None:
    if (
        isinstance(value, dict)
        and isinstance(value.get("bundleVersion"), str)
        and isinstance(value.get("fetchedAt"), str)
        and isinstance(value.get("records"), list)
    ):
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write("{\n")
            if isinstance(value.get("schemaVersion"), int):
                handle.write(f"  \"schemaVersion\":{value['schemaVersion']},\n")
            handle.write(f"  \"bundleVersion\":{json.dumps(value['bundleVersion'], ensure_ascii=False)},\n")
            handle.write(f"  \"fetchedAt\":{json.dumps(value['fetchedAt'], ensure_ascii=False)},\n")
            if isinstance(value.get("sources"), list):
                handle.write("  \"sources\":[\n")
                sources = value["sources"]
                for index, source in enumerate(sources):
                    suffix = "," if index < len(sources) - 1 else ""
                    encoded = json.dumps(source, ensure_ascii=False, separators=(",", ":"))
                    handle.write(f"    {encoded}{suffix}\n")
                handle.write("  ],\n")
            handle.write("  \"records\":[\n")
            records = value["records"]
            for index, record in enumerate(records):
                suffix = "," if index < len(records) - 1 else ""
                encoded = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
                handle.write(f"    {encoded}{suffix}\n")
            handle.write("  ]\n")
            handle.write("}\n")
        return

    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def fetch_text(url: str, timeout: int) -> str:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "LinkProofDatasetBuilder/1.0"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        status = getattr(response, "status", 200)
        if status < 200 or status >= 300:
            raise ValueError(f"{url} returned HTTP {status}")
        data = response.read()
        charset = response.headers.get_content_charset()

    encodings = [encoding for encoding in [charset, "utf-8-sig", "utf-8", "big5", "cp950"] if encoding]
    last_error: Exception | None = None
    for encoding in encodings:
        try:
            return data.decode(encoding)
        except UnicodeDecodeError as error:
            last_error = error
    raise ValueError(f"could not decode {url}: {last_error}")


def csv_rows(text: str) -> list[dict[str, str]]:
    cleaned = text.lstrip("\ufeff")
    reader = csv.DictReader(io.StringIO(cleaned))
    return [{(key or "").lstrip("\ufeff"): value for key, value in row.items()} for row in reader]


def parse_roc_month(value: str | None) -> str | None:
    if not value:
        return None
    digits = re.sub(r"\D", "", value)
    if len(digits) < 5:
        return None
    year = int(digits[:-2]) + 1911
    month = int(digits[-2:])
    if month < 1 or month > 12:
        return None
    return f"{year:04d}-{month:02d}-01"


def parse_date(value: str | None) -> str | None:
    if not value:
        return None
    trimmed = value.strip()
    if not trimmed:
        return None

    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%Y/%m/%d", "%Y%m%d"):
        try:
            return dt.datetime.strptime(trimmed[:19], fmt).date().isoformat()
        except ValueError:
            continue
    return None


def normalize_domain(value: str | None) -> str | None:
    return normalize_dataset_domain(value)


def category_en_for_npa_stopped(category_zh: str | None, fallback: str) -> str:
    mapping = {
        "金融保險": "Financial or insurance scam website",
        "電子商務": "E-commerce scam website",
        "投資": "Investment scam website",
        "博弈": "Gambling scam website",
    }
    if not category_zh:
        return fallback
    return mapping.get(category_zh.strip(), fallback)


def make_record(
    source: SourceSpec,
    domain: str,
    dataset_date: str | None,
    category_zh: str | None = None,
    category_en: str | None = None,
) -> dict:
    record = {
        "domain": domain,
        "pathPrefix": "",
        "riskLevel": source.risk_level,
        "sourceName": {
            "zhTW": source.source_name_zh,
            "enUS": source.source_name_en,
        },
        "sourceURL": source.page_url,
        "datasetDate": dataset_date or dt.date.today().isoformat(),
        "category": {
            "zhTW": category_zh or source.category_zh,
            "enUS": category_en or source.category_en,
        },
    }
    if source.compact_source_id:
        record["_sourceID"] = source.compact_source_id
    return record


def parse_npa_stopped_resolution(text: str, source: SourceSpec) -> list[dict]:
    records = []
    for row in csv_rows(text):
        domain = normalize_domain(row.get("網域"))
        if not domain:
            continue
        category_zh = (row.get("網站性質") or "").strip() or source.category_zh
        records.append(
            make_record(
                source,
                domain,
                parse_roc_month(row.get("民國年月")),
                category_zh=f"{source.category_zh}：{category_zh}",
                category_en=category_en_for_npa_stopped(category_zh, source.category_en),
            )
        )
    return records


def parse_moda_ecommerce_rpz(text: str, source: SourceSpec) -> list[dict]:
    data = json.loads(text)
    if not isinstance(data, list):
        raise ValueError("MODA source must be a JSON array")

    records = []
    for item in data:
        if not isinstance(item, dict):
            continue
        domain = normalize_domain(item.get("網域名稱")) or normalize_domain(item.get("偽冒網址"))
        if not domain:
            continue
        dataset_date = (
            parse_date(item.get("停止解析日期"))
            or parse_date(item.get("接獲通報日期"))
            or parse_date(item.get("詐騙網站創建日期"))
        )
        records.append(make_record(source, domain, dataset_date))
    return records


def parse_npa_fake_investment(text: str, source: SourceSpec) -> list[dict]:
    records = []
    for row in csv_rows(text):
        if row.get("WEBSITE_NM") == "網站名稱":
            continue
        domain = normalize_domain(row.get("WEBURL"))
        if not domain:
            continue
        dataset_date = parse_date(row.get("STA_EDATE")) or parse_date(row.get("STA_SDATE"))
        records.append(make_record(source, domain, dataset_date))
    return records


def expand_compact_source_records(source: SourceSpec, records: list[dict]) -> list[dict]:
    expanded = []
    for record in records:
        if not isinstance(record, dict):
            continue

        raw_domain = record.get("domain") if isinstance(record.get("domain"), str) else None
        raw_path = record.get("pathPrefix", "") if isinstance(record.get("pathPrefix", ""), str) else ""
        domain = normalize_dataset_domain(raw_domain)
        path_prefix = normalize_dataset_path(raw_path)
        dataset_date = parse_date(record.get("datasetDate")) if isinstance(record.get("datasetDate"), str) else None
        if not domain or path_prefix is None:
            continue

        expanded.append(make_record(source, domain, dataset_date, category_zh=source.category_zh, category_en=source.category_en) | {"pathPrefix": path_prefix})
    return expanded


def compact_source_records(records: list[dict]) -> list[dict]:
    compact = []
    for record in records:
        compact_record = {
            "domain": record["domain"],
            "pathPrefix": record.get("pathPrefix", ""),
            "datasetDate": record["datasetDate"],
        }
        if record.get("_sourceID"):
            compact_record["sourceID"] = record["_sourceID"]
        compact.append(compact_record)
    return sorted(compact, key=lambda record: (record["domain"], record.get("pathPrefix", "")))


def write_source_cache(source_output_dir: Path | None, source: SourceSpec, records: list[dict]) -> None:
    if source_output_dir is None or not source.cache_filename:
        return

    source_output_dir.mkdir(parents=True, exist_ok=True)
    write_json(source_output_dir / source.cache_filename, compact_source_records(records))


def load_cached_source_records(source_output_dir: Path | None, source: SourceSpec) -> list[dict]:
    if source_output_dir is None or not source.cache_filename:
        return []

    cached = load_json(source_output_dir / source.cache_filename)
    if not isinstance(cached, list):
        return []

    try:
        return expand_compact_source_records(source, cached)
    except (KeyError, TypeError, ValueError):
        return []


def load_phishtank_records(
    source: SourceSpec,
    api_key: str | None,
    fixture_path: Path | None,
    allow_small_fixture: bool,
) -> list[dict]:
    if fixture_path is not None:
        raw = load_json(fixture_path)
        if not isinstance(raw, list):
            raise ValueError("PhishTank fixture must be a JSON array")
    else:
        raw = fetch_phishtank(api_key or "")

    compact_records = transform_phishtank(raw)
    if len(compact_records) < source.min_records and not (fixture_path is not None and allow_small_fixture):
        raise ValueError(f"{source.source_id} produced only {len(compact_records)} records")

    return expand_compact_source_records(source, compact_records)


PARSERS: dict[str, Callable[[str, SourceSpec], list[dict]]] = {
    "npa_stopped_resolution": parse_npa_stopped_resolution,
    "moda_ecommerce_rpz": parse_moda_ecommerce_rpz,
    "npa_fake_investment": parse_npa_fake_investment,
}


def fingerprint_records(records: list[dict]) -> str:
    encoded = json.dumps(records, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:12]


def source_id_for(record: dict) -> str:
    if isinstance(record.get("_sourceID"), str) and record["_sourceID"]:
        return record["_sourceID"]

    source = {
        "riskLevel": record["riskLevel"],
        "sourceName": record["sourceName"],
        "sourceURL": record["sourceURL"],
        "category": record["category"],
    }
    digest = hashlib.sha256(json.dumps(source, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
    return f"src_{digest[:12]}"


def compact_dataset_records(records: list[dict]) -> tuple[list[dict], list[dict]]:
    sources_by_id: dict[str, dict] = {}
    compact_records = []

    for record in records:
        source_id = source_id_for(record)
        sources_by_id[source_id] = {
            "id": source_id,
            "riskLevel": record["riskLevel"],
            "sourceName": record["sourceName"],
            "sourceURL": record["sourceURL"],
            "category": record["category"],
        }

        compact_record = {
            "domain": record["domain"],
            "sourceID": source_id,
            "datasetDate": record["datasetDate"],
        }
        if record["pathPrefix"]:
            compact_record["pathPrefix"] = record["pathPrefix"]
        compact_records.append(compact_record)

    return sorted(sources_by_id.values(), key=lambda source: source["id"]), compact_records


def record_identities(dataset: object | None) -> set[tuple[str, str]]:
    if not isinstance(dataset, dict):
        return set()

    records = dataset.get("records")
    if not isinstance(records, list):
        return set()

    identities: set[tuple[str, str]] = set()
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("domain"), str):
            continue
        path_prefix = record.get("pathPrefix", "")
        if not isinstance(path_prefix, str):
            path_prefix = ""
        identities.add((record["domain"], path_prefix))
    return identities


def same_dataset_payload(existing: object | None, dataset: dict) -> bool:
    return (
        isinstance(existing, dict)
        and existing.get("schemaVersion") == dataset.get("schemaVersion")
        and existing.get("sources") == dataset.get("sources")
        and existing.get("records") == dataset.get("records")
    )


def enforce_record_drop_guard(existing: object | None, records: list[dict], max_drop_ratio: float) -> None:
    if not isinstance(existing, dict):
        return

    existing_records = existing.get("records")
    if not isinstance(existing_records, list) or not existing_records:
        return

    old_count = len(existing_records)
    new_count = len(records)
    if new_count >= old_count * (1 - max_drop_ratio):
        return

    drop_ratio = (old_count - new_count) / old_count
    raise ValueError(
        "record count dropped from "
        f"{old_count} to {new_count} ({drop_ratio:.1%}); "
        f"maximum allowed drop is {max_drop_ratio:.1%}"
    )


def enforce_source_drop_guard(
    publications: object | None,
    current_stats: dict,
    max_drop_ratio: float,
    allowed_sources: set[str],
) -> None:
    if not isinstance(publications, list) or not publications:
        return

    previous_stats = publications[0].get("sourceStats") if isinstance(publications[0], dict) else None
    if not isinstance(previous_stats, dict):
        return

    current_sources = current_stats.get("perSource")
    if not isinstance(current_sources, dict):
        return

    for source_id, current in current_sources.items():
        if source_id in allowed_sources or not isinstance(current, dict):
            continue

        previous = previous_stats.get(source_id)
        if not isinstance(previous, dict):
            continue

        old_count = previous.get("seen")
        new_count = current.get("seen")
        if not isinstance(old_count, int) or not isinstance(new_count, int) or old_count <= 0:
            continue
        if new_count >= old_count * (1 - max_drop_ratio):
            continue

        drop_ratio = (old_count - new_count) / old_count
        raise ValueError(
            f"{source_id} source records dropped from {old_count} to {new_count} "
            f"({drop_ratio:.1%}); maximum allowed drop is {max_drop_ratio:.1%}"
        )


def print_dedupe_sanity(stats: dict) -> None:
    per_source = stats.get("perSource")
    if not isinstance(per_source, dict):
        return

    phishtank_stats = per_source.get(PHISHTANK_SOURCE_ID)
    if not isinstance(phishtank_stats, dict):
        return

    seen = phishtank_stats.get("seen", 0)
    dropped = phishtank_stats.get("droppedDedupe", 0)
    if not isinstance(seen, int) or seen == 0 or not isinstance(dropped, int):
        return

    ratio = dropped / seen
    if ratio < 0.05:
        print(f"WARNING: PhishTank dedupe overlap is low ({ratio:.1%}); verify normalization if unexpected.")
    elif ratio > 0.5:
        print(f"WARNING: PhishTank dedupe overlap is high ({ratio:.1%}); review source value.")


def publication_entry(existing: object | None, dataset: dict, build_stats: dict | None = None) -> dict:
    old_records = record_identities(existing)
    new_records = record_identities(dataset)
    added_records = new_records - old_records
    removed_records = old_records - new_records

    entry = {
        "version": dataset["bundleVersion"],
        "publishedAt": dataset["fetchedAt"],
        "recordCount": len(dataset["records"]),
        "sourceCount": len(dataset.get("sources", [])),
        "addedRecords": len(added_records),
        "removedRecords": len(removed_records),
    }
    if build_stats:
        entry["sourceStats"] = build_stats.get("perSource", {})
        entry["dedupeStats"] = {
            "totalSeen": build_stats.get("totalSeen", 0),
            "deduped": build_stats.get("deduped", 0),
        }
    return entry


def render_changelog(publications: list[dict]) -> str:
    lines = ["# LinkProof Dataset Changelog", ""]
    if not publications:
        lines.append("No dataset publications recorded yet.")
        return "\n".join(lines) + "\n"

    for entry in publications:
        lines.append(f"## {entry['version']} - {entry['publishedAt']}")
        lines.append("")
        lines.append(f"- Records: {entry['recordCount']:,}")
        lines.append(f"- Sources: {entry['sourceCount']:,}")
        lines.append(f"- Added records: {entry['addedRecords']:,}")
        lines.append(f"- Removed records: {entry['removedRecords']:,}")
        dedupe_stats = entry.get("dedupeStats")
        if isinstance(dedupe_stats, dict):
            total_seen = dedupe_stats.get("totalSeen", 0)
            deduped = dedupe_stats.get("deduped", 0)
            if isinstance(total_seen, int) and isinstance(deduped, int) and total_seen:
                lines.append(f"- Dedupe: {deduped:,} of {total_seen:,} source records")
        source_stats = entry.get("sourceStats")
        if isinstance(source_stats, dict) and source_stats:
            source_lines = []
            for source_id, stats in sorted(source_stats.items()):
                if isinstance(stats, dict) and isinstance(stats.get("seen"), int) and isinstance(stats.get("kept"), int):
                    source_lines.append(f"{source_id} {stats['kept']:,}/{stats['seen']:,}")
            if source_lines:
                lines.append(f"- Source kept/seen: {', '.join(source_lines)}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def update_release_artifacts(
    publications_path: Path,
    changelog_path: Path,
    existing: object | None,
    dataset: dict,
    build_stats: dict | None = None,
) -> None:
    loaded_publications = load_json(publications_path)
    publications = loaded_publications if isinstance(loaded_publications, list) else []
    publications = [entry for entry in publications if isinstance(entry, dict)]

    dataset_changed = not same_dataset_payload(existing, dataset)
    has_current_entry = any(entry.get("version") == dataset["bundleVersion"] for entry in publications)
    if not dataset_changed and has_current_entry and changelog_path.exists():
        return

    baseline = existing if dataset_changed else None
    current_entry = publication_entry(baseline, dataset, build_stats)
    publications = [entry for entry in publications if entry.get("version") != current_entry["version"]]
    publications.insert(0, current_entry)

    write_json(publications_path, publications)
    changelog_path.write_text(render_changelog(publications), encoding="utf-8", newline="\n")


def build_dataset(
    output_path: Path,
    timeout: int,
    fetched_at: str | None,
    max_record_drop_ratio: float,
    publications_path: Path,
    allow_source_drop: set[str],
    phishtank_api_key: str | None,
    phishtank_fixture: Path | None,
    allow_small_phishtank_fixture: bool,
    skip_phishtank: bool,
    source_output_dir: Path | None,
) -> tuple[dict, dict]:
    source_records: list[tuple[SourceSpec, list[dict]]] = []
    for source in SOURCES:
        text = fetch_text(source.raw_url, timeout)
        parser = PARSERS[source.parser]
        records = parser(text, source)
        if len(records) < source.min_records:
            raise ValueError(f"{source.source_id} produced only {len(records)} records")
        print(f"{source.source_id}: {len(records)} raw records")
        write_source_cache(source_output_dir, source, records)
        source_records.append((source, records))

    if skip_phishtank:
        print("src_phishtank: skipped by --skip-phishtank")
    else:
        try:
            records = load_phishtank_records(
                PHISHTANK_SOURCE,
                phishtank_api_key,
                phishtank_fixture,
                allow_small_phishtank_fixture,
            )
        except Exception as error:
            if phishtank_fixture is not None:
                raise
            cached_records = load_cached_source_records(source_output_dir, PHISHTANK_SOURCE)
            if cached_records:
                print(
                    f"WARNING: {PHISHTANK_SOURCE.source_id} feed could not be fetched; "
                    f"using {len(cached_records)} cached records: {error}"
                )
                source_records.append((PHISHTANK_SOURCE, cached_records))
            else:
                print(f"WARNING: {PHISHTANK_SOURCE.source_id} skipped because the feed could not be fetched: {error}")
        else:
            print(f"{PHISHTANK_SOURCE.source_id}: {len(records)} raw records")
            write_source_cache(source_output_dir, PHISHTANK_SOURCE, records)
            source_records.append((PHISHTANK_SOURCE, records))

    records, stats = merge_records(source_records)
    if not records:
        raise ValueError("no usable records were produced")

    sources, compact_records = compact_dataset_records(records)

    existing = load_json(output_path)
    enforce_record_drop_guard(existing, compact_records, max_record_drop_ratio)
    enforce_source_drop_guard(load_json(publications_path), stats, max_record_drop_ratio, allow_source_drop)
    print_dedupe_sanity(stats)
    if (
        isinstance(existing, dict)
        and existing.get("schemaVersion") == 2
        and existing.get("sources") == sources
        and existing.get("records") == compact_records
    ):
        bundle_version = str(existing.get("bundleVersion"))
        effective_fetched_at = str(existing.get("fetchedAt"))
    else:
        effective_fetched_at = fetched_at or utc_now()
        date_part = taipei_date_part(effective_fetched_at)
        bundle_version = f"{date_part}.gov2.{fingerprint_records(records)}"

    dataset = {
        "schemaVersion": 2,
        "bundleVersion": bundle_version,
        "fetchedAt": effective_fetched_at,
        "sources": sources,
        "records": compact_records,
    }
    print(
        f"merged: {len(records)} records, {len(sources)} sources, "
        f"{stats.get('deduped', 0)} deduped, version {bundle_version}"
    )
    return dataset, stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the LinkProof public dataset from official Taiwan open-data sources.")
    parser.add_argument("--output", default="scam-datasets.json", type=Path)
    parser.add_argument("--timeout", default=60, type=int)
    parser.add_argument("--fetched-at", default=None)
    parser.add_argument("--changelog", default="CHANGELOG.md", type=Path)
    parser.add_argument("--publications", default="publications.json", type=Path)
    parser.add_argument("--max-record-drop-ratio", default=0.2, type=float)
    parser.add_argument("--allow-source-drop", action="append", default=[])
    parser.add_argument("--phishtank-api-key", default=os.environ.get("PHISHTANK_API_KEY"))
    parser.add_argument("--phishtank-fixture", default=None, type=Path)
    parser.add_argument("--allow-small-phishtank-fixture", action="store_true")
    parser.add_argument("--skip-phishtank", action="store_true")
    parser.add_argument("--source-output-dir", default="sources", type=Path)
    args = parser.parse_args()

    if args.max_record_drop_ratio < 0 or args.max_record_drop_ratio > 1:
        parser.error("--max-record-drop-ratio must be between 0 and 1")

    existing = load_json(args.output)
    dataset, stats = build_dataset(
        args.output,
        args.timeout,
        args.fetched_at,
        args.max_record_drop_ratio,
        args.publications,
        set(args.allow_source_drop),
        args.phishtank_api_key,
        args.phishtank_fixture,
        args.allow_small_phishtank_fixture,
        args.skip_phishtank,
        args.source_output_dir,
    )
    write_json(args.output, dataset)
    update_release_artifacts(args.publications, args.changelog, existing, dataset, stats)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        sys.exit(f"dataset build failed: {error}")
