#!/usr/bin/env python3
"""Merge normalized LinkProof source records with deterministic priority rules."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Iterable


RISK_PRIORITY = {
    "confirmedScam": 3,
    "highRisk": 2,
    "needsVerification": 1,
    "noPublicReport": 0,
}


def record_sort_key(record: dict) -> tuple[str, str]:
    return (record["domain"], record.get("pathPrefix", ""))


def should_replace(existing: dict, incoming: dict, existing_priority: int, incoming_priority: int) -> bool:
    existing_risk = RISK_PRIORITY[existing["riskLevel"]]
    incoming_risk = RISK_PRIORITY[incoming["riskLevel"]]
    if incoming_risk != existing_risk:
        return incoming_risk > existing_risk
    if incoming_priority != existing_priority:
        return incoming_priority > existing_priority
    return incoming["datasetDate"] > existing["datasetDate"]


def merge_records(source_records: Iterable[tuple[object, list[dict]]]) -> tuple[list[dict], dict]:
    merged: dict[tuple[str, str], tuple[dict, int, str]] = {}
    stats = {"totalSeen": 0, "deduped": 0, "perSource": {}}

    for source, records in source_records:
        source_id = _source_id(source)
        priority = _priority(source)
        per_source = stats["perSource"].setdefault(
            source_id,
            {"seen": 0, "kept": 0, "droppedDedupe": 0},
        )

        for record in records:
            stats["totalSeen"] += 1
            per_source["seen"] += 1
            key = (record["domain"], record.get("pathPrefix", ""))
            current = merged.get(key)
            if current is None or should_replace(current[0], record, current[1], priority):
                merged[key] = (record, priority, source_id)

    winners_by_source: dict[str, int] = {}
    for _, _, source_id in merged.values():
        winners_by_source[source_id] = winners_by_source.get(source_id, 0) + 1

    for source_id, per_source in stats["perSource"].items():
        per_source["kept"] = winners_by_source.get(source_id, 0)
        per_source["droppedDedupe"] = per_source["seen"] - per_source["kept"]

    records = sorted((record for record, _, _ in merged.values()), key=record_sort_key)
    stats["deduped"] = stats["totalSeen"] - len(records)
    return records, stats


def merge_sources(sources_by_priority: list[tuple[str, list[dict]]]) -> tuple[list[dict], dict]:
    source_records = [
        (SimpleNamespace(source_id=source_id, priority=len(sources_by_priority) - index), records)
        for index, (source_id, records) in enumerate(sources_by_priority)
    ]
    return merge_records(source_records)


def _source_id(source: object) -> str:
    value = getattr(source, "source_id", None)
    if isinstance(value, str) and value:
        return value
    return str(source)


def _priority(source: object) -> int:
    value = getattr(source, "priority", 0)
    return int(value)
