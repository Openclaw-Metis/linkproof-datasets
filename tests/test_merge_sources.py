import json
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from merge_sources import merge_records, merge_sources


def record(domain, source_id, risk_level="confirmedScam", dataset_date="2026-05-17"):
    return {
        "domain": domain,
        "pathPrefix": "",
        "riskLevel": risk_level,
        "sourceName": {"zhTW": source_id, "enUS": source_id},
        "sourceURL": "https://example.com",
        "datasetDate": dataset_date,
        "category": {"zhTW": source_id, "enUS": source_id},
        "_sourceID": source_id,
    }


def test_official_wins_over_phishtank():
    official = SimpleNamespace(source_id="src_official", priority=300)
    phishtank = SimpleNamespace(source_id="src_phishtank", priority=100)

    merged, stats = merge_records(
        [
            (official, [record("example.com", "src_official", "confirmedScam")]),
            (phishtank, [record("example.com", "src_phishtank", "highRisk")]),
        ]
    )

    assert len(merged) == 1
    assert merged[0]["_sourceID"] == "src_official"
    assert stats["perSource"]["src_phishtank"]["droppedDedupe"] == 1


def test_phishtank_unique_kept():
    official = SimpleNamespace(source_id="src_official", priority=300)
    phishtank = SimpleNamespace(source_id="src_phishtank", priority=100)

    merged, stats = merge_records(
        [
            (official, [record("official.example", "src_official", "confirmedScam")]),
            (phishtank, [record("phish-only.example", "src_phishtank", "highRisk")]),
        ]
    )

    assert [item["domain"] for item in merged] == ["official.example", "phish-only.example"]
    assert stats["perSource"]["src_phishtank"]["kept"] == 1


def test_merge_sources_priority_order_fixture_shape():
    merged, _ = merge_sources(
        [
            ("src_official", [{"domain": "official.example", "pathPrefix": "", "riskLevel": "confirmedScam", "datasetDate": "2026-05-17"}]),
            ("src_phishtank", [{"domain": "official.example", "pathPrefix": "", "riskLevel": "highRisk", "datasetDate": "2026-05-17"}]),
        ]
    )

    assert len(merged) == 1


def test_expected_merged_fixture_documents_output_order():
    fixture_path = Path(__file__).resolve().parent / "fixtures" / "expected_merged.json"
    assert json.loads(fixture_path.read_text(encoding="utf-8"))[1]["sourceID"] == "src_phishtank"
