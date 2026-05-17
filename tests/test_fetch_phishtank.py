import json
import gzip
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from fetch_phishtank import (
    PHISHTANK_PUBLIC_CSV_GZ_URL,
    PHISHTANK_PUBLIC_URL,
    PHISHTANK_SOURCE_ID,
    USER_AGENT,
    _parse_payload,
    phishtank_feed_candidates,
    phishtank_feed_url,
    transform,
)


def test_feed_url_uses_public_dump_without_api_key():
    url, mode = phishtank_feed_url(None)
    candidates = phishtank_feed_candidates(None)

    assert url == PHISHTANK_PUBLIC_URL
    assert mode == "public"
    assert [candidate.url for candidate in candidates] == [
        PHISHTANK_PUBLIC_URL,
        PHISHTANK_PUBLIC_CSV_GZ_URL,
    ]


def test_feed_url_uses_keyed_dump_when_api_key_is_available():
    url, mode = phishtank_feed_url("test-key")

    assert url == "https://data.phishtank.com/data/test-key/online-valid.json.bz2"
    assert mode == "keyed"


def test_user_agent_is_descriptive():
    assert "LinkProofDatasetBuilder" in USER_AGENT
    assert "Openclaw-Metis/linkproof-datasets" in USER_AGENT


def test_parse_csv_gz_payload_matches_phishtank_columns():
    csv_payload = (
        "phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target\n"
        "123,https://example.com/login,http://example.test/detail,2026-05-17T00:00:00+00:00,"
        "yes,2026-05-17T01:00:00+00:00,yes,Example\n"
    )

    records = _parse_payload(gzip.compress(csv_payload.encode("utf-8")), "csv-gz")

    assert records == [
        {
            "phish_id": "123",
            "url": "https://example.com/login",
            "phish_detail_url": "http://example.test/detail",
            "submission_time": "2026-05-17T00:00:00+00:00",
            "verified": "yes",
            "verification_time": "2026-05-17T01:00:00+00:00",
            "online": "yes",
            "target": "Example",
        }
    ]


def test_transform_keeps_verified_online_domains_only():
    fixture_path = Path(__file__).resolve().parent / "fixtures" / "phishtank_sample.json"
    raw_records = json.loads(fixture_path.read_text(encoding="utf-8"))

    records = transform(raw_records)

    assert records == [
        {
            "domain": "phish-only.example",
            "pathPrefix": "",
            "sourceID": PHISHTANK_SOURCE_ID,
            "datasetDate": "2026-05-17",
        },
        {
            "domain": "xn--fsqu00a.xn--fiqs8s",
            "pathPrefix": "",
            "sourceID": PHISHTANK_SOURCE_ID,
            "datasetDate": "2026-05-17",
        },
    ]
