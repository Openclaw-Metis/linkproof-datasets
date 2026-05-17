import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from fetch_phishtank import PHISHTANK_SOURCE_ID, transform


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
