import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from build_dataset import (
    PHISHTANK_SOURCE,
    contains_known_legitimate_domain_only_record,
    enforce_known_legitimate_domain_guard,
    normalize_url_with_path,
)


def test_known_legitimate_domain_only_record_fails_build():
    sources = [
        {
            "id": "src_phishtank",
            "riskLevel": "highRisk",
            "sourceName": {"zhTW": "PhishTank", "enUS": "PhishTank"},
            "sourceURL": "https://www.phishtank.com/",
            "category": {"zhTW": "釣魚網站", "enUS": "Phishing site"},
        }
    ]
    records = [
        {
            "domain": "google.com",
            "sourceID": "src_phishtank",
            "datasetDate": "2026-05-17",
        }
    ]

    with pytest.raises(ValueError, match="google.com"):
        enforce_known_legitimate_domain_guard(sources, records)


def test_known_legitimate_path_record_is_allowed():
    sources = [
        {
            "id": "src_phishtank",
            "riskLevel": "highRisk",
            "sourceName": {"zhTW": "PhishTank", "enUS": "PhishTank"},
            "sourceURL": "https://www.phishtank.com/",
            "category": {"zhTW": "釣魚網站", "enUS": "Phishing site"},
        }
    ]
    records = [
        {
            "domain": "google.com",
            "pathPrefix": "/forms/d",
            "sourceID": "src_phishtank",
            "datasetDate": "2026-05-17",
        }
    ]

    enforce_known_legitimate_domain_guard(sources, records)


def test_url_source_preserves_path_prefix():
    assert normalize_url_with_path("https://play.google.com/store/apps/details?id=bad") == (
        "play.google.com",
        "/store/apps",
    )


def test_unsafe_phishtank_cache_is_detected():
    assert contains_known_legitimate_domain_only_record(
        PHISHTANK_SOURCE,
        [
            {
                "domain": "accounts.google.com",
                "pathPrefix": "",
                "riskLevel": "highRisk",
            }
        ],
    )


def test_path_aware_phishtank_cache_is_allowed():
    assert not contains_known_legitimate_domain_only_record(
        PHISHTANK_SOURCE,
        [
            {
                "domain": "accounts.google.com",
                "pathPrefix": "/signin/v2",
                "riskLevel": "highRisk",
            }
        ],
    )
