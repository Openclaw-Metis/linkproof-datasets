import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from spike_urlhaus_overlap import compute_overlap, domains_from_urlhaus_text


def test_domains_from_urlhaus_text_normalizes_urls_and_idn():
    fixture_path = Path(__file__).resolve().parent / "fixtures" / "urlhaus_text_sample.txt"
    domains = domains_from_urlhaus_text(fixture_path.read_text(encoding="utf-8"))

    assert domains == {
        "official.example",
        "malware-only.example",
        "xn--fsqu00a.xn--fiqs8s",
    }


def test_compute_overlap_reports_hit_rate():
    result = compute_overlap(
        ["official.example", "phish-only.example"],
        {"official.example", "malware-only.example"},
    )

    assert result["sampleCount"] == 2
    assert result["urlhausDomainCount"] == 2
    assert result["hitCount"] == 1
    assert result["hitRate"] == 0.5
    assert result["hits"] == ["official.example"]
