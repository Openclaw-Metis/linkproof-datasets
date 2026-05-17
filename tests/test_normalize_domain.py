import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from normalize_domain import normalize_dataset_domain, normalize_dataset_path


def test_idn_punycode():
    assert normalize_dataset_domain("https://例子.中国") == "xn--fsqu00a.xn--fiqs8s"


def test_nameprep_sharp_s_matches_mobile_policy():
    assert normalize_dataset_domain("https://straße.example") == "strasse.example"


def test_blocked_public_suffix():
    assert normalize_dataset_domain("com.tw") is None


def test_invalid_url():
    assert normalize_dataset_domain("not a url") is None


def test_strips_www():
    assert normalize_dataset_domain("https://www.example.com/foo") == "example.com"


def test_normalizes_dataset_path():
    assert normalize_dataset_path("%E4%BB%98%E6%AC%BE") == "/付款"
