#!/usr/bin/env python3
"""Domain and path normalization shared by dataset source importers.

This intentionally mirrors the mobile app DomainPolicy rules: lowercasing,
IDN ASCII conversion, www stripping, blocked public-suffix records, and the
same dataset-domain validation envelope.
"""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import unquote, urlparse

import idna


BLOCKED_PUBLIC_SUFFIXES = {
    "com.tw",
    "net.tw",
    "org.tw",
    "edu.tw",
    "gov.tw",
    "mil.tw",
    "idv.tw",
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "co.jp",
    "ne.jp",
    "or.jp",
    "com.au",
    "net.au",
    "org.au",
    "co.kr",
    "or.kr",
}


def normalize_dataset_domain(url_or_domain: str | None) -> str | None:
    """Return a normalized ASCII dataset domain, or None when invalid."""
    if not url_or_domain:
        return None

    candidate = url_or_domain.strip().strip("\"'`")
    candidate = candidate.replace("\u3000", "").replace(" ", "")
    candidate = candidate.removeprefix("*.").removeprefix(".")
    if not candidate:
        return None

    host = _extract_host(candidate)
    if not host:
        return None

    host = host.strip().strip(".").lower()
    if not host:
        return None

    labels = host.split(".")
    if any(not label for label in labels):
        return None

    try:
        ascii_host = ".".join(_to_ascii_label(label) for label in labels)
    except (UnicodeError, idna.IDNAError):
        return None

    if len(ascii_host) > 253:
        return None

    if ascii_host.startswith("www.") and len(ascii_host) > 4:
        ascii_host = ascii_host[4:]

    if not is_valid_dataset_domain(ascii_host):
        return None
    return ascii_host


def normalize_dataset_path(path_prefix: str | None) -> str | None:
    if path_prefix is None:
        return ""

    trimmed = path_prefix.strip()
    if not trimmed:
        return ""

    candidate = trimmed if trimmed.startswith("/") else f"/{trimmed}"
    try:
        return unquote(candidate, encoding="utf-8", errors="strict")
    except UnicodeDecodeError:
        return None


def normalize_path_for_comparison(path: str) -> str:
    try:
        return unquote(path, encoding="utf-8", errors="strict")
    except UnicodeDecodeError:
        return path


def is_valid_dataset_domain(domain: str) -> bool:
    labels = domain.split(".")
    if len(labels) < 2 or any(not label for label in labels) or domain in BLOCKED_PUBLIC_SUFFIXES:
        return False

    top_level_domain = labels[-1]
    if not _is_valid_top_level_domain(top_level_domain):
        return False

    return all(_is_valid_ascii_label(label) for label in labels)


def _extract_host(candidate: str) -> str | None:
    if "://" in candidate:
        try:
            return urlparse(candidate).hostname
        except ValueError:
            return None

    if any(separator in candidate for separator in ["/", "?", "#"]):
        try:
            return urlparse(f"https://{candidate}").hostname
        except ValueError:
            return None

    return candidate


def _to_ascii_label(label: str) -> str:
    prepared = unicodedata.normalize("NFKC", label.lower()).replace("ß", "ss")
    if all(ord(character) < 0x80 for character in prepared):
        if not _is_valid_ascii_label(prepared):
            raise UnicodeError("invalid ASCII label")
        return prepared
    return idna.encode(prepared).decode("ascii").lower()


def _is_valid_top_level_domain(label: str) -> bool:
    if not 2 <= len(label) <= 24:
        return False
    if label.startswith("xn--"):
        return _is_valid_ascii_label(label)
    return bool(re.fullmatch(r"[a-z]+", label))


def _is_valid_ascii_label(label: str) -> bool:
    return (
        1 <= len(label) <= 63
        and not label.startswith("-")
        and not label.endswith("-")
        and bool(re.fullmatch(r"[a-z0-9-]+", label))
    )
