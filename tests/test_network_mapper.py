"""Regression tests for network range parsing."""

import ipaddress

import pytest

from recon.network_mapper import parse_range


def test_parse_range_accepts_documented_full_ipv4_endpoints():
    assert parse_range("192.168.1.1-192.168.1.3") == [
        "192.168.1.1",
        "192.168.1.2",
        "192.168.1.3",
    ]


def test_parse_range_preserves_ipv4_last_octet_shorthand():
    assert parse_range("192.168.1.1-3") == [
        "192.168.1.1",
        "192.168.1.2",
        "192.168.1.3",
    ]


def test_parse_range_accepts_ipv6_endpoints():
    assert parse_range("2001:db8::1-2001:db8::3") == [
        "2001:db8::1",
        "2001:db8::2",
        "2001:db8::3",
    ]


def test_parse_range_rejects_descending_ranges():
    with pytest.raises(ValueError, match="start must not be greater"):
        parse_range("192.168.1.3-192.168.1.1")


def test_parse_range_rejects_mixed_ip_versions():
    with pytest.raises(ValueError, match="same IP version"):
        parse_range("192.168.1.1-2001:db8::1")
