"""Input validation tests for the TCP port scanner."""
import argparse
import math

import pytest

from recon.port_scanner import parse_ports, positive_float, positive_int


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("22,80,443", [22, 80, 443]),
        ("80,22,80", [22, 80]),
        ("100-102,22", [22, 100, 101, 102]),
        (" 22 , 80 ", [22, 80]),
    ],
)
def test_parse_ports_valid_inputs(value, expected):
    assert parse_ports(value) == expected


@pytest.mark.parametrize(
    "value",
    ["", " ", ",22", "22,", "22,,80", "0", "65536", "-1", "80-70", "1-65536", "a", "1-2-3"],
)
def test_parse_ports_rejects_invalid_inputs(value):
    with pytest.raises(ValueError):
        parse_ports(value)


@pytest.mark.parametrize("value", ["0", "-1", "1.5", "nan", "inf", "abc"])
def test_positive_int_rejects_invalid_values(value):
    with pytest.raises(argparse.ArgumentTypeError):
        positive_int(value)


@pytest.mark.parametrize("value", ["0", "-0.1", "nan", "inf", "-inf", "abc"])
def test_positive_float_rejects_invalid_values(value):
    with pytest.raises(argparse.ArgumentTypeError):
        positive_float(value)


def test_positive_float_accepts_finite_positive_timeout():
    assert math.isclose(positive_float("0.25"), 0.25)


def test_positive_int_accepts_positive_thread_count():
    assert positive_int("8") == 8
