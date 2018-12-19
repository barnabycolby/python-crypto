#! /usr/bin/env python3
from converter import Converter

def test_bytes_to_hex():
    expected = "2f5b0124"
    actual = Converter(b"\x2f\x5b\x01\x24").hex()
    assert expected == actual


def test_hex_to_bytes():
    expected = b"\x2f\x5b\x01\x24"
    actual = Converter("2f5b0124", input_type="hex").bytes()
    assert expected == actual


def test_bytes_to_base64():
    expected = "L1sBJA=="
    actual = Converter(b"\x2f\x5b\x01\x24").base64()
    assert expected == actual


def test_base64_to_bytes():
    expected = b"\x2f\x5b\x01\x24"
    actual = Converter("L1sBJA==", input_type="base64").bytes()
    assert expected == actual


def test_string_to_bytes():
    expected = b"writing_tests"
    actual = Converter("writing_tests").bytes()
    assert expected == actual


def test_bytes_to_string():
    expected = "writing_tests"
    actual = Converter(b"writing_tests").string()
    assert expected == actual


def test_bytes_to_bits():
    expected = "01110111011100100110100101110100011010010110111001100111010111110111010001100101011100110111010001110011"
    actual = Converter(b"writing_tests").bits()
    assert expected == actual
