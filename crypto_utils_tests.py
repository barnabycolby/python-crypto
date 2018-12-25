#! /usr/bin/env python3
import crypto_utils
import pytest

def test_english_language_score():
    english_score = crypto_utils.calculate_english_language_score("a tribe called quest")
    gibberish_score = crypto_utils.calculate_english_language_score("yrwepohofdhaurhewopquio reuiwo fdaoisfdsafdsafsdaafs reoirweurweoih")

    assert english_score > gibberish_score


def test_hamming_distance():
    expected = 37
    actual = crypto_utils.hamming_distance(b"this is a test", b"wokka wokka!!!")
    assert expected == actual


def test_get_block():
    ciphertext = b"AABBCCDDEEFF"
    assert crypto_utils.get_block(ciphertext, 2, 2) == b"CC"
    assert crypto_utils.get_block(ciphertext, 4, 1) == b"CCDD"
    assert crypto_utils.get_block(ciphertext, 2, 0) == b"AA"


def test_split_into_blocks():
    ciphertext = b"AABBCCDDEEFF"
    expected = [b"AA", b"BB", b"CC", b"DD", b"EE", b"FF"]
    actual = crypto_utils.split_into_blocks(ciphertext, 2)
    assert expected == actual


def test_pkcs7_pad_incomplete_block():
    """
    Taken from cryptopals set 2 challenge 9.
    """
    block_length = 20
    incomplete_block = b"A" * block_length + b"YELLOW SUBMARINE"
    expected = incomplete_block + b"\x04\x04\x04\x04"
    actual = crypto_utils.pkcs7_pad(incomplete_block, block_length)
    assert expected == actual


def test_pkcs7_pad_full_block():
    block_length = 16
    block = b"A" * block_length + b"YELLOW SUBMARINE"
    expected = block + b"\x10" * block_length
    actual = crypto_utils.pkcs7_pad(block, block_length)
    assert expected == actual


def test_pkcs7_unpad_incomplete_block():
    block_length = 20
    expected = b"A" * block_length + b"YELLOW SUBMARINE"
    padded_block = expected + b"\x04\x04\x04\x04"
    actual = crypto_utils.pkcs7_unpad(padded_block, block_length)
    assert expected == actual


def test_pkcs7_unpad_full_block():
    block_length = 16
    expected = b"A" * block_length + b"YELLOW SUBMARINE"
    padded_block = expected + b"\x10" * 0x10
    actual = crypto_utils.pkcs7_unpad(padded_block, block_length)
    assert expected == actual


def test_pkcs7_unpad_invalid():
    block_length = 16

    with pytest.raises(Exception):
        crypto_utils.pkcs7_unpad(b"ICE ICE BABY\x05\x05\x05\x05", block_length)

    with pytest.raises(Exception):
        crypto_utils.pkcs7_unpad(b"ICE ICE BABY\x01\x02\x03\x04", block_length)
