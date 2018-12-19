#! /usr/bin/env python3
import crypto_utils

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
    incomplete_block = b"YELLOW SUBMARINE"
    expected = b"YELLOW SUBMARINE\x04\x04\x04\x04"
    actual = crypto_utils.pkcs7_pad(incomplete_block, 20)
    assert expected == actual


def test_pkcs7_pad_full_block():
    block = b"YELLOW SUBMARINE"
    expected = b"YELLOW SUBMARINE" + b"\x10" * 0x10
    actual = crypto_utils.pkcs7_pad(block, 16)
    assert expected == actual


def test_pkcs7_unpad_incomplete_block():
    padded_block = b"YELLOW SUBMARINE\x04\x04\x04\x04"
    expected = b"YELLOW SUBMARINE"
    actual = crypto_utils.pkcs7_unpad(padded_block, 20)
    assert expected == actual


def test_pkcs7_unpad_full_block():
    padded_block = b"YELLOW SUBMARINE" + b"\x10" * 0x10
    expected = b"YELLOW SUBMARINE"
    actual = crypto_utils.pkcs7_unpad(padded_block, 16)
    assert expected == actual
