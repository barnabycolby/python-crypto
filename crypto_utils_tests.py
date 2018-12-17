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
