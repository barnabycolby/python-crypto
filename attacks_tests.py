#! /usr/bin/env python3
import attacks
import ciphers
from converter import Converter

def test_find_single_byte_xor_key():
    """
    Taken from cryptopals set 1 challenge 3.
    """
    ciphertext_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    expected_plaintext = "Cooking MC's like a pound of bacon"

    ciphertext_bytes = Converter(ciphertext_hex, input_type="hex").bytes()
    guessed_key = attacks.find_single_byte_xor_key(ciphertext_bytes)
    plaintext_bytes = ciphers.xor_single_byte(guessed_key, ciphertext_bytes)
    actual_plaintext = Converter(plaintext_bytes).string()

    assert expected_plaintext == actual_plaintext
