#! /usr/bin/env python3
import attacks
import base64
import ciphers
import os
from converter import Converter

TEST_FILES = "test_files"

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


def test_find_repeating_xor_key():
    """
    Taken from cryptopals set 1 challenge 6.
    """
    ciphertext_file_path = os.path.join(TEST_FILES, "repeating_xor_ciphertext.txt")
    ciphertext_base64 = read_file_bytes(ciphertext_file_path)
    ciphertext_bytes = base64.b64decode(ciphertext_base64)

    plaintext_file_path = os.path.join(TEST_FILES, "repeating_xor_plaintext.txt")
    expected_plaintext = read_file_bytes(plaintext_file_path)

    guessed_key = attacks.find_repeating_xor_key(ciphertext_bytes)
    actual_plaintext = ciphers.xor_repeating_key_bytes(ciphertext_bytes, guessed_key)

    assert expected_plaintext == actual_plaintext


def read_file_bytes(path):
    with open(path, "rb") as the_file:
        return the_file.read()
