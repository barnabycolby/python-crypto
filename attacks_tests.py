#! /usr/bin/env python3
import attacks
import base64
import ciphers
import os
from converter import Converter
from Crypto.Cipher import AES
from Crypto.Util import Padding

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


def test_detect_ecb_mode():
    """
    Taken from cryptopals set 1 challenge 8.
    """
    ecb_ciphertext_hex = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"
    ecb_ciphertext = Converter(ecb_ciphertext_hex, input_type="hex").bytes()
    assert attacks.detect_ecb_mode(ecb_ciphertext, 16)

    non_ecb_ciphertext_hex = "8a10247f90d0a05538888ad6205882196f5f6d05c21ec8dca0cb0be02c3f8b09e382963f443aa514daa501257b09a36bf8c4c392d8ca1bf4395f0d5f2542148c7e5ff22237969874bf66cb85357ef99956accf13ba1af36ca7a91a50533c4d89b7353f908c5a166774293b0bf6247391df69c87dacc4125a99ec417221b58170e633381e3847c6b1c28dda2913c011e13fc4406f8fe73bbf78e803e1d995ce4d"
    non_ecb_ciphertext = Converter(non_ecb_ciphertext_hex, input_type="hex").bytes()
    assert not attacks.detect_ecb_mode(non_ecb_ciphertext, 16)


def test_find_block_size():
    block_size = 16
    key = os.urandom(block_size)

    def oracle(plaintext):
        extended_plaintext = Padding.pad(b"AAAAA" + plaintext, block_size)
        encryptor = AES.new(key, AES.MODE_ECB)
        return encryptor.encrypt(extended_plaintext)

    assert block_size == attacks.find_block_size(oracle)


def test_find_cipher_secret_size():
    block_size = 16
    key = os.urandom(block_size)
    secret_length = 22

    def oracle(plaintext):
        extended_plaintext = Padding.pad(b"A" * secret_length + plaintext, block_size)
        encryptor = AES.new(key, AES.MODE_ECB)
        return encryptor.encrypt(extended_plaintext)

    assert secret_length == attacks.find_cipher_secret_size(oracle)


def test_find_cipher_prefix_size():
    block_size = 16
    key = os.urandom(block_size)
    prefix = b"ABCDEFGHIJK" # 11
    secret = b"TRGT"

    def oracle(plaintext):
        extended_plaintext = Padding.pad(prefix + plaintext + secret, block_size)
        encryptor = AES.new(key, AES.MODE_ECB)
        return encryptor.encrypt(extended_plaintext)

    assert len(prefix) == attacks.find_cipher_prefix_size(oracle)


def test_decrypt_ecb_appended_secret():
    block_size = 16
    key = os.urandom(block_size)
    secret = b"SECRET_KEY_THAT_IS_LONGER_THAN_THE_BLOCK_SIZE"

    def oracle(plaintext):
        extended_plaintext = Padding.pad(plaintext + secret, block_size)
        encryptor = AES.new(key, AES.MODE_ECB)
        return encryptor.encrypt(extended_plaintext)

    assert secret == attacks.decrypt_ecb_appended_secret(oracle)


def read_file_bytes(path):
    with open(path, "rb") as the_file:
        return the_file.read()
