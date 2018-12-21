#! /usr/bin/env python3
import ciphers
import os
from converter import Converter

def test_xor_bytes():
    expected = b"\xbb\x99\xff\x99\xbb\x99"
    actual = ciphers.xor_bytes(b"\xaa\xbb\xcc\xdd\xee\xff", b"\x11\x22\x33\x44\x55\x66")
    assert expected == actual


def test_xor_single_bytes():
    expected = b"\xbb\x88\x99\xee\xff\xcc"
    actual = ciphers.xor_single_byte(0xaa, b"\x11\x22\x33\x44\x55\x66")
    assert expected == actual


def test_xor_repeating_key_bytes():
    """
    Taken from cryptopals set 1 challenge 5.
    """
    plaintext = ("Burning 'em, if you ain't quick and nimble\n"
                 "I go crazy when I hear a cymbal")
    plaintext_bytes = Converter(plaintext).bytes()
    ciphertext_bytes = ciphers.xor_repeating_key_bytes(plaintext_bytes, b"ICE")
    ciphertext_hex = Converter(ciphertext_bytes).hex()

    expected = ("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2622632427276527"
                "2a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
    assert expected == ciphertext_hex


def test_aes_ecb_128_round_trip():
    plaintext = ("Burning 'em, if you ain't quick and nimble\n"
                 "I go crazy when I hear a cymbal")
    plaintext_bytes = Converter(plaintext).bytes()

    key = os.urandom(16)
    round_trip_ciphertext = ciphers.encrypt_aes_ecb_128(plaintext_bytes, key)
    round_trip_plaintext = ciphers.decrypt_aes_ecb_128(round_trip_ciphertext, key)

    assert plaintext_bytes == round_trip_plaintext
