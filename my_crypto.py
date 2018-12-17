#!/usr/bin/env python3
import base64
import sys

CHARACTER_FREQUENCIES = {
    'a': 0.0651738,
    'b': 0.0124248,
    'c': 0.0217339,
    'd': 0.0349835,
    'e': 0.1041442,
    'f': 0.0197881,
    'g': 0.0158610,
    'h': 0.0492888,
    'i': 0.0558094,
    'j': 0.0009033,
    'k': 0.0050529,
    'l': 0.0331490,
    'm': 0.0202124,
    'n': 0.0564513,
    'o': 0.0596302,
    'p': 0.0137645,
    'q': 0.0008606,
    'r': 0.0497563,
    's': 0.0515760,
    't': 0.0729357,
    'u': 0.0225134,
    'v': 0.0082903,
    'w': 0.0171272,
    'x': 0.0013692,
    'y': 0.0145984,
    'z': 0.0007836,
    ' ': 0.1918182
}


def calculate_english_language_score(string_to_score):
    score = 0
    lowercase_string_to_score = string_to_score.lower()

    for letter, weight in CHARACTER_FREQUENCIES.items():
        score += lowercase_string_to_score.count(letter) * weight

    return score


def hex_to_bytes(hex_string):
    return bytearray.fromhex(hex_string)


def bytes_to_hex(the_bytes):
    return the_bytes.hex()


def bytes_to_base64(the_bytes):
    return base64.b64encode(the_bytes).decode("utf-8")


def string_to_bytes(the_string):
    return the_string.encode("ascii")


def bytes_to_string(the_bytes):
    return the_bytes.decode("ascii")


def xor_bytes(bytes_a, bytes_b):
    return bytes(a ^ b for (a,b) in zip(bytes_a, bytes_b))


def xor_single_byte(single_byte, the_bytes):
    return bytes(single_byte ^ c for c in the_bytes)


def xor_repeating_key_bytes(plaintext_bytes, key_bytes):
    # Extend the key to be the same length as the plaintext.
    key_bytes_length = len(key_bytes)
    plaintext_bytes_length = len(plaintext_bytes)
    if key_bytes_length < plaintext_bytes_length:
        # Integer divisoun, but rounded up.
        repeats = (plaintext_bytes_length + key_bytes_length // 2) // key_bytes_length
        extended_key_bytes = key_bytes * repeats

    return xor_bytes(plaintext_bytes, extended_key_bytes)


if __name__ == "__main__":
    print("This is a library and should not be run directly.")
