#!/usr/bin/env python3
from converter import Converter

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

    return score / len(string_to_score)


def hamming_distance(a, b):
    assert len(a) == len(b)
    
    # First convert to bitstrings.
    a_bits = Converter(a).bits()
    b_bits = Converter(b).bits()

    return sum(a_bit != b_bit for a_bit, b_bit in zip(a_bits, b_bits))


def get_block(ciphertext, block_size, block_index):
    start_index = block_size * block_index
    end_index = start_index + block_size
    return ciphertext[start_index:end_index]


if __name__ == "__main__":
    print("This is a library and should not be run directly.")
