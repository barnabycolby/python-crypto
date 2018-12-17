#!/usr/bin/env python3
from converter import Converter

def find_single_byte_xor_key(ciphertext):
    possible_plaintexts_and_scores = []
    for c in range(256):
        possible_plaintext_bytes = xor_single_byte(c, ciphertext)

        # Is it valid text?
        try:
            possible_plaintext = Converter(possible_plaintext_bytes).string()
        except UnicodeDecodeError:
            continue

        score = calculate_english_language_score(possible_plaintext)
        possible_plaintexts_and_scores.append((score, c))

    best_score, best_key = max(possible_plaintexts_and_scores, key=lambda x: x[0])
    return best_key


if __name__ == "__main__":
    print("This is a library and should not be run directly.")
