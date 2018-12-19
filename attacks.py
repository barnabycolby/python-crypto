#!/usr/bin/env python3
import ciphers
import crypto_utils
from converter import Converter

def find_single_byte_xor_key(ciphertext):
    possible_plaintexts_and_scores = []
    for c in range(256):
        possible_plaintext_bytes = ciphers.xor_single_byte(c, ciphertext)

        # Is it valid text?
        try:
            possible_plaintext = Converter(possible_plaintext_bytes).string()
        except UnicodeDecodeError:
            continue

        score = crypto_utils.calculate_english_language_score(possible_plaintext)
        possible_plaintexts_and_scores.append((score, c))

    best_score, best_key = max(possible_plaintexts_and_scores, key=lambda x: x[0])
    return best_key


def find_repeating_xor_key(ciphertext):
    keysize = guess_keysize_using_hamming(ciphertext)
    transposed_blocks = transpose(ciphertext, keysize)
    single_byte_keys = [find_single_byte_xor_key(block) for block in transposed_blocks]
    key_bytes = bytes(bytearray(single_byte_keys))
    return key_bytes


def guess_keysize_using_hamming(ciphertext):
    # We store the keysizes and the resulting hamming distances in this array.
    # We can find the best guess using this list later.
    guess_results = []

    for keysize in range(2, 41):
        number_of_blocks = len(ciphertext) // keysize
        assert number_of_blocks > 1

        blocks = [crypto_utils.get_block(ciphertext, keysize, i) for i in range(number_of_blocks)]

        hamming_distance = 0
        for i in range(number_of_blocks - 1):
            hamming_distance += crypto_utils.hamming_distance(blocks[i], blocks[i+1])
        normalised_hamming_distance = hamming_distance / number_of_blocks / keysize

        guess_results.append((keysize, normalised_hamming_distance))

    best_keysize_guess, smallest_hamming_distance = min(guess_results, key=lambda x: x[1])
    return best_keysize_guess


def transpose(ciphertext, blocksize):
    blocks = []
    for i in range(blocksize):
        blocks.append([])

    for i in range(len(ciphertext)):
        block_index = i % blocksize
        blocks[block_index].append(ciphertext[i])

    return [bytes(bytearray(block)) for block in blocks]


def detect_ecb_mode(ciphertext, block_size):
    blocks = crypto_utils.split_into_blocks(ciphertext, block_size)
    return len(set(blocks)) != len(blocks)


def find_block_size(oracle):
    def find_size_change(starting_length):
        plaintext = b"A" * starting_length
        initial_size = len(oracle(plaintext))

        while len(oracle(plaintext)) is initial_size:
            plaintext += b"A"
        return len(plaintext) - starting_length

    first_bump_length = find_size_change(0)
    return find_size_change(first_bump_length)


if __name__ == "__main__":
    print("This is a library and should not be run directly.")
