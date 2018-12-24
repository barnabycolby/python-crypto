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


def detect_ecb_mode_using_oracle(oracle, block_size):
    plaintext = b"A" * block_size * 4
    ciphertext = oracle(plaintext)
    return detect_ecb_mode(ciphertext, block_size)


def detect_ecb_mode(ciphertext, block_size):
    blocks = crypto_utils.split_into_blocks(ciphertext, block_size)
    return len(set(blocks)) != len(blocks)


def find_cipher_size_change(oracle, starting_length):
    plaintext = b"A" * starting_length
    initial_size = len(oracle(plaintext))

    while len(oracle(plaintext)) is initial_size:
        plaintext += b"A"
    return len(plaintext) - starting_length


def find_block_size(oracle):
    first_bump_length = find_cipher_size_change(oracle, 0)
    return find_cipher_size_change(oracle, first_bump_length)


def find_cipher_secret_size(oracle):
    block_size = find_block_size(oracle)
    empty_size = len(oracle(b""))
    first_bump_length = find_cipher_size_change(oracle, 0)
    return empty_size - first_bump_length


def find_cipher_prefix_size(oracle):
    block_size = find_block_size(oracle)
    number_of_blocks = len(oracle(b"")) // block_size
    length_of_prefix_and_secret = block_size - find_cipher_size_change(oracle, 0)

    # We attempt to detect the prefix length as follows:
    #
    # ABCDTRGT|
    # ABCD1TRG|T-------| # New block, so therefore length of (random-prefix + target-bytes) is 8.
    # ABCD12TR|GT------|
    # ABCD123T|RGT-----|
    # ABCD1234|TRGT----|
    # ABCD1234|5TRGT---| # This is the first time that the second last block stops changing, which means that our extended user input is now only affecting the later block.
    # ABCD1234|56TRGT--|
    # ABCD1234|567TRGT-|
    # ABCD1234|5678TRGT|
    # ABCD1234|56781TRG|T-------|
    # ABCD1234|567812TR|GT------|
    # ABCD1234|5678123T|RGT-----|
    # ABCD1234|56781234|TRGT----|
    # ABCD1234|56781234|5TRGT---|
    # ABCD1234|56781234|56TRGT--|
    # ABCD1234|56781234|567TRGT-|
    # ABCD1234|56781234|5678TRGT|
    plaintext = b""
    previous_block = b""
    new_block = b""
    first_block_stopped_changing = False

    for block_index in range(number_of_blocks):
        for i in range(block_size * 2):
            ciphertext = oracle(plaintext)

            previous_block = new_block
            new_block = crypto_utils.get_block(ciphertext, block_size, block_index)

            if new_block == previous_block:
                plaintext_length_to_stop_block_changing = len(plaintext) - 1

                if plaintext_length_to_stop_block_changing != 0:
                    first_block_stopped_changing = True

                break

            plaintext += b"A"
        else:
            raise "Something went wrong!"

        if first_block_stopped_changing:
            break

    prefix_length_in_last_block = block_size - plaintext_length_to_stop_block_changing
    return (block_size * block_index) + prefix_length_in_last_block


def decrypt_ecb_appended_secret(oracle):
    block_size = find_block_size(oracle)
    secret_size = find_cipher_secret_size(oracle)
    assert detect_ecb_mode_using_oracle(oracle, block_size)

    # Blocks where the entire block is filled with secret data.
    number_of_full_secret_blocks = secret_size // block_size

    partial_secret_block_size = secret_size % block_size

    # Decrypt the full blocks.
    secret = b""
    for block_index in range(number_of_full_secret_blocks):
        secret = decrypt_ecb_appended_secret_block(oracle, block_size, block_index, secret, block_size)

    # Decrypt the last partial block.
    secret = decrypt_ecb_appended_secret_block(oracle, block_size, number_of_full_secret_blocks, secret, partial_secret_block_size)

    return secret


def decrypt_ecb_appended_secret_block(oracle, block_size, block_index, secret, amount_to_guess):
    for i in range(1, amount_to_guess + 1):
        short_input = b"A" * (block_size - i)
        secret_byte_ciphertext = oracle(short_input)
        secret_byte_ciphertext_block = crypto_utils.get_block(secret_byte_ciphertext, block_size, block_index)

        for guess_value in range(256):
            guessed_byte = bytes([guess_value])

            # We don't know how long the secret is, so this could be longer than a block.
            # To compensate, we always take the last block.
            guess_plaintext = (short_input + secret + guessed_byte)[-block_size:]

            guess_ciphertext = oracle(guess_plaintext)
            guess_ciphertext_block = guess_ciphertext[:block_size] 

            if guess_ciphertext_block == secret_byte_ciphertext_block:
                secret += guessed_byte
                break
        else:
            raise "Failed to decrypt the secret. Is this oracle definitely an AES ECB ciphert that appends a secret to the given plaintext?"

    return secret



if __name__ == "__main__":
    print("This is a library and should not be run directly.")
