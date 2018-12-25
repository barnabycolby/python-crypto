#!/usr/bin/env python3
import ciphers
import crypto_utils
from converter import Converter

class ECBByteByByteAttack:
    def __init__(self, oracle):
        self.oracle = oracle


    def recover_secret(self):
        prefix_size = self.find_prefix_size()
        block_size = self.find_block_size()
        secret_size = self.find_added_data_size() - prefix_size

        # We figure out each byte by removing one byte of our input one byte at a time.
        # To make the calculations easy, we simply start with an input equal to the length of the secret.
        # To make this even easier, we add characters such that the secret is initially aligned to the start of a block.
        length_of_oracle_input_without_alignment = (prefix_size + secret_size)
        length_of_alignment_input = block_size - (length_of_oracle_input_without_alignment % block_size)
        oracle_input = b"A" * (secret_size + length_of_alignment_input)

        # Because we replace the input characters with known characters of the secret, the block we
        # look at for comparison is always going to be the same.
        interesting_block_index = (len(oracle_input) + prefix_size - 1) // block_size

        # Now we figure out the characters one-by-one.
        secret = b""
        while len(oracle_input) > length_of_alignment_input:
            oracle_input = oracle_input[:-1]
            secret += self.brute_secret_character(block_size, oracle_input, secret, interesting_block_index)

        return secret


    def brute_secret_character(self, block_size, plaintext_input, known_secret, interesting_block_index):
        # First, we generate the block that contains the secret byte.
        ciphertext = self.oracle(plaintext_input)
        expected_block = crypto_utils.get_block(ciphertext, block_size, interesting_block_index)

        for guess_value in range(256):
            guessed_byte = bytes([guess_value])
            plaintext_with_guess = plaintext_input + known_secret + guessed_byte

            guess_ciphertext = self.oracle(plaintext_with_guess)
            guess_ciphertext_block = crypto_utils.get_block(guess_ciphertext, block_size, interesting_block_index)

            if guess_ciphertext_block == expected_block:
                return guessed_byte

        raise "Didn't find the secret character"


    def find_cipher_size_change(self, starting_length):
        plaintext = b"A" * starting_length
        initial_size = len(self.oracle(plaintext))

        while len(self.oracle(plaintext)) is initial_size:
            plaintext += b"A"
        return len(plaintext) - starting_length


    def find_added_data_size(self):
        block_size = self.find_block_size()
        empty_size = len(self.oracle(b""))
        first_bump_length = self.find_cipher_size_change(0)
        return empty_size - first_bump_length


    def find_block_size(self):
        first_bump_length = self.find_cipher_size_change(0)
        return self.find_cipher_size_change(first_bump_length)


    def find_prefix_size(self):
        block_size = self.find_block_size()
        number_of_blocks = len(self.oracle(b"")) // block_size
        length_of_prefix_and_secret = block_size - self.find_cipher_size_change(0)

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
                ciphertext = self.oracle(plaintext)

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


if __name__ == "__main__":
    print("This is a library and should not be run directly.")
