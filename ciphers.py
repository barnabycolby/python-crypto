#!/usr/bin/env python3

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
