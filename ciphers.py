#!/usr/bin/env python3
from Crypto.Cipher import AES
import crypto_utils

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


def encrypt_aes_ecb_128(plaintext, key):
    block_size = 16
    encryptor = AES.new(key, AES.MODE_ECB)

    padded_plaintext = crypto_utils.pkcs7_pad(plaintext, block_size)
    return encryptor.encrypt(padded_plaintext)


def decrypt_aes_ecb_128(ciphertext, key):
    block_size = 16
    decryptor = AES.new(key, AES.MODE_ECB)

    padded_plaintext = decryptor.decrypt(ciphertext)
    return crypto_utils.pkcs7_unpad(padded_plaintext, block_size)


if __name__ == "__main__":
    print("This is a library and should not be run directly.")
