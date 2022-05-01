from ecb import aes_ecb_encrypt
from base64 import b64decode
from xor import xor_data
from Crypto.Cipher import AES
import struct


def aes_ctr(data, key, nonce):
    """Encrypts or decrypts with AES-CTR mode."""
    output = b''
    counter = 0

    # Takes a block size of input at each time (or less if a block-size is not available), and XORs
    # it with the encrypted concatenation of nonce and counter.
    while data:

        # Get the little endian bytes concatenation of nonce and counter (each 64bit values)
        concatenated_nonce_and_counter = struct.pack('<QQ', nonce, counter)

        # Encrypt the concatenation of nonce and counter
        encrypted_counter = aes_ecb_encrypt(concatenated_nonce_and_counter, key)

        # XOR the encrypted value with the input data
        output += xor_data(encrypted_counter, data[:AES.block_size])

        # Update data to contain only the values that haven't been encrypted/decrypted yet
        data = data[AES.block_size:]

        # Update the counter as prescribed in the CTR mode of operation
        counter += 1

    return output
