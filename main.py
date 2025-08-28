import streamlit as st
import os

st.set_page_config(page_title="File Encryptor", page_icon="🔐")
import os
import hashlib
from typing import Iterator
from encryption_utils import (
    prepend_salt_and_encrypt,
    read_salt_and_decrypt,
    CHUNK_SIZE,
)


SALT_SIZE = 16 # bytes
PBKDF2_ITERS = 200_000
CHUNK_SIZE = 1024 * 1024 # 1 MB chunks




def derive_key(password: str, salt: bytes, length: int) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERS, dklen=length)




def xor_bytes(data: bytes, key: bytes) -> bytes:
	"""XOR `data` with `key` repeated as necessary."""
	out = bytearray(len(data))
	klen = len(key)
	for i in range(len(data)):
		out[i] = data[i] ^ key[i % klen]
	return bytes(out)




def process_stream_xor(in_file, out_file, password: str, salt: bytes):
	"""Read input stream in chunks, XOR with key, write to out_file.

	When encrypting we generate a random salt and it must be saved (prepended) so
	decryption can derive the same key. For this function the caller handles salt placement.
	"""
	# Derive a key sized to the chunk size (but we only need a key of a reasonable length).
	# We'll choose 64 bytes key length and repeat it over the data.
	key = derive_key(password, salt, 64)

	while True:
		chunk = in_file.read(CHUNK_SIZE)
		if not chunk:
			break
		out_file.write(xor_bytes(chunk, key))




def prepend_salt_and_encrypt(in_file_path: str, out_file_path: str, password: str):
	salt = os.urandom(SALT_SIZE)
	with open(in_file_path, 'rb') as fin, open(out_file_path, 'wb') as fout:
		fout.write(salt) # write salt as header
		process_stream_xor(fin, fout, password, salt)


def read_salt_and_decrypt(in_file_path: str, out_file_path: str, password: str):
	with open(in_file_path, 'rb') as fin:
		salt = fin.read(SALT_SIZE)
		with open(out_file_path, 'wb') as fout:
			process_stream_xor(fin, fout, password, salt)
