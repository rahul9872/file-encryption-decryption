import hashlib
import os
from typing import Generator

CHUNK_SIZE = 4096  # 4 KB chunks for streaming

def derive_key(password: str, salt: bytes, length: int = 32) -> bytes:
    """
    Derive a key from the given password using PBKDF2-HMAC-SHA256.
    """
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        100000,
        dklen=length,
    )

def get_cipher(key: bytes) -> Generator[bytes, bytes, None]:
    """
    Generator-based XOR cipher for streaming.
    """
    while True:
        data = (yield)
        if data is None:
            break
        # XOR each byte with the key (repeating key as needed)
        yield bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def encrypt_file(input_file, output_file, password: str):
    """
    Encrypts a file using XOR + PBKDF2-derived key.
    """
    salt = os.urandom(16)
    key = derive_key(password, salt)
    cipher = get_cipher(key)
    next(cipher)  # prime generator

    # Write salt at the start of the file so it can be reused in decryption
    output_file.write(salt)

    while chunk := input_file.read(CHUNK_SIZE):
        output_file.write(cipher.send(chunk))

def decrypt_file(input_file, output_file, password: str):
    """
    Decrypts a file using XOR + PBKDF2-derived key.
    """
    # First 16 bytes are the salt
    salt = input_file.read(16)
    key = derive_key(password, salt)
    cipher = get_cipher(key)
    next(cipher)  # prime generator

    while chunk := input_file.read(CHUNK_SIZE):
        output_file.write(cipher.send(chunk))
