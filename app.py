"""Streamlit app: file encrypt/decrypt UI"""
import streamlit as st
import os
import tempfile

# ======================
# ENCRYPTION FUNCTIONS
# ======================

CHUNK_SIZE = 4096

def xor_data(data: bytes, key: bytes) -> bytes:
    """XOR encrypt/decrypt data with key."""
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def prepend_salt_and_encrypt(input_file, output_file, password):
    """Encrypt file with password + random salt."""
    salt = os.urandom(16)  # Random salt
    key = password.encode("utf-8") + salt  # Mix salt into key

    with open(input_file, "rb") as f:
        data = f.read()

    encrypted_data = xor_data(data, key)

    # Save salt + ciphertext
    with open(output_file, "wb") as f:
        f.write(salt + encrypted_data)

def read_salt_and_decrypt(input_file, output_file, password):
    """Decrypt file by extracting salt and applying XOR."""
    with open(input_file, "rb") as f:
        content = f.read()

    salt = content[:16]
    encrypted_data = content[16:]
    key = password.encode("utf-8") + salt  # Same key derivation

    decrypted_data = xor_data(encrypted_data, key)

    with open(output_file, "wb") as f:
        f.write(decrypted_data)

# ======================
# STREAMLIT UI
# ======================

st.set_page_config(page_title="File Encryptor", page_icon="🔐")
st.title("🔐 File Encryption & Decryption Tool")
st.write("Upload a file, choose encrypt or decrypt, enter a password, then download the result.")

mode = st.radio("Mode", ("Encrypt", "Decrypt"))
uploaded_file = st.file_uploader("Choose a file", type=None)
password = st.text_input("Password", type="password")

if uploaded_file is None:
    st.info("Upload a file to get started.")

if st.button("Process"):
    if uploaded_file is None:
        st.warning("Please upload a file first.")
    elif not password:
        st.warning("Please enter a password.")
    else:
        # Save uploaded file to a temp file
        with tempfile.NamedTemporaryFile(delete=False) as in_tmp:
            in_tmp_name = in_tmp.name
            while True:
                chunk = uploaded_file.read(CHUNK_SIZE)
                if not chunk:
                    break
                in_tmp.write(chunk)

        # Create output temp file
        out_tmp_fd, out_tmp_name = tempfile.mkstemp()
        os.close(out_tmp_fd)

        try:
            # Process encryption/decryption
            if mode == "Encrypt":
                prepend_salt_and_encrypt(in_tmp_name, out_tmp_name, password)
            else:
                read_salt_and_decrypt(in_tmp_name, out_tmp_name, password)

            # ✅ Correct filename handling
            if mode == "Encrypt":
                out_filename = f"{uploaded_file.name}.enc"
            else:
                if uploaded_file.name.endswith(".enc"):
                    out_filename = uploaded_file.name[:-4]  # strip ".enc"
                else:
                    out_filename = f"{uploaded_file.name}.dec"

            # Read processed file
            with open(out_tmp_name, "rb") as f:
                data_bytes = f.read()

            # Download button
            st.success("Processing finished — download below")
            st.download_button(
                label="Download result",
                data=data_bytes,
                file_name=out_filename
            )

        finally:
            try:
                os.remove(in_tmp_name)
            except Exception:
                pass
