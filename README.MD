# File Encryption & Decryption Tool (Streamlit + XOR)


## Overview
A small Streamlit web app to encrypt and decrypt files using an XOR-based cipher with a password-derived key (PBKDF2). The app handles file uploads, processes files in streaming chunks (to support larger files), and provides a download button for the output.


## Setup
1. Create and activate a Python virtual environment (recommended):


```bash
python3 -m venv venv
source venv/bin/activate # macOS / Linux
# On Windows: venv\Scripts\activate

To run file 
source venv/bin/activate
streamlit run app.py