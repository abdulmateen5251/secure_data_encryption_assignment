import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet

# --- Initialization ---
st.set_page_config(page_title="Secure Data Encryption", layout="centered")

# Generate or load encryption key
KEY_FILE = "fernet_key.key"
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as f:
        f.write(Fernet.generate_key())

with open(KEY_FILE, "rb") as f:
    KEY = f.read()

cipher = Fernet(KEY)

# Data file for persistence
DATA_FILE = "stored_data.json"

# Master password hash for better login security
MASTER_PASSWORD_HASH = hashlib.sha256("admin123".encode()).hexdigest()

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(st.session_state.stored_data, f)

# Session State Initialization
if "stored_data" not in st.session_state:
    st.session_state.stored_data = load_data()

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "logged_in" not in st.session_state:
    st.session_state.logged_in = True

# --- Utility Functions ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey, username):
    hashed_passkey = hash_passkey(passkey)

    user_record = st.session_state.stored_data.get(username)
    if user_record and user_record["encrypted_text"] == encrypted_text and user_record["passkey"] == hashed_passkey:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1
    return None

# --- UI Pages ---
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.title("🔒 Secure Data Encryption System")
    st.write("Welcome! Use this app to **securely store and retrieve data** with encryption.")

elif choice == "Store Data":
    st.title("📂 Store Data Securely")
    username = st.text_input("Enter a Username:")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if username and user_data and passkey:
            encrypted_text = encrypt_data(user_data)
            hashed_passkey = hash_passkey(passkey)
            st.session_state.stored_data[username] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            save_data()
            st.success("✅ Data stored securely!")
            st.code(encrypted_text, language="text")
        else:
            st.error("⚠️ All fields are required!")

elif choice == "Retrieve Data":
    if not st.session_state.logged_in:
        st.warning("🔐 Please login first.")
        st.stop()

    st.title("🔍 Retrieve Your Data")
    username = st.text_input("Enter Your Username:")
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if username and encrypted_text and passkey:
            result = decrypt_data(encrypted_text, passkey, username)
            if result:
                st.success("✅ Decrypted Data:")
                st.code(result, language="text")
            else:
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_left}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                    st.session_state.logged_in = False
                    time.sleep(2)
                    st.experimental_rerun()
        else:
            st.error("⚠️ All fields are required!")

elif choice == "Login":
    st.title("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if hashlib.sha256(login_pass.encode()).hexdigest() == MASTER_PASSWORD_HASH:
            st.session_state.failed_attempts = 0
            st.session_state.logged_in = True
            st.success("✅ Reauthorized successfully! Redirecting...")
            time.sleep(2)
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")
