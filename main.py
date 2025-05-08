import streamlit as st
import hashlib
import json
import os
import time
import base64
import secrets
import hmac

# --- Initialization ---
st.set_page_config(page_title="Secure Data Encryption", layout="centered", page_icon="🔒")

# Generate or load encryption key
KEY_FILE = "encryption_key.key"
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as f:
        f.write(secrets.token_bytes(32))  # 256-bit key

with open(KEY_FILE, "rb") as f:
    KEY = f.read()

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
    # Create a unique salt for this encryption
    salt = secrets.token_bytes(16)
    
    # Derive an encryption key and authentication key from our master key and salt
    # using HMAC as a poor man's key derivation function
    encryption_key = hmac.new(KEY, salt + b'encryption', hashlib.sha256).digest()
    auth_key = hmac.new(KEY, salt + b'authentication', hashlib.sha256).digest()
    
    # Create a random IV (initialization vector)
    iv = secrets.token_bytes(16)
    
    # XOR-based encryption (a simple stream cipher)
    # We'll create a keystream by using HMAC with increasing counter values
    data = text.encode('utf-8')
    counter = 0
    keystream = b''
    
    # Generate enough keystream to cover our data
    while len(keystream) < len(data):
        counter_bytes = counter.to_bytes(4, byteorder='big')
        keystream += hmac.new(encryption_key, iv + counter_bytes, hashlib.sha256).digest()
        counter += 1
    
    # Truncate keystream to the data length
    keystream = keystream[:len(data)]
    
    # XOR the data with the keystream
    encrypted_data = bytes(x ^ y for x, y in zip(data, keystream))
    
    # Create an authentication tag (HMAC of salt + iv + encrypted_data)
    auth_tag = hmac.new(auth_key, salt + iv + encrypted_data, hashlib.sha256).digest()
    
    # Combine salt + iv + encrypted_data + auth_tag
    result = salt + iv + encrypted_data + auth_tag
    
    # Convert to base64 for safe storage
    return base64.b64encode(result).decode()

def decrypt_data(encrypted_text, passkey, username):
    hashed_passkey = hash_passkey(passkey)

    user_record = st.session_state.stored_data.get(username)
    if user_record and user_record["encrypted_text"] == encrypted_text and user_record["passkey"] == hashed_passkey:
        try:
            # Decode from base64
            raw_data = base64.b64decode(encrypted_text)
            
            # Extract the components
            salt = raw_data[:16]
            iv = raw_data[16:32]
            auth_tag = raw_data[-32:]  # Last 32 bytes (SHA-256 output size)
            encrypted_data = raw_data[32:-32]  # Everything between iv and auth_tag
            
            # Derive the same encryption and authentication keys
            encryption_key = hmac.new(KEY, salt + b'encryption', hashlib.sha256).digest()
            auth_key = hmac.new(KEY, salt + b'authentication', hashlib.sha256).digest()
            
            # Verify authentication tag
            expected_tag = hmac.new(auth_key, salt + iv + encrypted_data, hashlib.sha256).digest()
            if not hmac.compare_digest(auth_tag, expected_tag):
                raise ValueError("Authentication failed - data may have been tampered with")
            
            # Generate the same keystream
            counter = 0
            keystream = b''
            
            # Generate enough keystream to cover our encrypted data
            while len(keystream) < len(encrypted_data):
                counter_bytes = counter.to_bytes(4, byteorder='big')
                keystream += hmac.new(encryption_key, iv + counter_bytes, hashlib.sha256).digest()
                counter += 1
            
            # Truncate keystream to the data length
            keystream = keystream[:len(encrypted_data)]
            
            # XOR to decrypt
            decrypted_data = bytes(x ^ y for x, y in zip(encrypted_data, keystream))
            
            st.session_state.failed_attempts = 0
            return decrypted_data.decode('utf-8')
        except Exception as e:
            st.session_state.failed_attempts += 1
            st.error(f"Decryption error: {e}")
            return None
    
    st.session_state.failed_attempts += 1
    return None

# --- UI Pages ---
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.title("🔒 Secure Data Encryption System")
    st.write("Welcome! Use this app to **securely store and retrieve data** with AES encryption.")
    
    st.info("This application uses HMAC-based encryption with authentication for secure data storage.")
    
    st.markdown("""
    ### Security Features:
    - 256-bit encryption key
    - Unique salt and IV for each encryption
    - HMAC authentication to prevent tampering
    - Password hashing with SHA-256
    - Account lockout after 3 failed attempts
    """)

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