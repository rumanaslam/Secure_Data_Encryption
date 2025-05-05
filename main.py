import streamlit as st
import sqlite3
import hashlib
import os
from cryptography.fernet import Fernet

# Constants
KEY_FILE = "simple_secret.key"
DB_FILE = "simple_data.db"

# Load or generate encryption key
def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return key

cipher = Fernet(load_key())

# Initialize database
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS vault(
            label TEXT PRIMARY KEY,
            encrypted_text TEXT,
            passkey TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# Hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt and decrypt functions
def encrypt(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# UI
st.set_page_config(page_title="Secure Vault", page_icon="🔐")
st.title("🔐 Secure Data Vault")

menu = ["Store Secret", "Retrieve Secret"]
choice = st.sidebar.radio("Navigation", menu)

if choice == "Store Secret":
    st.header("📝 Store a New Secret")

    label = st.text_input("Label (Unique ID):")
    secret = st.text_area("Secret Message:")
    col1, col2 = st.columns(2)
    with col1:
        passkey = st.text_input("Passkey:", type="password")
    with col2:
        confirm_passkey = st.text_input("Confirm Passkey:", type="password")

    if st.button("🔒 Encrypt and Save"):
        if not label or not secret or not passkey or not confirm_passkey:
            st.warning("⚠️ Please fill in all fields.")
        elif passkey != confirm_passkey:
            st.error("❌ Passkeys do not match!")
        else:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            encrypted = encrypt(secret)
            hashed_key = hash_passkey(passkey)

            try:
                c.execute("INSERT INTO vault (label, encrypted_text, passkey) VALUES (?, ?, ?)",
                          (label, encrypted, hashed_key))
                conn.commit()
                st.success("✅ Secret saved successfully!")
            except sqlite3.IntegrityError:
                st.error("❌ A secret with this label already exists!")
            conn.close()

elif choice == "Retrieve Secret":
    st.header("🔍 Retrieve Your Secret")

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT label FROM vault")
    labels = [row[0] for row in c.fetchall()]
    conn.close()

    label = st.selectbox("Select Label:", labels if labels else ["No data found"])
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("🔓 Decrypt"):
        if not label or not passkey:
            st.warning("⚠️ Please provide both label and passkey.")
        else:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("SELECT encrypted_text, passkey FROM vault WHERE label=?", (label,))
            result = c.fetchone()
            conn.close()

            if result:
                encrypted_text, stored_hash = result
                if hash_passkey(passkey) == stored_hash:
                    decrypted = decrypt(encrypted_text)
                    st.success("✅ Secret successfully decrypted:")
                    st.code(decrypted)
                else:
                    st.error("❌ Incorrect passkey.")
            else:
                st.warning("⚠️ No such label found.")
