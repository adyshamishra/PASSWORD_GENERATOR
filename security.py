import hashlib
import os
import base64
from cryptography.fernet import Fernet

def hash_master_password(password):
    salt = os.urandom(16)
    hashed_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt, hashed_key

def verify_master_password(provided_password, stored_salt, stored_hashed_key):
    new_hash = hashlib.pbkdf2_hmac('sha256', provided_password.encode(), stored_salt, 100000)
    return new_hash == stored_hashed_key

def derive_encryption_key(password, salt):
    """Derives a Fernet-compatible key from the master password."""
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return base64.urlsafe_b64encode(key)

def encrypt_password(plain_text, master_password, salt):
    key = derive_encryption_key(master_password, salt)
    f = Fernet(key)
    return f.encrypt(plain_text.encode())

def decrypt_password(cipher_text, master_password, salt):
    key = derive_encryption_key(master_password, salt)
    f = Fernet(key)
    return f.decrypt(cipher_text).decode()