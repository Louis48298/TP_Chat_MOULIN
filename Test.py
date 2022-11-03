
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
import base64
import os
"""
password = b"password"
salt_int = "16"
salt = bytes(salt_int, "utf8")
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
)
key = base64.urlsafe_b64encode(kdf.derive(password))
f = Fernet(key)
token = f.encrypt(b"Secret message!")
print(key)
print(f.decrypt(token))"""
def encrypt(message):
        message = bytes(message, "utf8") 
        salt = bytes("16", "utf8")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(message))
        f = Fernet(key)
        token = f.encrypt(b"Secret message!")
        iv = os.urandom(16)
        return (iv, token)


print(encrypt("test"))
        
    