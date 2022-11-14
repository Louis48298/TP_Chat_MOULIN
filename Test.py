
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
import base64
import os
"""
message = b"message"
salt_int = "16"
salt = bytes(salt_int, "utf8")
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
)
key = base64.urlsafe_b64encode(kdf.derive(message))
f = Fernet(key)
token = f.encrypt(b"Secret message!")
print(key)
print(f.decrypt(token))
def encrypt(message):
        message = bytes(message, "utf8") 
        salt = bytes("16", "utf8")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(message)) #message should be the self._password to generate the key
        f = Fernet(key)
        token = f.encrypt(message)
        iv = os.urandom(16)
        return (iv, token)

def decrypt(token):
        f = Fernet(key) #key should be the self._password to generate the key
        return f.decrypt(token)
        
print(encrypt("test"))
print(decrypt(encrypt("test")[1], encrypt("test")[2]))
"""
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = os.urandom(32)
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
encryptor = cipher.encryptor()
ct = encryptor.update(b"a secret message") + encryptor.finalize()
decryptor = cipher.decryptor()
decryptor.update(ct) + decryptor.finalize()    
    