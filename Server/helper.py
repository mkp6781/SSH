import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import padding as pad
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json
import os
import random
import socket


def CreateKeys() -> None:
    # Generate key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=None)
    # Write key to disk for safe keeping
    with open(f"serverpriv.txt", "wb") as pr:
        pr.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"password"),
        ))
    public_key = private_key.public_key()
    with open(f"serverpub.txt", "wb") as pu:
        pu.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

# Loading public key of server.
def load_server_public_key_from_file() -> bytes:
    with open(f"serverpub.txt", "rb") as key_file:
        server_private_key = key_file.read()
    return server_private_key

def load_keys(filename: str): # returns _RSA objects
    # Loading private and public key of reciever and sender.
    with open(filename, "rb") as key_file:
        priv_key = serialization.load_pem_private_key(key_file.read(), password=b'password',)
    pub_key = priv_key.public_key()
    return pub_key, priv_key

def decrypt_msg(key: bytes, data: bytes) -> bytes:
    decrypted_content = key.decrypt(
                            data,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
    return decrypted_content

def derive_password(passphrase: str, iv: bytes) -> str:
    # Takes the given passphrase and converts it into a binary string.
    passphrase_bin_string = ''.join(format(ord(i), '08b') for i in passphrase)
    # converts binary string to integer and left shifts by 64bits.
    key = int(passphrase_bin_string, 2) << 64
    # converts into byte string of 16 bytes
    key = key.to_bytes(16, byteorder= 'big')
    zeros_byte_string = bytes("0"*16, 'utf-8')
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(zeros_byte_string) + encryptor.finalize()
    ct_base64 = base64.b64encode(ct).decode('utf-8')
    iv_base64 = base64.b64encode(iv).decode('utf-8')
    return (iv_base64+ct_base64)

def decrypt_msg_with_AES(session_key: str, iv: str, encrypted_msg: str) -> str:
    iv_bytes = base64.b64decode(iv)
    session_key_bytes = base64.b64decode(session_key)
    encrypted_msg_bytes = base64.b64decode(encrypted_msg)
    cipher = Cipher(algorithms.AES(session_key_bytes), modes.CBC(iv_bytes))
    decryptor = cipher.decryptor()
    padded_original_message_bytes = decryptor.update(encrypted_msg_bytes)
    unpadder = pad.PKCS7(128).unpadder()
    original_message_bytes = unpadder.update(padded_original_message_bytes)
    original_message_bytes+=unpadder.finalize()
    original_message = original_message_bytes.decode('utf-8')
    return original_message