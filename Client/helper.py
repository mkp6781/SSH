import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as pad
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
import json
import socket

# Loading file containing public key of server.
def load_server_public_key_from_file() -> bytes:
    with open(f"serverpub.txt", "rb") as key_file:
        key = key_file.read()
    server_pub_key = base64.b64encode(key)
    return server_pub_key

def send_message(data: dict, s: socket) -> None:
    json_format_data = json.dumps(data).encode('utf-8')
    s.sendall(json_format_data)

def encrypt_msg(key: bytes, data: dict) -> bytes:
    data_in_bytes = json.dumps(data).encode('utf-8')
    encrypted_data = key.encrypt(
                        (data_in_bytes),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
    return encrypted_data

def encrypt_with_AES(session_key: bytes, iv: bytes, data: str) -> str:
    data_bytes = bytes(data, 'utf-8')
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    padder = pad.PKCS7(128).padder()
    padded_data = padder.update(data_bytes)
    padded_data+=padder.finalize()
    encryptor = cipher.encryptor()
    ct_bytes = encryptor.update(padded_data) + encryptor.finalize()
    ct_str = base64.b64encode(ct_bytes).decode('utf-8')
    return ct_str