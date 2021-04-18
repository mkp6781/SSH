#!/usr/bin/env python3

import base64
from cryptography.hazmat.primitives import hashes
from helper import CreateKeys, decrypt_msg, decrypt_msg_with_AES, derive_password, load_keys, load_server_public_key_from_file
import json
import os
from pathlib import Path
import socket
from subprocess import PIPE, Popen, STDOUT

server_port_number = 54321

OUTPUT_FILE = Path(__file__).resolve().parent
SERVER_FILE_LOCATION = OUTPUT_FILE / 'serverpriv.txt'
USER_FILE_LOCATION = OUTPUT_FILE / 'UserCredentials'


def main():
    # setting up a listening socket for ssh server.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as serversocket:
        serversocket.bind(('0.0.0.0', server_port_number))
        serversocket.listen(5)
        print(f"Listening on port {server_port_number}")
        print("Waiting for connection from client.......")
        # client_connection_socket is different from serversocket.
        # This new socket object is used for communication between client and server.
        while True:
            (client_connection_socket, address) = serversocket.accept()
            print(f'Connection from {address}')
            # The server's public key is read as is from the file to be sent to the client.
            server_pub_key = load_server_public_key_from_file()
            server_pub_key = base64.b64encode(server_pub_key)
            client_connection_socket.sendall(server_pub_key)
            # Both the keys of the server are loaded from the files.
            server_public_key, server_private_key = load_keys(SERVER_FILE_LOCATION)
            while True:
                # Recieve serialised data from the client and convert it into dict.
                data = client_connection_socket.recv(1024)
                if not data:
                    break
                decrypted_data = decrypt_msg(server_private_key, data)
                decrypted_data = json.loads(decrypted_data)
                if decrypted_data['type'] == "Registration":
                    # Derive encrypted password from passphrase.
                    iv = os.urandom(16)
                    encrypted_password = derive_password(decrypted_data['passwd'], iv)

                    # ssh server storing user info in file.
                    user_file_name = f"{decrypted_data['name']}.txt"
                    with open(USER_FILE_LOCATION / user_file_name, "w") as pwd:
                        pwd.write(f"{decrypted_data['name']}\n")
                        pwd.write(encrypted_password)
                    reply = {
                        "code": "OK",
                    }
                elif decrypted_data['type'] == 'SSH':
                    # Derive password using `decrypted_data` and compare with `encrypted_password` in file.
                    user_file_name = f"{decrypted_data['name']}.txt"
                    with open(USER_FILE_LOCATION / user_file_name, "r") as pwd:
                        password_from_file = pwd.read().split("\n")[-1]
                        iv_base64 = password_from_file[:24]
                        enc_output_base64 = password_from_file[24:]

                    iv = base64.b64decode(iv_base64)
                    password_derived = derive_password(decrypted_data['passwd'], iv)
                    user_authenticated = (password_derived[24:] == enc_output_base64)
                    reply = {
                        "code": ("OK" if user_authenticated else "NOK"),
                    }
                    json_format_reply = json.dumps(reply).encode('utf-8')
                    client_connection_socket.sendall(json_format_reply)

                    # If the passwords do not match close the connection.
                    if not user_authenticated:
                        break

                    session_key = decrypted_data['session_key']
                    while True:
                        data = client_connection_socket.recv(1024)
                        if not data:
                            break
                        data = json.loads(data)
                        shell_command = decrypt_msg_with_AES(session_key, data['iv'], data['command'])
                        shell_command_args = shell_command.split()
                        print(shell_command[3:])
                        print(shell_command_args, shell_command)
                        if (len(shell_command_args)==1):
                            os.system(f"{shell_command_args[0]} > output.txt")
                        elif shell_command_args[0]=="cd":
                            os.chdir(shell_command[3:])
                            with open("output.txt", "w") as f:
                                f.write("")
                        else:
                            os.system(f"{shell_command} > output.txt")

                        with open("output.txt", "r") as f:
                            output = f.read()
                        reply = {
                            "output": output
                        }
                        json_format_reply = json.dumps(reply).encode('utf-8')
                        client_connection_socket.sendall(json_format_reply)

                json_format_reply = json.dumps(reply).encode('utf-8')
                client_connection_socket.sendall(json_format_reply)

if __name__ == "__main__":
    CreateKeys()
    main()