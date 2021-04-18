#!/usr/bin/python3

import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import getopt
from helper import encrypt_msg, encrypt_with_AES, send_message
import json
import os
import socket, sys


def parse_args(argv):
    server_ip = ''
    server_port_number = ''
    user_name = ''
    try:
        opts, args = getopt.getopt(argv,"i:p:n:",[])
    except getopt.GetoptError:
        print("./ssh_client -i <ip_address> -p <port_no> -n <user_name>")
        sys.exit(2)
    for opt, arg in opts:
        if opt == "-i":
            server_ip = arg
        elif opt == "-p":
            server_port_number = arg
        elif opt == "-n":
            user_name = arg
    return (server_ip, server_port_number, user_name)

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_ip, int(server_port_number)))
        response = base64.b64decode(s.recv(1024))
        with open("server_pub.txt", "wb") as pu:
            pu.write(response)
        server_public_key = load_pem_public_key(response)
        new_client = input("Are you a new client(y/n): ")
        if new_client == "y":
            # Registration with KDC
            print("Please register with KDC....")
            password = input("Enter password(max characters-8): ")
            data = {
                'type': 'Registration',
                'name': user_name,
                'passwd': password,
            }
            encrypted_data = encrypt_msg(server_public_key, data)
            s.sendall(encrypted_data)
            response = json.loads(s.recv(1024))
            if response['code'] == "OK":
                print("Registration Succesful!! :)")

        is_ssh_request = input("Do you wish to ssh into the server?(y/n): ")
        if is_ssh_request == "y":
            password = input(f"Hi {user_name}, Please enter your password: ")
            session_key_bytes = os.urandom(32)
            session_key = base64.b64encode(session_key_bytes).decode('utf-8')
            data = {
                'type': 'SSH',
                'name': user_name,
                'passwd': password,
                'session_key': session_key
            }
            encrypted_data = encrypt_msg(server_public_key, data)
            s.sendall(encrypted_data)
            response = json.loads(s.recv(1024))
            if response['code'] == "OK":
                print("You are now authenticated to access the server's shell!!")
                while True:
                    command = input("Enter command to be executed: ")
                    if command == "logout":
                        break
                    iv_bytes = os.urandom(16)
                    iv = base64.b64encode(iv_bytes).decode('utf-8')
                    encrypted_command = encrypt_with_AES(session_key_bytes, iv_bytes, command)
                    message = {
                        "command": encrypted_command,
                        "iv": iv
                    }
                    send_message(message, s)
                    response = json.loads(s.recv(1024))
                    print(response)

if __name__ == "__main__":
    (server_ip, server_port_number, user_name) = parse_args(sys.argv[1:])
    main()