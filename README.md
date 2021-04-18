# SSH Implementation

This is a basic implementation of an SSH client and SSH server. This implementation allows the
client to perform certain basic commands in the server's terminal. The following are the commands
that can be passed to the secure shell.
1. **ls**: To list files in the current directory of the server.
2. **pwd**: To show absolute path to the current directory of the server.
3. **cd absolutepath**: To change to the specified directory of the server.
4. **cp src dest**: To copy a file in the server from src to dest.
5. **mv src dest**: Move a file in the server from src to dest.

## Setup Instructions
```
sudo apt install python3
sudo apt install python3-pip
pip3 install cryptography==3.3.1
```

## Running Code
1) Start SSH server.
The server creates it's own pair of public and private keys and listens for connections on
port 54321. Whenever a client connects to it, it transfers it's public key to the client.

```
./ssh_server.py
```

2) Start SSH client
Once the client is registered with the server, it recieves the public key of the server.
Using this public key, client encrypts the session key and succesfuly exchanges a secret key
with the server. For encrypting the terminal commands send to the secure shell and any further
communication, this exchanged session key is used.

```
./ssh_client.py -i <server_ip> -p <server_port_no> -n <user_name>
./ssh_client.py -i 127.0.0.1 -p 54321 -n john
```

Follow along with the prompts in the terminal to register a user with the server and to establish
a connection.

**NOTE**:
* Only users registered with the server will be authenticated and given access to the server's 
shell.
