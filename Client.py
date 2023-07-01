import socket
import sys
import random
import time

import Database
import Encryption
import json
import threading
import os
from cryptography.hazmat.primitives import serialization

from client_db import *

SERVER_ADDR = ('127.0.0.1', 2232)
username = ""
password = ""
BUFFER_SIZE = 65536
listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock = None

inbox = []

# Encryption keys
token = None
public_key = None
private_key = None
username = None
server_public_key = None
session_key = None
session_cipher = None
session_iv = None
databasePassword = None

main_menu = [
    ("Register", "Create an account"),
    ("Login", "Login to an existing account"),
]

logged_in_menu = [
    ("Logout", "Logout from the account"),
    ("Online-Users", "Show online users"),
    ("Chat", "Chat with an online user"),
    ("Inbox", "See received messages"),
]

logged_in = False


def get_chat_message():
    try:
        msg = listen_socket.recv(BUFFER_SIZE)
        return msg
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def send_msg(msg):
    sock.sendall(msg)


def recv_msg():
    try:
        msg = sock.recv(BUFFER_SIZE)
        return msg
    except Exception as e:
        print(f"Error: {e}")


def to_json(data):
    return json.dumps(data).encode('latin-1')


def from_json(data):
    return json.loads(data.decode('latin-1'))


def generate_nonce(length=8):
    return ''.join([str(random.randint(0, 9)) for i in range(length)])


def handshake():
    global server_public_key, session_key, session_iv, session_cipher
    try:
        session_key, session_iv, session_cipher = Encryption.symmetric_key()
        data_to_send = {
            "cmd": "handshake",
            "session_key": session_key.decode('latin-1'),
            "session_iv": session_iv.decode('latin-1'),
            "nonce": generate_nonce(8),
        }
        send_msg(Encryption.asymmetric_encrypt(data=to_json(data_to_send), key=server_public_key))
        response = from_json(Encryption.symmetric_decrypt(cipher_text=recv_msg(), cipher=session_cipher))
        if Encryption.check_signature(response, server_public_key) \
                and Encryption.check_nonce(response, data_to_send["nonce"]):
            print("Handshake was successful")
            return True
    except Exception as e:
        print("Handshake was failed")
        print(f"Error: {e}")
    return False


def register():
    global public_key, private_key, server_public_key, token, databasePassword
    while True:
        username = input("Enter username: ")
        password = input("Enter password: ")
        retype_password = input("Re-type Password: ")
        if password == retype_password:
            break
        else:
            print("Passwords do not match, try again...")
    try:
        public_key, private_key = Encryption.generate_keys(size=4096, password=password)
        print("Keys generated successfully")
        data_to_send = {
            "cmd": "register",
            "username": username,
            "password": password,
            "public_key": Encryption.get_serialized_key(public_key).decode('latin-1'),
            "nonce": generate_nonce(8),
        }
        send_msg(Encryption.sign_and_encrypt(data_to_send, private_key, session_cipher))
        response = from_json(Encryption.symmetric_decrypt(cipher_text=recv_msg(), cipher=session_cipher))
        if Encryption.check_signature(response, server_public_key) \
                and Encryption.check_nonce(response, data_to_send['nonce']) \
                and response['data']['result'] == 'success':
            token = response['data']['token']
            databasePassword = password
            return True, "Registered Successfully"
        return False, "Couldn't register to the server"
    except Exception as e:
        return False, e


def login():
    global public_key, private_key, server_public_key
    if logged_in:
        return False, "Already logged in"
    username = input("Enter username: ")
    password = input("Enter Password: ")
    try:
        if os.path.exists("private_key.pem") and os.path.exists("public_key.pem"):
            try:
                public_key = Encryption.read_publickey_from_file("public_key.pem")
                private_key = Encryption.read_privatekey_from_file("private_key.pem", password)
            except Exception as e:
                return False, "Wrong password"
        else:
            public_key, private_key = Encryption.generate_keys(size=4096, password=password)
        data_to_send = {
            "cmd": "login",
            "username": username,
            "password": password,
            "nonce": generate_nonce(8),
        }
        send_msg(Encryption.sign_and_encrypt(data_to_send, private_key, session_cipher))
        response = from_json(Encryption.symmetric_decrypt(cipher_text=recv_msg(), cipher=session_cipher))
        if Encryption.check_signature(response, server_public_key) \
                and Encryption.check_nonce(response, data_to_send['nonce']) \
                and response['data']['result'] == 'success':
            return login_2nd_phase(response)
        return False, "Invalid signature, username, or password"
    except Exception as e:
        return False, e


def login_2nd_phase(response):
    global token
    try:
        server_nonce = response['data']['server-nonce']
        data_to_send = {
            "nonce": generate_nonce(8),
            "server-nonce": server_nonce,
        }
        send_msg(Encryption.sign_and_encrypt(data_to_send, private_key, session_cipher))
        response = from_json(Encryption.symmetric_decrypt(cipher_text=recv_msg(), cipher=session_cipher))
        if Encryption.check_signature(response, server_public_key):
            if Encryption.check_nonce(response, data_to_send['nonce']) and response['data']['result'] == 'success':
                token = response['data']['token']
                return True, "Logged-in successfully"
            return False, "Wrong parameters!"
        return False, "Invalid Signature"
    except:
        return False


def logout():
    global token, inbox
    data_to_send = {
        "cmd": "logout",
        "token": token,
    }
    send_msg(Encryption.sign_and_encrypt(data_to_send, private_key, session_cipher))
    print("Logged out successfully")
    inbox = []


def show_online_users():
    global token
    try:
        data_to_send = {
            "cmd": "show-online-users",
            "token": token,
            "nonce": generate_nonce(8),
        }
        send_msg(Encryption.sign_and_encrypt(data_to_send, private_key, session_cipher))
        response = from_json(Encryption.symmetric_decrypt(cipher_text=recv_msg(), cipher=session_cipher))
        if Encryption.check_signature(response, server_public_key) \
                and Encryption.check_nonce(response, data_to_send['nonce']):
            print(f"Online Users: {response['data']['online-users']}")
    except Exception as e:
        print(f"Error: {e}")


def show_menu(commands):
    print("\n--------------------COMMANDS--------------------")
    for i, command in enumerate(commands):
        print(f"{i + 1}) [{command[0]}]: {command[1]}")


def start_chat():
    receiver = input("Please insert the receiver username: ")
    data_to_send = {
        "cmd": "chat",
        "token": token,
        "receiver": receiver,
        "nonce": generate_nonce(8),
    }
    send_msg(Encryption.sign_and_encrypt(data_to_send, private_key, session_cipher))
    response = from_json(Encryption.symmetric_decrypt(cipher_text=recv_msg(), cipher=session_cipher))
    if Encryption.check_signature(response, server_public_key) \
            and Encryption.check_nonce(response, data_to_send['nonce']):
        seq_num = int(response['data']['seq_num'])
        receiver_key = serialization.load_pem_public_key(response['data']['receiver_key'].encode('latin-1'))
        text_message = ''
        while True:
            text_message = input("please input your message: ")
            if text_message == "exit":
                data_to_send = {
                    "cmd": "quitchat",
                }
                send_msg(Encryption.sign_and_encrypt(data_to_send, private_key, session_cipher))
                break
            chat_key, chat_iv, chat_cipher = Encryption.symmetric_key()
            txt_msg = {
                "text": text_message,
            }
            txt_msg_cipher = Encryption.symmetric_encrypt(chat_cipher, json.dumps(txt_msg).encode('latin-1'))
            chat_key_par = {
                "chat_iv": chat_iv.decode('latin-1'),
                "chat_key": chat_key.decode('latin-1'),
            }
            chat_key_par_cipher = Encryption.asymmetric_encrypt(json.dumps(chat_key_par).encode('latin-1'),
                                                                receiver_key)
            data_to_send = {
                "cmd": "continue",
                "seq_num": str(seq_num),
                "cipher_text": txt_msg_cipher.decode('latin-1'),
                "chat_key_par_cipher": chat_key_par_cipher.decode('latin-1')
            }
            send_msg(Encryption.sign_and_encrypt(data_to_send, private_key, session_cipher))
            seq_num += 1
        print("chat closed!")
        return
    print("invalid server!")
    return


def add_msg_to_inbox(response):
    response = json.loads(Encryption.symmetric_decrypt(cipher_text=response, cipher=session_cipher).decode('latin-1'))
    if Encryption.check_signature(response, server_public_key):
        chat_key_par_cipher = response['data']['chat_key_par_cipher'].encode('latin-1')
        chat_key_par_cipher = from_json(Encryption.asymmetric_decrypt(chat_key_par_cipher, private_key))

        chat_iv = chat_key_par_cipher['chat_iv'].encode('latin-1')
        chat_key = chat_key_par_cipher['chat_key'].encode('latin-1')
        chat_cipher = Encryption.get_cipher_from_key(chat_key, chat_iv)

        cipher_text = response['data']['cipher_text'].encode('latin-1')
        msg_text = from_json(Encryption.symmetric_decrypt(cipher=chat_cipher, cipher_text=cipher_text))
        inbox.append((response['data']['sender'], msg_text['text']))
        Database.add_new_message(msg_text['text'], response['data']['sender'], int(time.time()), databasePassword)


def listen():
    data_to_send = {
        "token": token,
        "cmd": "listen",
    }
    msg = Encryption.asymmetric_encrypt(data=json.dumps(data_to_send).encode('latin-1'), key=server_public_key)
    listen_socket.sendall(msg)
    response = json.loads(
        Encryption.symmetric_decrypt(cipher_text=listen_socket.recv(BUFFER_SIZE), cipher=session_cipher).decode(
            'latin-1'))
    if Encryption.check_signature(response, server_public_key):
        data_to_send = {
            "token": token,
            "nonce": response['data']['nonce']
        }
        msg = Encryption.sign_and_encrypt(data_to_send, private_key, session_cipher)
        listen_socket.sendall(msg)

    while True:
        try:
            response = get_chat_message()
            add_msg_to_inbox(response)
        except Exception as e:
            print(e)


def run_client_menu():
    global logged_in, databasePassword
    while True:
        if logged_in:
            show_menu(logged_in_menu)
            command = input("Enter command: ")
            if command in ["1", "Logout"]:
                logout()
                logged_in = False
            elif command in ["2", "Online-Users"]:
                show_online_users()
            elif command in ["3", "Chat"]:
                start_chat()
            elif command in ["4", "Inbox"]:
                print(inbox)
            else:
                print("Invalid command!")
                continue
        else:
            show_menu(main_menu)
            command = input("Enter command: ")
            if command in ["1", "Register"]:
                res, message = register()
                print(message)
                if res:
                    logged_in = True
                    databasePassword = input("Enter password for database: ")
                    listen_socket.connect(('127.0.0.1', 2232))
                    t = threading.Thread(target=listen, args=())
                    t.daemon = True
                    t.start()
            elif command in ["2", "Login"]:
                res, message = login()
                print(message)
                if res:
                    logged_in = True
                    databasePassword = input("Enter password for database: ")
                    listen_socket.connect(('127.0.0.1', 2232))
                    t = threading.Thread(target=listen, args=())
                    t.daemon = True
                    t.start()
            else:
                print("Invalid command!")
                continue


def init_connection():
    global sock
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(SERVER_ADDR)
        handshake_status = handshake()
        if handshake_status:
            print("Connected to messenger server successfully")
            run_client_menu()
        else:
            print("Couldn't connect to messenger server")
            sock.close()
            sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    server_public_key = Encryption.read_publickey_from_file("server_public_key.pem")
    print("Server public key loaded successfully")
    Database.make_messages_db()
    init_connection()
