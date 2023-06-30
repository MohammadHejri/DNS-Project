import socket
import sys
import random
import Encryption
import json
import threading
from cryptography.hazmat.primitives import serialization
import os

from client_db import ClientDB

HOST = '127.0.0.1'
username = ""
password = ""
BUFFER_SIZE = 65536
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

chats = {}

# Encryption keys
token = None
public_key = None
private_key = None
username = None
server_pkey = None
session_key = None
session_cipher = None
session_iv = None

main_menu = {"login": "Login to an existing account", "register": "Create an account", }
logged_in_menu = {"chat": "Chat with an online user", "online users": "Show online users",
                  "logout": "Logout from the account"}
logged_in = False

inbox = []


def generate_nonce(length=8):
    return ''.join([str(random.randint(0, 9)) for i in range(length)])


def get_chat_message():
    try:
        msg = listen_socket.recv(BUFFER_SIZE)
        return msg
    except Exception as e:
        print("Error - %s" % e)
        sys.exit(1)


def get_msg():
    try:
        msg = sock.recv(BUFFER_SIZE)
        return msg
    except Exception as e:
        print("Error - %s" % e)
        sys.exit(1)


def send_msg(msg):
    sock.sendall(msg)


def handshake():
    global server_pkey, session_key, session_iv, session_cipher
    session_key, session_iv, session_cipher = Encryption.symmetric_key()
    data_to_send = {
        "cmd": "handshake",
        "session_iv": session_iv.decode('latin-1'),
        "session_key": session_key.decode('latin-1'),
        "nonce": generate_nonce(8),
    }
    try:
        send_msg(Encryption.asymmetric_encrypt(data=json.dumps(data_to_send).encode('latin-1'), key=server_pkey))
        response = json.loads(sock.recv(65536).decode('latin-1'))
        print(response['data'])
        if response['data']['nonce'] == data_to_send['nonce'] and Encryption.check_authority(
                json.dumps(response['data']).encode('latin-1'),
                response['signature'].encode('latin-1'),
                server_pkey):
            print("handshake was successful")
            return True
        return False
    except Exception as e:
        print(e)
        return 0


def register():
    global public_key, private_key, server_pkey, token
    while True:
        username = input("Choose a username: ")
        password = input("Enter Password: ")
        retype_password = input("Re-type Password: ")
        if password == retype_password:
            break
        else:
            print("Passwords do not match, try again.")
    try:
        public_key, private_key = Encryption.generate_keys(size=4096, public_name=username + "pub",
                                                           private_name=username + "priv", password=password)
        print("generate keys")
        data_to_send = {
            "cmd": "register",
            "username": username,
            "password": password,
            "public_key": Encryption.get_serialized_key(public_key).decode('latin-1'),
            "nonce": generate_nonce(8),
        }
        msg = Encryption.sign_and_encrypt(data_to_send, private_key, session_cipher)
        send_msg(msg)
        print("sent register information")
        response = json.loads(Encryption.symmetric_decrypt(ct=get_msg(), cipher=session_cipher).decode('latin-1'))
        if Encryption.check_authority(json.dumps(response['data']).encode('latin-1'),
                                      response['signature'].encode('latin-1'),
                                      server_pkey):
            if response['data']['nonce'] == data_to_send['nonce'] and response['data']['result'] == 'succ':
                token = response['data']['token']
                return True, "Registered Successfully"
        return False, "Couldn't register to the server"
    except Exception as e:
        return False, e


def login():
    if logged_in:
        return False, "already logged in"
    global public_key, private_key, server_pkey
    username = input("Choose a username: ")
    password = input("Enter Password: ")
    if os.path.exists(username + "priv.pem") and os.path.exists(username + "pub.pem"):
        public_key = Encryption.read_publickey_from_file(username + "pub.pem")
        try:
            private_key = Encryption.read_privatekey_from_file(username + "priv.pem", password)
        except Exception as e:
            return False, "Wrong username or password"
    else:
        public_key, private_key = Encryption.generate_keys(size=4096, password=password)
    data_to_send = {
        "cmd": "login",
        "username": username,
        "password": password,
        "nonce": generate_nonce(8),
    }
    msg = Encryption.sign_and_encrypt(data_to_send, private_key, session_cipher)
    send_msg(msg)
    print("Sent login info")
    response = json.loads(Encryption.symmetric_decrypt(ct=get_msg(), cipher=session_cipher).decode('latin-1'))
    if Encryption.check_authority(json.dumps(response['data']).encode('latin-1'),
                                  response['signature'].encode('latin-1'),
                                  server_pkey):
        if response['data']['nonce'] == data_to_send['nonce'] and response['data']['result'] == 'succ':
            return login_phase2(response)
        return False, "Wrong username or password"
    return False, "Invalid Signature"


def login_phase2(response):
    global token
    nonce2 = response['data']['nonce2']
    data_to_send = {
        "nonce": generate_nonce(8),
        "nonce2": nonce2,
    }
    msg = Encryption.sign_and_encrypt(data_to_send, private_key, session_cipher)
    send_msg(msg)
    print("Sent nonce2")
    response = json.loads(Encryption.symmetric_decrypt(ct=get_msg(), cipher=session_cipher).decode('latin-1'))
    if Encryption.check_authority(json.dumps(response['data']).encode('latin-1'),
                                  response['signature'].encode('latin-1'),
                                  server_pkey):
        if response['data']['nonce'] == data_to_send['nonce'] and response['data']['result'] == 'succ':
            token = response['data']['token']
            return True, "Logged-In Successfully"
        return False, "Wrong parameters!"
    return False, "Invalid Signature"


def logout():
    global token
    data_to_send = {
        "cmd": "logout",
        "token": token,
        "nonce": generate_nonce(8),
    }
    msg = Encryption.sign_and_encrypt(data_to_send, private_key, session_cipher)
    send_msg(msg)
    print("logged out successfully")


def show_online_users():
    global token
    data_to_send = {
        "cmd": "show-online-users",
        "token": token,
        "nonce": generate_nonce(8),
    }
    msg = Encryption.sign_and_encrypt(data_to_send, private_key, session_cipher)
    send_msg(msg)
    response = json.loads(Encryption.symmetric_decrypt(ct=get_msg(), cipher=session_cipher).decode('latin-1'))
    if Encryption.check_authority(json.dumps(response['data']).encode('latin-1'),
                                  response['signature'].encode('latin-1'),
                                  server_pkey):
        if response['data']['nonce'] == data_to_send['nonce']:
            print(response['data']['online-users'])


def show_menu(commands):
    print("COMMANDS:")
    for command in commands:
        print(command + " : " + commands[command])


def run_client_menu():
    global logged_in
    while True:
        if logged_in:
            show_menu(logged_in_menu)
        else:
            show_menu(main_menu)
        command = input("please enter the command:")
        if command == "register":
            res, message = register()
            print(message)
            if res:
                logged_in = True
                listen_socket.connect(('127.0.0.1', 2222))
                t = threading.Thread(target=listen, args=())
                t.daemon = True
                t.start()
        elif command == 'login':
            res, message = login()
            print(message)
            if res:
                logged_in = True
                listen_socket.connect(('127.0.0.1', 2222))
                t = threading.Thread(target=listen, args=())
                t.daemon = True
                t.start()

        elif command == 'logout':
            logout()
            logged_in = False
        elif command == 'online users':
            show_online_users()
        elif command == 'chat':
            start_chat()
        elif command == 'inbox':
            print(inbox)
        else:
            print("Invalid command!")
            continue


def init_connection():
    try:
        sock.connect(('127.0.0.1', 2222))
        handshake_status = handshake()
        if handshake_status:
            print("Connected to messenger server successfully )")
            run_client_menu()
        else:
            print("Couldn't connect to messenger server. Connection is not secure.")
            sock.close()
            sys.exit(1)
    except Exception as e:
        print(e)
        sys.exit(1)


def start_chat():
    receiver = input("Please insert the receiver username: ")
    data_to_send = {
        "cmd": "chat",
        "token": token,
        "receiver": receiver,
        "nonce": generate_nonce(8),
    }
    msg = Encryption.sign_and_encrypt(data_to_send, private_key, session_cipher)
    send_msg(msg)
    response = json.loads(Encryption.symmetric_decrypt(ct=get_msg(), cipher=session_cipher).decode('latin-1'))
    if Encryption.check_authority(json.dumps(response['data']).encode('latin-1'),
                                  response['signature'].encode('latin-1'),
                                  server_pkey) and response['data']['nonce'] == data_to_send['nonce']:
        seq_num = int(response['data']['seq_num'])
        receiver_key = serialization.load_pem_public_key(response['data']['receiver_key'].encode('latin-1'))
        text_message = ''
        while text_message != "exit":
            text_message = input("please input your message: ")
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
            msg = Encryption.sign_and_encrypt(data_to_send, private_key, session_cipher)
            send_msg(msg)
            seq_num += 1
        print("chat closed!")
        return
    print("invalid server!")
    return


def add_msg_to_inbox(response):
    response = json.loads(Encryption.symmetric_decrypt(ct=response, cipher=session_cipher).decode('latin-1'))
    if Encryption.check_authority(json.dumps(response['data']).encode('latin-1'),
                                  response['signature'].encode('latin-1'), server_pkey):
        chat_key_par_cipher = response['data']['chat_key_par_cipher'].encode('latin-1')
        chat_key_par_cipher = json.loads(
            Encryption.asymmetric_decrypt(chat_key_par_cipher, private_key).decode('latin-1'))

        chat_iv = chat_key_par_cipher['chat_iv'].encode('latin-1')
        chat_key = chat_key_par_cipher['chat_key'].encode('latin-1')
        chat_cipher = Encryption.get_cipher_from_key(chat_key, chat_iv)

        cipher_text = response['data']['cipher_text'].encode('latin-1')
        msg_text = json.loads(Encryption.symmetric_decrypt(cipher=chat_cipher, ct=cipher_text).decode('latin-1'))
        inbox.append(msg_text['text'])


def listen():
    data_to_send = {
        "token": token,
        "cmd": "listen",
    }
    msg = Encryption.asymmetric_encrypt(data=json.dumps(data_to_send).encode('latin-1'), key=server_pkey)
    listen_socket.sendall(msg)
    response = json.loads(
        Encryption.symmetric_decrypt(ct=listen_socket.recv(BUFFER_SIZE), cipher=session_cipher).decode('latin-1'))
    if Encryption.check_authority(json.dumps(response['data']).encode('latin-1'),
                                  response['signature'].encode('latin-1'), server_pkey):
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
            print("waiting")


if __name__ == "__main__":
    ClientDB.init()
    server_pkey = Encryption.read_publickey_from_file("server_pubkey.pem")
    print(server_pkey)
    init_connection()
