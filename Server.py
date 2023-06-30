import socket
import threading
import ast
import sqlite3
import os.path
from os import path
import codecs
import json
import random
import Encryption
from cryptography.hazmat.primitives import serialization
import sys
from Database import *

sock = None
lock = threading.Lock()
authorized_users = dict()
token_to_user = dict()
clients_public_keys = dict()
s_private_key = None
s_public_key = None
BUFFER_SIZE = 65536


def send_msg(conn, msg):
    conn.sendall(msg)


def recv_msg(conn):
    try:
        msg = conn.recv(BUFFER_SIZE)
        return msg
    except Exception as e:
        print(f"Error: {e}")
    return None


def to_json(data):
    return json.dumps(data).encode('latin-1')


def from_json(data):
    return json.loads(data.decode('latin-1'))


def generate_nonce(length=8):
    return ''.join([str(random.randint(0, 9)) for i in range(length)])


def generate_token(length=16):
    return ''.join([str(random.randint(0, 9)) for i in range(length)])


def handshake(conn, addr, data):
    session_key = data['session_key'].encode('latin-1')
    session_iv = data['session_iv'].encode('latin-1')
    nonce = data['nonce']
    session_cipher = Encryption.get_cipher_from_key(session_key, session_iv)
    data_to_send = {'nonce': nonce}
    msg = Encryption.sign_and_encrypt(data_to_send, s_private_key, session_cipher)
    send_msg(conn, msg)
    return session_key, session_iv, session_cipher


def login(request, session_cipher, conn, addr):
    username = request['data']['username']
    password = request['data']['password']
    nonce = request['data']['nonce']
    if not check_login_info(username, password):
        data_to_send = {'result': 'fail', 'nonce': nonce}
        send_msg(conn, Encryption.sign_and_encrypt(data_to_send, s_private_key, session_cipher))
        print("Login failed")
        return False
    if Encryption.check_signature(request, clients_public_keys.get(username)):
        data_to_send = {'result': 'success', 'nonce': nonce, 'server-nonce': generate_nonce(8)}
        send_msg(conn, Encryption.sign_and_encrypt(data_to_send, s_private_key, session_cipher))
        response = from_json(Encryption.symmetric_decrypt(cipher_text=recv_msg(conn), cipher=session_cipher))
        is_valid = Encryption.check_signature(response, clients_public_keys.get(username)) \
                and response['data']['server-nonce'] == data_to_send['server-nonce']
        if is_valid:
            token = generate_token()
            data_to_send = {'result': 'success', 'nonce': response['data']['nonce'], 'token': token}
            with lock:
                token_to_user[token] = username
                authorized_users[username] = conn
        else:
            data_to_send = {'result': 'fail', 'nonce': response['data']['nonce']}
        send_msg(conn, Encryption.sign_and_encrypt(data_to_send, s_private_key, session_cipher))
        print(f"{username}'s login" + ("was successful" if is_valid else "failed"))
        return is_valid
    print("Login failed")
    return False


def register(request, session_cipher, conn, addr):
    username = request['data']['username']
    password = request['data']['password']
    nonce = request['data']['nonce']
    public_key = serialization.load_pem_public_key(request['data']['public_key'].encode('latin-1'))
    try:
        if Encryption.check_signature(request, public_key):
            add_user_result = add_user(username, password, Encryption.get_serialized_key(public_key).decode('latin-1'))
            if add_user_result:
                token = generate_token()
                with lock:
                    token_to_user[token] = username
                    authorized_users[username] = conn
                data_to_send = {'result': 'success', 'nonce': nonce, 'token': token}
                send_msg(conn, Encryption.sign_and_encrypt(data_to_send, s_private_key, session_cipher))
                clients_public_keys[username] = public_key
                print(f"{username} registered successfully")
                return True
            data_to_send = {'result': 'fail', 'nonce': nonce}
            send_msg(conn, Encryption.sign_and_encrypt(data_to_send, s_private_key, session_cipher))
            print(f"Username [{username}] already exists")
            return False
        else:
            print("Invalid signature")
            return False
    except Exception as e:
        print(e)



def show_online_users(request, session_cipher, conn, addr):
    token = request['data']['token']
    username = token_to_user.get(token)
    if username:
        if Encryption.check_signature(request, clients_public_keys.get(username)):
            online_users = list(authorized_users.keys())
            data_to_send = {'online-users': online_users, 'nonce': request['data']['nonce']}
            send_msg(conn, Encryption.sign_and_encrypt(data_to_send, s_private_key, session_cipher))
            return True
    return False


def logout(request):
    token = request['data']['token']
    username = token_to_user.get(token)
    if username:
        if Encryption.check_signature(request, clients_public_keys.get(username)):
            with lock:
                del token_to_user[token]
                del authorized_users[username]
            print(username + " logged out")
            return True
    return False


def run_menu(conn, addr, session_iv, session_key):
    global s_public_key, s_private_key
    session_cipher = Encryption.get_cipher_from_key(session_key, session_iv)
    while True:
        msg = recv_msg(conn)
        if not msg:
            return
        request = from_json(Encryption.symmetric_decrypt(cipher=session_cipher, cipher_text=msg))
        cmd = request['data']['cmd']
        if cmd == 'login':
            res = login(request, session_cipher, conn, addr)
        elif cmd == 'register':
            res = register(request, session_cipher, conn, addr)
        elif cmd == 'show-online-users':
            show_online_users(request, session_cipher, conn, addr)
        elif cmd == 'logout':
            res = logout(request)

        else:
            response = json.dumps("{'resp_type':'FAIL','resp':'Invalid command'}").encode('latin-1')
            send_msg(conn, response)


def handle_connection(conn, addr):
    global s_public_key, s_private_key
    while True:
        msg = recv_msg(conn)
        if not msg:
            print("Connection closed by client")
            with lock:
                for (username, user_conn) in authorized_users.items():
                    if user_conn == conn:
                        del authorized_users[username]
            return
        try:
            data = from_json(Encryption.asymmetric_decrypt(msg, s_private_key))
            if data['cmd'] == 'handshake':
                session_key, session_iv, session_cipher = handshake(conn, addr, data)
                run_menu(conn, addr, session_iv, session_key)
        except Exception as e:
            print(f"Error: {e}")
            return


def init_server_keys():
    global s_public_key, s_private_key
    if os.path.exists("server_public_key.pem") and os.path.exists("server_private_key.pem"):
        s_public_key = Encryption.read_publickey_from_file("server_public_key.pem")
        s_private_key = Encryption.read_privatekey_from_file("server_private_key.pem", password='admin')
    else:
        s_public_key, s_private_key = Encryption.generate_keys(public_name="server_public_key",
                                                               private_name="server_private_key",
                                                               password='admin')


if __name__ == '__main__':
    init_server_keys()
    print("Server keys loaded successfully")

    make_db()
    print("Database initialized successfully")

    clients_public_keys = read_clients_public_keys()
    print("Users public keys loaded successfully")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('', 2232))
    sock.listen()

    while True:
        print("Waiting for connection...")
        conn, addr = sock.accept()
        print("New connection established")
        thr = threading.Thread(target=handle_connection, args=(conn, addr))
        thr.daemon = True
        thr.start()
