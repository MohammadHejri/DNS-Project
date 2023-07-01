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

listening_clients = dict()
users_cipher = dict()


def generate_seq_num():
    return random.randint(1, 10 ** 8)


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
                users_cipher[username] = session_cipher
        else:
            data_to_send = {'result': 'fail', 'nonce': response['data']['nonce']}
        send_msg(conn, Encryption.sign_and_encrypt(data_to_send, s_private_key, session_cipher))
        print(f"{username}'s login " + ("was successful" if is_valid else "failed"))
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
                    users_cipher[username] = session_cipher
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


def send_chat_message(request, session_cipher, conn, addr):
    global s_public_key, s_private_key, clients_public_keys
    token = request['data']['token']
    nonce = request['data']['nonce']
    receiver = request['data']['receiver']
    sender_key = clients_public_keys[token_to_user[token]]
    if Encryption.check_signature(request, sender_key):
        server_seq_num = generate_seq_num()
        data_to_send = {'receiver_key': Encryption.get_serialized_key(clients_public_keys.get(receiver)).decode('latin-1'),
                        'nonce': nonce, 'seq_num': str(server_seq_num)}
        msg = Encryption.sign_and_encrypt(data_to_send, s_private_key, session_cipher)
        send_msg(conn, msg)
        while True:
            response = json.loads(
                Encryption.symmetric_decrypt(cipher_text=conn.recv(BUFFER_SIZE), cipher=session_cipher).decode('latin-1'))
            response_cmd = response['data']['cmd']
            if response_cmd == "quitchat":
                quit_chat()
                break
            seq_num = int(response['data']['seq_num'])
            if Encryption.check_signature(request, sender_key):

                if seq_num == server_seq_num:
                    data_to_send = {
                        "cipher_text": response['data']['cipher_text'],
                        "chat_key_par_cipher": response['data']['chat_key_par_cipher'],
                        "sender": token_to_user[token]
                    }
                    msg = Encryption.sign_and_encrypt(data_to_send, s_private_key, users_cipher[receiver])
                    listening_clients[receiver][0].sendall(msg)
                    server_seq_num += 1


def quit_chat():
    return


def handle_listen(args, c, a):
    token = args['token']
    username = token_to_user[token]
    data_to_send = {
        "nonce": generate_nonce(8)
    }
    c.sendall(Encryption.sign_and_encrypt(data_to_send, s_private_key, users_cipher[username]))
    response = json.loads(
        Encryption.symmetric_decrypt(cipher_text=c.recv(BUFFER_SIZE), cipher=users_cipher[username]).decode('latin-1'))
    if Encryption.check_signature(response, clients_public_keys[username]):
        with lock:
            listening_clients[username] = (c, a)
        print("listen handled")
    return


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
                del users_cipher[username]
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
        elif cmd == 'chat':
            send_chat_message(request, session_cipher, conn, addr)

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
                        del users_cipher[username]
            return
        try:
            data = from_json(Encryption.asymmetric_decrypt(msg, s_private_key))
            if data['cmd'] == 'handshake':
                session_key, session_iv, session_cipher = handshake(conn, addr, data)
                run_menu(conn, addr, session_iv, session_key)
            elif data['cmd'] == 'listen':
                handle_listen(data, conn, addr)
                break
        except Exception as e:
            print(f"Error: {e}")
            return


def init_server_keys():
    global s_public_key, s_private_key
    if os.path.exists("server_public_key.pem") and os.path.exists("server_private_key.pem"):
        s_public_key = Encryption.read_publickey_from_file("server_public_key.pem")
        s_private_key = Encryption.read_privatekey_from_file("server_private_key.pem", password='admin')
    else:
        s_public_key, s_private_key = Encryption.generate_keys(size=4096, password='admin', name='server_')


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
