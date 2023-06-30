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

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sock.bind(('', 2222))
sock.listen()
print("Server started successfully")

lock = threading.Lock()
connections = list()
authorized_users = dict()
token_to_user = dict()
client_keys = dict()
s_private_key = None
s_public_key = None
BUFFER_SIZE = 65536


def send_msg(conn, addr, msg):
    conn.sendall(msg)


def generate_nonce(length=8):
    return ''.join([str(random.randint(0, 9)) for i in range(length)])


def generate_token(length=16):
    return ''.join([str(random.randint(0, 9)) for i in range(length)])


def handshake(conn, addr, data):
    # handshaking stage
    nonce = data['nonce']
    session_key = data['session_key'].encode('latin-1')
    session_iv = data['session_iv'].encode('latin-1')
    print(nonce)
    print("Encrypting Nonce ...")
    data_to_send = {'nonce': nonce}
    signed_nonce = Encryption.sign(data_to_send=json.dumps(data_to_send).encode('latin-1'), private_key=s_private_key)
    msg = json.dumps({'data': data_to_send, 'signature': signed_nonce.decode('latin-1')}).encode('latin-1')
    send_msg(conn, addr, msg)
    print("Sent encrypted Nonce to user")
    return session_key, session_iv


def login(args, signature, session_cipher, conn, addr):
    username = args['username']
    password = args['password']
    nonce = args['nonce']
    if Encryption.check_authority(json.dumps(args).encode('latin-1'), signature.encode('latin-1'),
                                  client_keys[username]):
        if not check_login_info(username, password):
            data_to_send = {'result': 'fail', 'nonce': nonce}
            msg = Encryption.sign_and_encrypt(data_to_send, s_private_key, session_cipher)
            send_msg(conn, addr, msg)
            return False
        data_to_send = {'result': 'succ', 'nonce': nonce, 'nonce2': generate_nonce(8)}
        msg = Encryption.sign_and_encrypt(data_to_send, s_private_key, session_cipher)
        send_msg(conn, addr, msg)
        response = json.loads(
            Encryption.symmetric_decrypt(ct=conn.recv(BUFFER_SIZE), cipher=session_cipher).decode('latin-1'))
        if Encryption.check_authority(json.dumps(response['data']).encode('latin-1'),
                                      response['signature'].encode('latin-1'),
                                      client_keys[username]):
            flag = True
            res = 'succ'
            if response['data']['nonce2'] != data_to_send['nonce2']:
                flag = False
                res = 'fail'
            token = generate_token()
            data_to_send = {'result': res, 'nonce': response['data']['nonce'], 'token': token}
            msg = Encryption.sign_and_encrypt(data_to_send, s_private_key, session_cipher)
            send_msg(conn, addr, msg)
            if flag:
                with lock:
                    token_to_user[token] = username
                    authorized_users[username] = conn
            print("logged in " + res)
            return flag


def register(args, signature, session_cipher, conn, addr):
    username = args['username']
    password = args['password']
    public_key = args['public_key'].encode('latin-1')
    nonce = args['nonce']
    public_key = serialization.load_pem_public_key(public_key)
    if Encryption.check_authority(json.dumps(args).encode('latin-1'), signature.encode('latin-1'), public_key):
        result = add_user(username, password, Encryption.get_serialized_key(public_key).decode('latin-1'))
        if result:
            token = generate_token()
            with lock:
                token_to_user[token] = username
                authorized_users[username] = conn
            data_to_send = {'result': 'succ', 'nonce': nonce, 'token': token}
            msg = Encryption.sign_and_encrypt(data_to_send, s_private_key, session_cipher)
            send_msg(conn, addr, msg)
            client_keys[username] = public_key
            print("Registered successfully")
            return True
        data_to_send = {'result': 'fail', 'nonce': nonce}
        msg = Encryption.sign_and_encrypt(data_to_send, s_private_key, session_cipher)
        send_msg(conn, addr, msg)
        print("Username already exists")
        return False
    else:
        print("Invalid signature")
        sys.exit(1)


def send_chat_message(from_user, to_user, msg, options):
    pass


def show_online_users(args, signature, session_cipher, conn, addr):
    username = token_to_user[args['token']]
    if Encryption.check_authority(json.dumps(args).encode('latin-1'), signature.encode('latin-1'),
                                  client_keys[username]):
        online_users = list(authorized_users.keys())
        data_to_send = {'online-users': online_users, 'nonce': args['nonce']}
        msg = Encryption.sign_and_encrypt(data_to_send, s_private_key, session_cipher)
        send_msg(conn, addr, msg)


def logout(args, signature):
    username = token_to_user[args['token']]
    if Encryption.check_authority(json.dumps(args).encode('latin-1'), signature.encode('latin-1'),
                                  client_keys[username]):
        with lock:
            del token_to_user[args['token']]
            del authorized_users[username]
        print(username + " logged out")
        return True
    return False


def run_menu(conn, addr, session_iv, session_key):
    global s_public_key, s_private_key
    session_cipher = Encryption.get_cipher_from_key(session_key, session_iv)
    logged_in = False
    while True:
        data = ''
        try:
            data = conn.recv(BUFFER_SIZE)
        except Exception as e:
            print("Error - %s" % e)
        if not data:
            return
        data = Encryption.symmetric_decrypt(cipher=session_cipher, ct=data)
        data = json.loads(data.decode('latin-1'))
        args = data['data']
        cmd = args['cmd']
        if cmd == 'login':
            res = login(args, data['signature'], session_cipher, conn, addr)
            if res:
                logged_in = True
        elif cmd == 'register':
            res = register(args, data['signature'], session_cipher, conn, addr)
            if res:
                logged_in = True
        elif cmd == 'show-online-users':
            show_online_users(args, data['signature'], session_cipher, conn, addr)
        elif cmd == 'logout':
            res = logout(args, data['signature'])
            if res:
                logged_in = False
        elif cmd == 'chat':
            send_chat_message(data['from_uname'], data['to_uname'], data['msg'], data['options'])

        else:
            response = json.dumps("{'resp_type':'FAIL','resp':'Invalid command'}").encode('latin-1')
            send_msg(conn, addr, response)


def handle_connection(conn, addr):
    global s_public_key, s_private_key
    while True:
        data = ''
        try:
            data = conn.recv(BUFFER_SIZE)
        except Exception as e:
            print("Error - %s" % e)
        if not data:
            print("Connection closed by client")
            with lock:
                del connections[connections.index(conn)]
                for i in authorized_users:
                    if authorized_users[i] == conn:
                        del authorized_users[i]
                        break
                break
        try:
            data = Encryption.asymmetric_decrypt(data, s_private_key)
            data = json.loads(data.decode('latin-1'))
            if data['cmd'] == 'handshake':
                session_key, session_iv = handshake(conn, addr, data)
                run_menu(conn, addr, session_iv, session_key)
        except Exception as e:
            print("Wrong format.")
            print(e)


if __name__ == '__main__':
    make_db()
    print("Database created")
    client_keys = read_clients_pubkey()
    print("Load users public keys")

    if os.path.exists("server_pubkey.pem") and os.path.exists("server_privkey.pem"):
        s_public_key = Encryption.read_publickey_from_file("server_pubkey.pem")
        s_private_key = Encryption.read_privatekey_from_file("server_privkey.pem", password='admin')
    else:
        s_public_key, s_private_key = Encryption.generate_keys(public_name="server_pubkey",
                                                               private_name="server_privkey", password='admin')
    while True:
        conn, addr = sock.accept()
        connections.append(conn)
        thr = threading.Thread(target=handle_connection, args=(conn, addr))
        thr.daemon = True
        thr.start()
