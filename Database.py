import sqlite3
from os import path
from cryptography.hazmat.primitives import serialization

import Encryption
from aes_encryption import AESCipher


def make_db():
    if not path.exists("users.db"):
        conn = sqlite3.connect('users.db')
        cur = conn.cursor()
        sql = ("\n"
               "        CREATE TABLE IF NOT EXISTS Users(\n"
               "            username NOT NULL PRIMARY KEY,\n"
               "            password);\n"
               "            \n"
               "        CREATE TABLE IF NOT EXISTS PubKeys(\n"
               "            username NOT NULL,\n"
               "            publickey);\n"
               "\n"
               "        ")
        cur.executescript(sql)
        conn.close()


def make_messages_db():
    if not path.exists("messages.db"):
        conn = sqlite3.connect('messages.db')
        cur = conn.cursor()
        sql = ("""
                    CREATE TABLE IF NOT EXISTS Messages (
                    message VARCHAR(255),
                    sender_id VARCHAR(32) NOT NULL,
                    message_timestamp INT
                );
                """)
        cur.executescript(sql)
        conn.close()


def add_user(username, password, serialized_pubkey):
    conn = sqlite3.connect('users.db')
    cursor = conn.execute("SELECT username from users where username='%s'" % (username))
    rowcount = len(cursor.fetchall())
    if rowcount > 0:
        return False
    conn.execute(
        "INSERT INTO Users(username,password) values('%s','%s')" % (username, Encryption.hash(password)))
    conn.execute("INSERT INTO PubKeys(username,publickey) values('%s','%s')" % (username, serialized_pubkey))
    conn.commit()
    conn.close()
    return True


def add_new_message(message, sender_id, timestamp, key):
    conn = sqlite3.connect('messages.db')
    encrypted_message = AESCipher(key).encrypt(message)
    conn.execute(
        f"INSERT INTO Messages (message, sender_id, message_timestamp) values(?, ?, ?)",
        (encrypted_message, sender_id, timestamp))
    conn.commit()
    conn.close()


def check_login_info(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.execute(
        "SELECT username from users where username='%s' AND password='%s'" % (
            username, Encryption.hash(password)))
    rowcount = len(cursor.fetchall())
    conn.close()
    return rowcount > 0


def read_clients_public_keys():
    conn = sqlite3.connect('users.db')
    cursor = conn.execute("SELECT * from PubKeys")
    client_keys = {}
    for username, pubkey in cursor.fetchall():
        client_keys[username] = serialization.load_pem_public_key(pubkey.encode('latin-1'))
    return client_keys
