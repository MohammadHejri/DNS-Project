import sqlite3
from os import path
from cryptography.hazmat.primitives import serialization

import Encryption


def make_db():
    if path.exists("users.db"):
        return 1
    else:
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


def check_login_info(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.execute(
        "SELECT username from users where username='%s' AND password='%s'" % (
            username, Encryption.hash(password)))
    rowcount = len(cursor.fetchall())
    conn.close()
    return rowcount > 0


def read_clients_pubkey():
    conn = sqlite3.connect('users.db')
    cursor = conn.execute("SELECT * from  PubKeys")
    client_keys = {}
    for username, pubkey in cursor.fetchall():
        client_keys[username] = serialization.load_pem_public_key(pubkey.encode('latin-1'))
    return client_keys


