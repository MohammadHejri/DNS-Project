import sqlite3
from os import path

import sqlite3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
import base64

from aes_encryption import AESCipher


class ClientDB:
    _connection = None

    @classmethod
    def init(cls):
        if not cls._connection:
            cls._connection = sqlite3.connect('client.db')
            cur = cls._connection.cursor()
            sql = ("""
                        CREATE TABLE IF NOT EXISTS Messages (
                        message VARCHAR(255),
                        sender_id INT NOT NULL,
                        group_id VARCHAR(31),
                        message_timestamp INT
                    );
                    """)
            cur.executescript(sql)

    @classmethod
    def add_new_message(cls, message, sender_id, group_id, timestamp, key):
        encrypted_message = AESCipher(key).encrypt(message)
        cls._connection.execute(
            f"INSERT INTO Messages (message, sender_id, group_id, message_timestamp) values(?, ?, ?, ?)",
            (encrypted_message, sender_id, group_id, timestamp))
        cls._connection.commit()
        return True

    @classmethod
    def get_messages(cls, group_id, key):
        cur = cls._connection.cursor()
        message_list = cur.execute(
            f"SELECT message, sender_id, group_id, message_timestamp FROM Messages WHERE group_id = {group_id}").fetchall()
        decrypted_message_list = []
        for message, sender_id, group_id, timestamp in message_list:
            decrypted_message_list.append((AESCipher(key).decrypt(message), sender_id, group_id, timestamp))
        return decrypted_message_list
