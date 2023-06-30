from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import json
import base64


def get_cipher_from_key(key, iv):
    return Cipher(algorithms.AES(key), modes.CTR(iv))


def symmetric_key():
    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    return key, iv, cipher


def symmetric_encrypt(cipher, plain_text):
    encryptor = cipher.encryptor()
    return encryptor.update(plain_text) + encryptor.finalize()


def symmetric_decrypt(cipher, ct):
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()


# save file helper
def save_file(filename, content):
    f = open(filename, "wb")
    f.write(content)
    f.close()


def asymmetric_encrypt(data, key):
    ciphertext = key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
    return ciphertext


def asymmetric_decrypt(cipher, key):
    plaintext = key.decrypt(
        cipher,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
    return plaintext


def generate_keys(size=4096, public_name='pubkey', private_name='private', password=None):
    # generate private key & write to disk
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=size,
        backend=default_backend()
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )
    save_file(private_name + ".pem", pem)

    # generate public key
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    save_file(public_name + ".pem", pem)
    return public_key, private_key


def get_serialized_key(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem


def sign(data_to_send, private_key):
    return private_key.sign(
        data_to_send,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def check_authority(data, signature, public_key):
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False


def read_publickey_from_file(path):
    with open(path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read())
    return public_key


def read_privatekey_from_file(path, password):
    with open(path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password.encode(),
        )
    return private_key


def hash(text):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(text.encode())
    return digest.finalize().hex()


def sign_and_encrypt(data_to_send, private_key, session_cipher):
    signature = sign(json.dumps(data_to_send).encode('latin-1'), private_key)
    msg = {'data': data_to_send, 'signature': signature.decode('latin-1')}
    msg = symmetric_encrypt(plain_text=json.dumps(msg).encode('latin-1'), cipher=session_cipher)
    return msg
