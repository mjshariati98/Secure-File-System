from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os
from Crypto.Random import get_random_bytes

RSA_KEY_BITS = 4096
AES_KEY_BITS = 128


def load_server_pub_key(path):
    return load_key(path)


def generate_RSA_key_pair():
    prv_key = RSA.generate(RSA_KEY_BITS)
    pub_key = prv_key.publickey()

    return prv_key, pub_key


def save_key_pair(prv_key, pub_key, path):
    prv_key_PEM = prv_key.exportKey().decode('ascii')
    prv_key_path = os.path.join(path, "prv.key")
    write_to_file(prv_key_PEM, prv_key_path)

    pub_key_PEM = pub_key.exportKey().decode('ascii')
    pub_key_path = os.path.join(path, "pub.key")
    write_to_file(pub_key_PEM, pub_key_path)

    return prv_key_path, pub_key_path


def load_key(path):
    key_PEM = read_file(path)
    key = RSA.import_key(key_PEM)
    return key


def get_pub_key(prv_key):
    return prv_key.publickey()


def write_to_file(content, path):
    f = open(path, "w")
    f.write(content)
    f.close()


def read_file(path):
    f = open(path, "r")
    return f.read()


def asymmetric_encrypt(key, data):
    encryptor = PKCS1_OAEP.new(key)
    if not isinstance(data, bytes):
        data = data.encode()
    encrypted_data = encryptor.encrypt(data)
    return encrypted_data


def asymmetric_decrypt(key, encrypted_data):
    decryptor = PKCS1_OAEP.new(key)
    data = decryptor.decrypt(encrypted_data)
    return data


def asymmetric_sign(key, data):
    signer = pkcs1_15.new(key)
    hash_obj = SHA256.new(data)
    signature = signer.sign(hash_obj)
    return signature


def asymmetric_sign_verify(key, data, signature):
    verifier = pkcs1_15.new(key)
    hash_obj = SHA256.new(data)
    try:
        verifier.verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False


def symmetric_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())

    return ciphertext, nonce, tag


def symmetric_decrypt(key, nonce, tag, ciphertext):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext
    except ValueError:
        return None


def generate_session_key():
    return get_random_bytes(AES_KEY_BITS // 8)


def path_with_respect_to_cd(client, path):
    if not path.startswith("/"):
        return os.path.join(client.current_path, path)
    else:
        return path
