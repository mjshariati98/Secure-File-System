from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os

RSA_KEY_BITS = 4096


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


def import_key(key_PEM):
    return RSA.import_key(key_PEM)


def write_to_file(content, path):
    f = open(path, "w")
    f.write(content)
    f.close()


def read_file(path):
    f = open(path, "r")
    return f.read()


def is_key_generated(path):
    return os.path.exists(path)


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


def get_hash(data):
    hash_obj = SHA256.new(data)
    return hash_obj.hexdigest()


def export_key(key):
    return key.exportKey().decode('ascii')
