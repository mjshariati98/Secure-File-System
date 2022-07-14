import sys
import os
import base64

sys.path.append("..")
sys.path.append("../server")

import client_utils
from vim import edit_file_in_vim

import server.api

SERVER_PUB_KEY_PATH = "../server/pub.key"  # It should be in the client side but we do this to be simpler.

SEPARATOR = "///Xvc6$8Jf_SEPARATOR_X90kNb%2a///"


def main():
    server_pub_key = client_utils.load_server_pub_key(SERVER_PUB_KEY_PATH)

    print("Welcome to your Secure File System!")

    client = None

    valid_input = False
    while valid_input is False:
        print("1: Sing-in")
        print("2: Sign-up")
        user_input = input("Enter your choice (`exit` for exit from the program): ")
        if user_input == 'exit':
            raise SystemExit
        elif user_input == '1':
            client = handle_sign_in(server_pub_key)
            if client is not None:
                valid_input = True
        elif user_input == '2':
            client = handle_sign_up(server_pub_key)
            if client is not None:
                valid_input = True
        else:
            print("Invalid input. Try again...")

    handle_client_commands(client)


def handle_sign_in(server_pub_key):
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    # Generate session key and encrypt password with it
    session_key = client_utils.generate_random_symmetric_key()
    encrypted_password, nonce, tag = client_utils.symmetric_encrypt(session_key, password)

    # Encrypt session key with server public key
    encrypted_session_key = client_utils.asymmetric_encrypt(server_pub_key, session_key)

    msg, err = server.api.sign_in_user(username, encrypted_password, nonce, tag, encrypted_session_key)
    print(msg)
    if err is not None:
        print(err)
        return None

    client_keys = handle_load_key_pair()  # TODO Do not check that the key belongs to the user
    client = Client(client_keys)
    client.username = username
    client.session_key = session_key
    client.current_path = "~"

    return client


def handle_sign_up(server_pub_key):
    client_keys = None

    valid_input = False
    while valid_input is False:
        print("1: Load your RSA key pair from the disk")
        print("2: Generate a new RSA key pair")
        user_input = input("Enter your choice (`exit` for exit from the program): ")
        if user_input == 'exit':
            raise SystemExit
        elif user_input == '1':
            valid_input = True
            client_keys = handle_load_key_pair()
        elif user_input == '2':
            valid_input = True
            client_keys = handle_generate_key_pair()
        else:
            print("Invalid input. Try again...")

    client = Client(client_keys)

    username = input("Enter your username: ")
    password = input("Enter your password: ")
    name = input("Enter your name: ")

    client.username = username
    client.session_key = client_utils.generate_random_symmetric_key()

    # First encrypt password with session key, then sign it with client private key
    encrypted_password, nonce, tag = client_utils.symmetric_encrypt(client.session_key, password)
    password_signature = client_utils.asymmetric_sign(client.client_keys.prv_key, encrypted_password)

    # Also encrypt session key with server public key
    encrypted_session_key = client_utils.asymmetric_encrypt(server_pub_key, client.session_key)

    msg, err = server.api.sign_up_user(name, username, encrypted_password, nonce, tag, password_signature, encrypted_session_key,
                                       client.client_keys.pub_key)
    print(msg)
    if err is not None:
        print(err)
        return None

    client.current_path = "~"
    return client


def handle_load_key_pair():
    user_input = input("Enter you private key path to load (default is `./prv.key`): ")
    if user_input == "":
        user_input = "./prv.key"
    prv_key = client_utils.load_key(user_input)
    pub_key = client_utils.get_pub_key(prv_key)
    client_keys = ClientKeys(prv_key, pub_key)
    return client_keys


def handle_generate_key_pair():
    user_input = input("Enter a directory path to save your private and public keys (`.` for current directory): ")
    if user_input == 'exit':
        raise SystemExit
    else:
        prv_key, pub_key = client_utils.generate_RSA_key_pair()
        prv_key_path, pub_key_path = client_utils.save_key_pair(prv_key, pub_key, path=user_input)
        print("Private key generated in " + prv_key_path)
        print("Public key generated in " + pub_key_path)
        client_keys = ClientKeys(prv_key, pub_key)
        return client_keys


def handle_client_commands(client):
    while True:
        current_path = client.current_path
        user_command = input(client.username + ":" + current_path + "$ ")
        command = user_command.split(" ")[0]

        if command == "exit":
            raise SystemExit
        elif command == "mkdir":
            if len(user_command.split(" ")) != 2:
                print("command mkdir gets only 1 argument")
                continue

            path = client_utils.path_with_respect_to_cd(client, user_command.split(" ")[1])
            final_command = "mkdir " + path
            encrypted_command, nonce, tag = client_utils.symmetric_encrypt(client.session_key, final_command)
            response, err = server.api.user_command(client.username, encrypted_command, nonce, tag)
            if err is not None:
                print(response)
                print(err)
        elif command == "touch":
            if len(user_command.split(" ")) != 2:
                print("command touch gets only 1 argument")
                continue
            path = client_utils.path_with_respect_to_cd(client, user_command.split(" ")[1])
            write_file(client, path, "")
        elif command == "cd":
            pass  # TODO
        elif command == "ls":
            if len(user_command.split(" ")) > 2:
                print("command ls gets only 1 argument")
                continue
            path = "."
            if len(user_command.split(" ")) == 2:
                path = user_command.split(" ")[1]
            final_command = "ls " + client_utils.path_with_respect_to_cd(client, path)
            encrypted_command, nonce, tag = client_utils.symmetric_encrypt(client.session_key, final_command)
            response, err = server.api.user_command(client.username, encrypted_command, nonce, tag)
            if err is not None:
                print(response)
                print(err)
            else:
                print(response)
        elif command == "rm":
            pass  # TODO
        elif command == "mv":
            pass  # TODO
        elif command == "share":
            pass  # TODO
        elif command == "revoke":
            pass  # TODO
        elif command == "vim":
            path = client_utils.path_with_respect_to_cd(client, user_command.split(" ")[1])
            value, enc_key = read_file(client, path)
            if value is not None:
                write_file(client, path, edit_file_in_vim(value), enc_key=enc_key)
        else:
            print("command " + command + " not found")


def write_file(client, path, value, enc_key=None):
    if enc_key is None:
        enc_key = client_utils.generate_random_symmetric_key()
    encrypted_value, nonce, tag = client_utils.symmetric_encrypt(enc_key, value)

    # encrypt enc_key with client pub key
    encrypted_enc_key = client_utils.asymmetric_encrypt(client.client_keys.pub_key, enc_key)
    final_command = "set " + SEPARATOR + \
                    path + SEPARATOR + \
                    base64.b64encode(encrypted_value).decode() + SEPARATOR + \
                    base64.b64encode(encrypted_enc_key).decode() + SEPARATOR + \
                    base64.b64encode(tag).decode() + SEPARATOR + base64.b64encode(nonce).decode()
    encrypted_command, nonce, tag = client_utils.symmetric_encrypt(client.session_key, final_command)
    response, err = server.api.user_command(client.username, encrypted_command, nonce, tag)
    if err is not None:
        print(response)
        print(err)


def read_file(client, path):
    final_command = f"get {path}"
    encrypted_command, nonce, tag = client_utils.symmetric_encrypt(client.session_key, final_command)
    response, err = server.api.user_command(client.username, encrypted_command, nonce, tag)
    if err is not None:
        print(response)
        print(err)
        return None, None

    encrypted_value = base64.b64decode(response.split(SEPARATOR)[0])
    encrypted_enc_key = base64.b64decode(response.split(SEPARATOR)[1])
    tag = base64.b64decode(response.split(SEPARATOR)[2])
    nonce = base64.b64decode(response.split(SEPARATOR)[3])

    # decrypt enc_key using client prv key
    enc_key = client_utils.asymmetric_decrypt(client.client_keys.prv_key, encrypted_enc_key)

    # decrypt file using enc_key
    value = client_utils.symmetric_decrypt(enc_key, nonce, tag, encrypted_value)
    if value is None:
        print("File corrupted!")
        return None
    return value.decode('utf-8'), enc_key


class Client:
    username = None
    session_key = None
    current_path = None

    def __init__(self, client_keys):
        self.client_keys = client_keys


class ClientKeys:
    def __init__(self, prv_key, pub_key):
        self.prv_key = prv_key
        self.pub_key = pub_key


if __name__ == "__main__":
    main()
