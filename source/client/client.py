import sys
import os
import base64
import pwinput

sys.path.append("..")
sys.path.append("../server")

import client_utils
from vim import edit_file_in_vim

import server.api

SERVER_PUB_KEY_PATH = "../server/pub.key"  # It should be in the client side but we do this to be simpler.

SEPARATOR = "///Xvc6$8Jf_SEPARATOR_X90kNb%2a///"
ALL_USERS = "__all_users__"


def main():
    server_pub_key = client_utils.load_server_pub_key(SERVER_PUB_KEY_PATH)

    print("Welcome to your Secure File System!")

    client = None

    valid_input = False
    while valid_input is False:
        print("1: Sing-in")
        print("2: Sign-up")
        user_input = input("Enter your choice (`exit` for exit from the file-system): ")
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
    password = pwinput.pwinput("Enter your password: ")

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

    client_keys = None
    while client_keys is None:
        client_keys, err = handle_load_key_pair()
        if client_keys is None:
            print("An error occurred while loading keys")
            print(err)

    # Check this key is the same key that the user was signed up with
    text = "CHECK KEY".encode('utf-8')
    signature = client_utils.asymmetric_sign(client_keys.prv_key, text)
    encrypted_signature, nonce, tag = client_utils.symmetric_encrypt(session_key, signature)
    msg, err = server.api.check_key(username, text, encrypted_signature, nonce, tag)
    print(msg)
    if err is not None:
        print(err)
        return None

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
            client_keys, err = handle_load_key_pair()
            if client_keys is None:
                print("An error occurred while loading keys")
                print(err)
            else:
                valid_input = True
        elif user_input == '2':
            client_keys, err = handle_generate_key_pair()
            if client_keys is None:
                print("An error occurred while creating keys")
                print(err)
            else:
                valid_input = True
        else:
            print("Invalid input. Try again...")

    client = Client(client_keys)

    username = input("Enter your username: ")
    password = pwinput.pwinput("Enter your password: ")
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
    try:
        user_input = input("Enter you private key path to load (default is `./prv.key`): ")
        if user_input == "":
            user_input = "./prv.key"
        prv_key = client_utils.load_key(user_input)
        pub_key = client_utils.get_pub_key(prv_key)
        client_keys = ClientKeys(prv_key, pub_key)
        return client_keys, None
    except Exception as err:
        return None, err


def handle_generate_key_pair():
    try:
        user_input = input("Enter a directory path to save your private and public keys (`.` for current directory): ")
        if user_input == 'exit':
            raise SystemExit
        else:
            os.makedirs(user_input, exist_ok=True)
            prv_key, pub_key = client_utils.generate_RSA_key_pair()
            prv_key_path, pub_key_path = client_utils.save_key_pair(prv_key, pub_key, path=user_input)
            print("Private key generated in " + prv_key_path)
            print("Public key generated in " + pub_key_path)
            client_keys = ClientKeys(prv_key, pub_key)
            return client_keys, None
    except Exception as err:
        return None, err


def handle_client_commands(client):
    while True:
        current_path = client.current_path
        user_command = input(client.username + ":" + current_path + "$ ")
        command = user_command.split(" ")[0]

        if command == "exit":
            main()
            return
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
            final_command = f"exists {path}"
            encrypted_command, nonce, tag = client_utils.symmetric_encrypt(client.session_key, final_command)
            response, err = server.api.user_command(client.username, encrypted_command, nonce, tag)
            if err is not None:
                print(response)
                print(err)
                continue
            if response:
                print("Can not touch existing file")
                continue
            response, err = write_file(client, path, "")
            if err is not None:
                print(response)
                print(err)
        elif command == "cd":
            if len(user_command.split(" ")) != 2:
                print("command cd gets 1 argument")
                continue
            path = client_utils.path_with_respect_to_cd(client, user_command.split(" ")[1])
            final_command = f"cd {path}"
            encrypted_command, nonce, tag = client_utils.symmetric_encrypt(client.session_key, final_command)
            response, err = server.api.user_command(client.username, encrypted_command, nonce, tag)
            if err is not None:
                print(response)
                print(err)
            else:
                client.current_path = path[len(client.username) + 1:]
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
            user_command_parts = user_command.split(" ")
            if len(user_command_parts) != 2 and user_command_parts[1] != "-r":
                print("bad arguments for rm")
                continue
            user_command_parts[-1] = client_utils.path_with_respect_to_cd(client, user_command_parts[-1])
            final_command = " ".join(user_command_parts)
            encrypted_command, nonce, tag = client_utils.symmetric_encrypt(client.session_key, final_command)
            response, err = server.api.user_command(client.username, encrypted_command, nonce, tag)
            if response is not None:
                print(response)
            if err is not None:
                print(err)
        elif command == "mv":
            user_command_parts = user_command.split(" ")
            if len(user_command_parts) != 3 and user_command_parts[1] != "-r":
                print("bad arguments for mv")
                continue
            user_command_parts[-1] = client_utils.path_with_respect_to_cd(client, user_command_parts[-1])
            user_command_parts[-2] = client_utils.path_with_respect_to_cd(client, user_command_parts[-2])
            final_command = f"exists {user_command_parts[-1]}"
            encrypted_command, nonce, tag = client_utils.symmetric_encrypt(client.session_key, final_command)
            response, err = server.api.user_command(client.username, encrypted_command, nonce, tag)
            if err is not None:
                print(response)
                print(err)
                continue
            if response:
                print("mv can not override files")
                continue
            final_command = " ".join(user_command_parts)
            encrypted_command, nonce, tag = client_utils.symmetric_encrypt(client.session_key, final_command)
            response, err = server.api.user_command(client.username, encrypted_command, nonce, tag)
            if response is not None:
                print(response)
            if err is not None:
                print(err)
        elif command == "share":
            user_command_parts = user_command.split(" ")
            if len(user_command_parts) < 3 or len(user_command_parts) > 4:
                print("bad arguments for share")
                continue
            path = client_utils.path_with_respect_to_cd(client, user_command_parts[1])
            target_user = user_command_parts[2]
            share_mode = "r"
            if len(user_command_parts) == 4:
                share_mode = user_command_parts[3][1:]
            if not (share_mode == "r" or share_mode == "rw"):
                print("Invalid share mode. Support modes are -r, -rw")
                continue

            target_user_pubkey, err = get_users_pub_key(client, target_user)
            if err is not None:
                print(err)
                continue

            _, enc_key, user_access = read_file(client, path)
            if enc_key is None:
                continue
            if user_access != 'owner':
                print("Only owner of a file can share it.")
                continue

            # Encrypt enc_key with target user's pub key
            encrypted_enc_key = client_utils.asymmetric_encrypt(client_utils.import_key(target_user_pubkey), enc_key)

            final_command = "share " + SEPARATOR + \
                            target_user + SEPARATOR + \
                            path + SEPARATOR + \
                            share_mode + SEPARATOR + \
                            base64.b64encode(encrypted_enc_key).decode()
            encrypted_command, nonce, tag = client_utils.symmetric_encrypt(client.session_key, final_command)
            response, err = server.api.user_command(client.username, encrypted_command, nonce, tag)
            if response is not None:
                print(response)
            if err is not None:
                print(err)
        elif command == "revoke":
            user_command_parts = user_command.split(" ")
            if len(user_command_parts) < 2 or len(user_command_parts) > 3:
                print("bad arguments for share")
                print("example: revoke <file> <user> for revoking access from specific user or revoke <file> for revoking access for all users")
            path = client_utils.path_with_respect_to_cd(client, user_command_parts[1])
            target_user = ALL_USERS
            if len(user_command_parts) == 3:
                target_user = user_command_parts[2]

            final_command = f"revoke {path} {target_user}"
            encrypted_command, nonce, tag = client_utils.symmetric_encrypt(client.session_key, final_command)
            response, err = server.api.user_command(client.username, encrypted_command, nonce, tag)
            if response is not None:
                print(response)
            if err is not None:
                print(err)
        elif command == "vim":
            path = client_utils.path_with_respect_to_cd(client, user_command.split(" ")[1])
            value, enc_key, user_access = read_file(client, path)
            if value is not None:
                new_value = edit_file_in_vim(value, mode=user_access)
                if user_access == "owner" or user_access == "rw":
                    response, err = write_file(client, path, new_value, enc_key=enc_key)
                    if err is not None:
                        print(response)
                        print(err)
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
    return response, err


def read_file(client, path):
    final_command = f"get {path}"
    encrypted_command, nonce, tag = client_utils.symmetric_encrypt(client.session_key, final_command)
    response, err = server.api.user_command(client.username, encrypted_command, nonce, tag)
    if err is not None:
        print(response)
        print(err)
        return None, None, None

    encrypted_value = base64.b64decode(response.split(SEPARATOR)[0])
    encrypted_enc_key = base64.b64decode(response.split(SEPARATOR)[1])
    tag = base64.b64decode(response.split(SEPARATOR)[2])
    nonce = base64.b64decode(response.split(SEPARATOR)[3])
    user_access = response.split(SEPARATOR)[4]

    # decrypt enc_key using client prv key
    enc_key = client_utils.asymmetric_decrypt(client.client_keys.prv_key, encrypted_enc_key)

    # decrypt file using enc_key
    value = client_utils.symmetric_decrypt(enc_key, nonce, tag, encrypted_value)
    if value is None:
        print("File corrupted!")
        return None, None, None
    return value.decode('utf-8'), enc_key, user_access


def get_users_pub_key(client, username):
    command = f"pubkey {username}"
    encrypted_command, nonce, tag = client_utils.symmetric_encrypt(client.session_key, command)
    response, err = server.api.user_command(client.username, encrypted_command, nonce, tag)
    return response, err


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
