import os
import sqlite3
import json
from pathlib import Path

import server_utils
from file_tree import *

DIR_NAME = os.path.dirname(__file__)
DB_PATH = os.path.join(DIR_NAME, "server.db")
PRV_KEY_PATH = os.path.join(DIR_NAME, 'prv.key')
PUB_KEY_PATH = os.path.join(DIR_NAME, 'pub.key')
DATA_PATH = os.path.join(DIR_NAME, 'data')

SEPARATOR = "///Xvc6$8Jf_SEPARATOR_X90kNb%2a///"


def initialize():
    print("Starting Server ...")

    # Generate keys
    if not server_utils.is_key_generated(PRV_KEY_PATH):
        generate_keys()
        print("Server keys generated")

    # Create data directory
    if not os.path.exists(DATA_PATH):
        os.mkdir(DATA_PATH)

    # Create Database tables
    create_db_tables()


def generate_keys():
    prv_key, pub_key = server_utils.generate_RSA_key_pair()
    server_utils.save_key_pair(prv_key, pub_key, path=".")


def create_db_tables():
    # users table
    exec_db_command("""CREATE TABLE IF NOT EXISTS users (
    name varchar(256) NOT NULL,
    username varchar(256) NOT NULL,
    hashed_password text NOT NULL,
    pub_key text NOT NULL,
    file_tree text,
    session_key text, PRIMARY KEY (username)
    )""")


def sign_up(name, username, encrypted_password, nonce, tag, password_signature, encrypted_session_key, user_pub_key):
    try:
        server_prv_key = server_utils.load_key(PRV_KEY_PATH)

        session_key = server_utils.asymmetric_decrypt(server_prv_key, encrypted_session_key)

        verified = server_utils.asymmetric_sign_verify(user_pub_key, encrypted_password, password_signature)
        if not verified:
            return False, "Password signature not verified by user public key"
        password = server_utils.symmetric_decrypt(session_key, nonce, tag, encrypted_password)
        if password is None:
            return False, "Password corrupted"

        hashed_password = server_utils.get_hash(password)

        add_user_to_db(name, username, hashed_password, server_utils.export_key(user_pub_key))
        set_session_key(username, session_key)
        return True, None
    except Exception as err:
        return False, err


def sign_in(username, encrypted_password, nonce, tag, encrypted_session_key):
    try:
        server_prv_key = server_utils.load_key(PRV_KEY_PATH)

        session_key = server_utils.asymmetric_decrypt(server_prv_key, encrypted_session_key)

        password = server_utils.symmetric_decrypt(session_key, nonce, tag, encrypted_password)
        if password is None:
            return False, "Password corrupted"

        try:
            user_hashed_password = get_user_hashed_password(username)
        except IndexError:  # no such user in database
            return False, "Invalid credentials"

        if user_hashed_password != server_utils.get_hash(password):
            return False, "Invalid credentials"

        set_session_key(username, session_key)
        return True, None
    except Exception as err:
        return False, err


def check_key_match(username, text, encrypted_signature, nonce, tag):
    user_session_key = get_user_session_key(username)
    user_pub_key = server_utils.import_key(get_user_pub_key(username))

    signature = server_utils.symmetric_decrypt(user_session_key, nonce, tag, encrypted_signature)
    if signature is None:
        return False, "Signature corrupted"

    verified = server_utils.asymmetric_sign_verify(user_pub_key, text, signature)
    if not verified:
        return False, "This key is not matched with the user's stored key at the server"
    return True, None


def add_user_to_db(name, username, password, user_pub_key):
    exec_db_command(
        "INSERT INTO users (name, username, hashed_password, pub_key, file_tree) VALUES (:name, :username, :password, :pub_key, :file_tree)",
        {
            "name": name,
            "username": username,
            "password": password,
            "pub_key": user_pub_key,
            "file_tree": json.dumps(default_file_tree()),
        })


def set_session_key(username, session_key):
    exec_db_command("UPDATE users SET session_key = :session_key WHERE username=:username",
                    {"username": username, "session_key": session_key})


def exec_user_command(username, encrypted_command, nonce, tag):
    user_session_key = get_user_session_key(username)
    user_command = server_utils.symmetric_decrypt(user_session_key, nonce, tag, encrypted_command)
    if user_command is None:
        return None, "Command corrupted"
    user_command = user_command.decode()

    command = user_command.split(" ")[0]
    if command == "mkdir":
        try:
            path = user_command.split(" ")[1]
            file_tree = get_user_file_tree(username)
            # TODO check permission
            create_directory(file_tree, path)
            store_user_file_tree(username, file_tree)
            return None, None
        except Exception as err:
            return "An error occurred while creating new directory", err
    elif command == "get":
        try:
            path = user_command.split(" ")[1]
            file_tree = get_user_file_tree(username)
            # TODO check permission
            try:
                ft = locate_path(file_tree, path)
            except IndexError:
                return "An error occurred while reading file", "File not found"
            if ft['type'] != 'file':
                return "An error occurred while reading file", f"{ft['name']} is not a file"

            if not os.path.exists(os.path.join(DATA_PATH, ft['fs_file_name'])):
                return "An error occurred while reading file", "File is lost!"
            encrypted_value = Path(os.path.join(DATA_PATH, ft['fs_file_name'])).read_text()
            enc_key = ft['enc_key']
            tag = ft['tag']
            nonce = ft['nonce']

            response = encrypted_value + SEPARATOR + enc_key + SEPARATOR + tag + SEPARATOR + nonce
            return response, None
        except Exception as err:
            return "An error occurred while reading file", err
    elif command == "set":
        try:
            path = user_command.split(SEPARATOR)[1]
            encrypted_value = user_command.split(SEPARATOR)[2]
            enc_key = user_command.split(SEPARATOR)[3]
            tag = user_command.split(SEPARATOR)[4]
            nonce = user_command.split(SEPARATOR)[5]

            file_tree = get_user_file_tree(username)
            try:
                ft = locate_path(file_tree, path)
                file_name = ft['fs_file_name']
            except IndexError:  # file not exist
                file_name = os.urandom(40).hex()
            file_to_write = Path(os.path.join(DATA_PATH, file_name))
            file_to_write.write_text(encrypted_value)
            # TODO check permission
            set_file(file_tree, path, file_name, enc_key, tag, nonce)
            store_user_file_tree(username, file_tree)
            return None, None
        except Exception as err:
            return "An error occurred while setting text of the file", err
    elif command == "cd":
        try:
            path = user_command.split(" ")[1]
            file_tree = get_user_file_tree(username)
            # TODO check permission
            try:
                ft = locate_path(file_tree, path)
            except IndexError:
                return "An error occurred while cd", f"Directory not found"
            if ft['type'] != 'folder':
                return "An error occurred while cd", f"{ft['name']} is not a folder"
            return "OK", None
        except Exception as err:
            return "An error occurred while cd", err
    elif command == "ls":
        try:
            path = user_command.split(" ")[1]
            file_tree = get_user_file_tree(username)
            # TODO check permission
            try:
                ft = locate_path(file_tree, path)
            except IndexError:
                return "An error occurred while ls", f"Directory not found"
            if ft['type'] != 'folder':
                return "An error occurred while ls", f"{ft['name']} is not a folder"
            return "\t".join([x['name'] for x in ft['files']]), None
        except Exception as err:
            return "An error occurred while ls", err
    elif command == "rm":
        try:
            path = user_command.split(" ")[-1]
            file_tree = get_user_file_tree(username)
            try:
                ft = locate_path(file_tree, path)
            except IndexError:
                return "An error occurred while removing file", "File not found"
            if ft['type'] == 'folder' and user_command.split(" ")[-2] != "-r":
                return "An error occurred while removing file", "Folder need -r"
            r, e = None, None
            for x in iterate_subtree_files(ft):
                try:
                    os.remove(os.path.join(DATA_PATH, x['fs_file_name']))
                except Exception as err:
                    r, e = f"File {x['fs_file_name']} is also removed by enemy", err
            remove_subtree(file_tree, path)
            store_user_file_tree(username, file_tree)
            return r, e
        except Exception as err:
            return "An error occurred while removing", err
    elif command == "mv":
        try:
            from_path = user_command.split(" ")[-2]
            to_path = user_command.split(" ")[-1]
            file_tree = get_user_file_tree(username)
            try:
                ft = locate_path(file_tree, from_path)
            except IndexError:
                return "An error occurred while removing file", "File not found"
            if ft['type'] == 'folder' and user_command.split(" ")[-3] != "-r":
                return "An error occurred while removing file", "Folder need -r"
            remove_subtree(file_tree, from_path)
            insert_subtree(file_tree, to_path, ft)
            store_user_file_tree(username, file_tree)
            return None, None
        except Exception as err:
            return "An error occurred while removing", err
    elif command == "share":
        try:
            _, target_user, path = user_command.split(" ")
            file_tree = get_user_file_tree(username)
            target_file_tree = get_user_file_tree(target_user)
            try:
                ft = locate_path(file_tree, path)
            except IndexError:
                return "An error occurred while sharing file", "File not found"
            if ft['type'] == 'folder':
                return "An error occurred while sharing file", "Share folder is not implemented yet"
            insert_subtree(target_file_tree, path.replace("~", f"{username}"), ft)
            store_user_file_tree(target_user, target_file_tree)
            return None, None
        except Exception as err:
            return "An error occurred while sharing", err
    elif command == "revoke":
        pass  # TODO
    else:
        return None, "Command not found"


def db_connection():
    db_conn = sqlite3.connect(DB_PATH)
    db_cursor = db_conn.cursor()
    return db_conn, db_cursor


def exec_db_command(*args):
    db_conn, db_cursor = db_connection()
    try:
        db_cursor.execute(*args)
    finally:
        db_conn.commit()
        db_conn.close()


def exec_db_command_with_result(*args):
    db_conn, db_cursor = db_connection()
    results = []
    for row in db_cursor.execute(*args):
        results.append(row)
    db_conn.commit()
    db_conn.close()

    return results


def get_user_hashed_password(username):
    results = exec_db_command_with_result("SELECT hashed_password FROM users WHERE username=:username",
                                          {"username": username})
    return results[0][0]


def get_user_session_key(username):
    results = exec_db_command_with_result("SELECT session_key FROM users WHERE username=:username",
                                          {"username": username})
    return results[0][0]


def get_user_pub_key(username):
    results = exec_db_command_with_result("SELECT pub_key FROM users WHERE username=:username",
                                          {"username": username})
    return results[0][0]


def get_user_file_tree(username):
    results = exec_db_command_with_result("SELECT file_tree FROM users WHERE username=:username",
                                          {"username": username})
    return json.loads(results[0][0])


def store_user_file_tree(username, file_tree):
    exec_db_command_with_result("UPDATE users SET file_tree=:file_tree WHERE username=:username",
                                {"username": username, "file_tree": json.dumps(file_tree)})


if __name__ == '__main__':
    initialize()
