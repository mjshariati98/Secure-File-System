import os
import sqlite3
import json
from pathlib import Path

import server_utils
from file_tree import default_file_tree, create_directory, locate_path, set_file_name

DIR_NAME = os.path.dirname(__file__)
DB_PATH = os.path.join(DIR_NAME, "server.db")
PRV_KEY_PATH = os.path.join(DIR_NAME, 'prv.key')
PUB_KEY_PATH = os.path.join(DIR_NAME, 'pub.key')
DATA_PATH = os.path.join(DIR_NAME, 'data')


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
    server_utils.save_key_pair(prv_key, pub_key, path=".")  # TODO correct method


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
            print("Not verified by user public key")
            return  # TODO
        password = server_utils.symmetric_decrypt(session_key, nonce, tag, encrypted_password)
        if password is None:
            print("Not verified by session key tag")  # TODO

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
            print("Not verified by session key tag")  # TODO

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
        print("Not verified by session key tag")  # TODO
    user_command = user_command.decode()

    command = user_command.split(" ")[0]
    if command == "mkdir":  # TODO hash addresses
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
            return Path(os.path.join(DATA_PATH, ft['content'])).read_text(), None
        except Exception as err:
            return "An error occurred while ls", err
    elif command == "set":
        try:
            path = user_command.split(" ")[1]
            value = " ".join(user_command.split(" ")[2:])
            file_tree = get_user_file_tree(username)
            try:
                ft = locate_path(file_tree, path)
                file_name = ft['content']
            except IndexError:  # file not exist
                file_name = os.urandom(40).hex()
            file_to_write = Path(os.path.join(DATA_PATH, file_name))
            file_to_write.write_text(value)
            # TODO check permission
            set_file_name(file_tree, path, file_name)
            store_user_file_tree(username, file_tree)
            return None, None
        except Exception as err:
            return "An error occurred while setting text of the file", err
    elif command == "cd":
        pass  # TODO
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
        pass  # TODO
    elif command == "mv":
        pass  # TODO
    elif command == "share":
        pass  # TODO
    elif command == "revoke":
        pass  # TODO
    else:
        return "Command not found", None


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


def get_user_file_tree(username):
    results = exec_db_command_with_result("SELECT file_tree FROM users WHERE username=:username",
                                          {"username": username})
    return json.loads(results[0][0])


def store_user_file_tree(username, file_tree):
    exec_db_command_with_result("UPDATE users SET file_tree=:file_tree WHERE username=:username",
                                {"username": username, "file_tree": json.dumps(file_tree)})


if __name__ == '__main__':
    initialize()
