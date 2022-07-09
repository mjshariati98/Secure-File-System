import os
import sqlite3

import server_utils

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
    username varchar(256) NOT NULL, hashed_password text NOT NULL, pub_key text NOT NULL, session_key text, PRIMARY KEY (username)
    )""")


def sign_up(username, encrypted_password, nonce, tag, password_signature, encrypted_session_key, user_pub_key):
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

        add_user_to_db(username, hashed_password, server_utils.export_key(user_pub_key))
        set_session_key(username, session_key)
        create_user_home_dir(username)
        return True, None
    except Exception as err:
        return False, err


def add_user_to_db(username, password, user_pub_key):
    exec_db_command("INSERT INTO users (username, hashed_password, pub_key) VALUES (:username, :password, :pub_key)",
                    {"username": username, "password": password, "pub_key": user_pub_key})


def set_session_key(username, session_key):
    exec_db_command("UPDATE users SET session_key = :session_key WHERE username=:username",
                    {"username": username, "session_key": session_key})


def create_user_home_dir(username):
    home_dir_path = server_utils.home_dir_path(username, DATA_PATH)
    if not os.path.exists(home_dir_path):
        os.mkdir(home_dir_path)


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
            new_dir_path = os.path.join(DATA_PATH, path[1:])
            # TODO check permission
            os.makedirs(new_dir_path, exist_ok=True)
            return None, None
        except Exception as err:
            return "An error occurred while creating new directory", err
    elif command == "touch":
        pass  # TODO
    elif command == "cd":
        pass  # TODO
    elif command == "ls":
        pass  # TODO
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
    db_cursor.execute(*args)
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


def get_user_session_key(username):
    results = exec_db_command_with_result("SELECT session_key FROM users WHERE username=:username",
                                          {"username": username})
    return results[0][0]


if __name__ == '__main__':
    initialize()
