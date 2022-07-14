from .server import *


def sign_up_user(name, username, encrypted_password, nonce, tag, password_signature, encrypted_session_key, user_pub_key):
    successful, err = sign_up(name, username, encrypted_password, nonce, tag, password_signature, encrypted_session_key, user_pub_key)
    if successful:
        return "User signed up successfully", None
    else:
        return "An error occurred during signing up user", err


def sign_in_user(username, encrypted_password, nonce, tag, encrypted_session_key):
    successful, err = sign_in(username, encrypted_password, nonce, tag, encrypted_session_key)
    if successful:
        return "User signed in successfully", None
    else:
        return "An error occurred during signing in user", err


def user_command(username, encrypted_command, nonce, tag):
    response, err = exec_user_command(username, encrypted_command, nonce, tag)
    return response, err
