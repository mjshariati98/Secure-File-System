# Secure File System

## System Architecture
The system consists of 3 parts: Client, Server, and Data Storage

### Client
It's a Command Line Interface (CLI) between a user and server that provides the following:
- A Unix-like terminal that gets commands from the user
- Send the user's commands to the server and receive and show the server's responses
- Symmetric and Asymmetric encryption and decryption
- Key generation and management

### Server
An Honest but curious module that provides:
- User Authentication and Authorization
- Validate requests and send appropriate responses
- Put/Get files to/from Data Storage

### Data Storage
An untrusted module that stores users' files.

## Features

### User Authentication
Users can create accounts and access the file system by providing their username and password.

### Validate Requests
The server validates the user's request for files and paths with Discretionary Access Control (DAC).

### Files and Paths Commands
Supported commands are as follows (Paths can be absolute or relative):
- mkdir
- touch
- cd
- ls
- rm
- mv

### Edit File Contents
Users can view and edit their file contents by providing the `vim` command.

### Server's Confidentiality
All data (files, directories, users' information, etc.) stored on the server side is encrypted.

### Secure File Sharing
Users can share their own files with other users in two modes: readable (r) or readable and writable (rw). The following commands are provided for this purpose:
- `share <file_name> <username> <mode>`
- `revoke <file_name> [username]`

## Security Features
The following features have been provided to make the file system secure:
- An attacker with **full access** to Data Storage isn't able to find out anything about the user's information or files (like the number of total users of the system or the number of files/directories each user has). 
- An attacker with **full access** to the server's Access Control mechanism isn't able to reach the user's file contents.
- Any malicious change (Add, remove, or modify) of Data storage files is recognizable by the server.
- Server is not able to read or change users' file contents.
- Every file is encrypted with a distinct key.
- Lack of need to re-encrypt a file with a different key after revoking some user's access to a file.

## How to run
To run the file system, run the following commands:
```
docker build -t file-system:1.0 .
docker run -it file-system:1.0
``` 