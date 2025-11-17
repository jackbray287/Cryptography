# Simple File Transfer (SiFT) v1.0

## Overview
SiFT v1.0 is a secure file transfer protocol that allows clients to send commands to a server for file manipulation, including uploading and downloading files. This project implements the SiFT v1.0 protocol, which includes cryptographic protections against eavesdropping, message modification, and replay attacks.

## Project Structure
The project is organized into the following directories and files:

```
sift-v1
├── client
│   ├── client.py                  # Main client application
│   ├── siftprotocols              # Package for client protocols
│   │   ├── __init__.py            # Initializes the siftprotocols package
│   │   ├── mtp.py                  # Message Transfer Protocol implementation
│   │   ├── login.py                # Login protocol implementation
│   │   ├── cmd.py                  # Commands protocol implementation
│   │   ├── upl.py                  # Upload protocol implementation
│   │   └── dnl.py                  # Download protocol implementation
│   └── keys
│       └── server_public.pem       # Public key for the server
├── server
│   ├── server.py                   # Main server application
│   ├── users.txt                   # User credentials storage
│   ├── users                        # Directory for user-specific folders
│   └── siftprotocols               # Package for server protocols
│       ├── __init__.py             # Initializes the siftprotocols package
│       ├── mtp.py                  # Message Transfer Protocol implementation
│       ├── login.py                # Login protocol implementation
│       ├── cmd.py                  # Commands protocol implementation
│       ├── upl.py                  # Upload protocol implementation
│       └── dnl.py                  # Download protocol implementation
│   └── keys
│       └── server_key.pem          # Private key for the server
├── docs
│   └── SiFT-v1.0-spec.md           # Specification document for SiFT v1.0
├── scripts
│   └── gen_keys.py                 # Utility script for generating RSA key pairs
├── tests
│   ├── test_login.py               # Unit tests for login functionality
│   └── test_mtp.py                 # Unit tests for MTP functionality
├── .gitignore                       # Files and directories to ignore in version control
├── pyproject.toml                  # Project configuration file
├── requirements.txt                 # Required Python packages
└── README.md                        # Project documentation
```

## Getting Started

### Prerequisites
- Python 3.x
- Required Python packages (install using `pip install -r requirements.txt`)

### Running the Server
1. Navigate to the `server` directory.
2. Start the server by running:
   ```
   python server.py
   ```

### Running the Client
1. Open a new terminal and navigate to the `client` directory.
2. Start the client by running:
   ```
   python client.py
   ```

### User Authentication
The server comes with predefined users. You can log in using the following credentials:
- Username: `alice`, Password: `aaa`
- Username: `bob`, Password: `bbb`
- Username: `charlie`, Password: `ccc`

### Commands
Once logged in, you can use the following commands:
- `pwd`: Print current working directory
- `lst`: List contents of the current directory
- `chd <directory>`: Change directory
- `mkd <directory>`: Make a new directory
- `del <file/directory>`: Delete a file or directory
- `upl <file>`: Upload a file
- `dnl <file>`: Download a file

## Contributing
Contributions are welcome! Please submit a pull request or open an issue for any enhancements or bug fixes.

## License
This project is licensed under the MIT License. See the LICENSE file for details.