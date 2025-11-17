# SiFT v1.0 Specification

## Simple File Transfer v1.0
This document specifies version 1.0 of the Simple File Transfer (SiFT) protocol. SiFT can be used by a client to send file commands to a server, which executes those commands. SiFT supports the following 7 commands:

- **pwd** --> Print current working directory: Returns to the client the name of the current working directory on the server.
- **lst** --> List content of the current working directory: Returns to the client the list of files and directories in the current working directory on the server.
- **chd** --> Change directory: Changes the current working directory on the server. The name of the target directory is provided as an argument to the chd command.
- **mkd** --> Make directory: Creates a new directory on the server. The name of the directory to be created is provided as an argument to the mkd command.
- **del** --> Delete file or directory: Deletes a file or a directory on the server. The name of the file or directory to be deleted is provided as an argument to the del command.
- **upl** --> Upload file: Uploads a file from the client to the server. The name of the file to be uploaded is provided as an argument to the upl command and the file is put in the current working directory on the server.
- **dnl** --> Download file: Downloads a file from the current working directory of the server to the client. The name of the file to be downloaded is provided as an argument to the dnl command.

SiFT allows the client and the server to communicate via a network and execute the above commands remotely. It assumes that the client and the server use the TCP/IP protocol to establish a connection and to send data reliably to each other. By reliability, we mean that the bytes sent by a party arrive at the other party, and they arrive in the order that they were sent. The SiFT v1.0 server must listen and accept client connection requests on TCP port 5150.

On the other hand, unlike earlier versions, SiFT v1.0 does not assume that the network is secure, which means that an attacker may eavesdrop, modify, delete, and replay messages sent by the parties, and the attacker may also inject new messages. SiFT provides protection against these misdeeds by using a cryptographically secured message transfer sub-protocol. This sub-protocol uses symmetric key cryptographic primitives, and hence, needs shared secret keys. SiFT uses a login sub-protocol to establish the needed secret keys and to authenticate the client and the server to each other. 

## Overview of sub-protocols
SiFT v1.0 has the following sub-protocols: Message Transfer Protocol (MTP), Login Protocol, Commands Protocol, Upload Protocol, and Download Protocol. 

SiFT messages are carried by the Message Transfer Protocol (MTP), which provides cryptographic protection to them. Messages are encrypted, their integrity is protected, and sequence numbers are used to detect replay attacks. MTP uses symmetric key cryptographic primitives, which require secret keys shared between the client and the server. These keys are established by the Login Protocol.

The Login Protocol is used to authenticate the parties to each other and to establish the secret key between the client and the server to be used by MTP. The server is authenticated implicitly by requiring it to use its private key, whereas the client authenticates itself to the server by sending a username and a password to it. The secret key intended for MTP is derived from random numbers that the client and the server exchange in the Login Protocol. 

## SiFT v1.0 Message Transfer Protocol 
The SiFT v1.0 Message Transfer Protocol (MTP) uses cryptography to encrypt SiFT messages (i.e., commands and their arguments sent by the client to the server and the server's responses to them, as well as the files that are uploaded to or downloaded from the server), to protect their integrity, and to ensure their authenticity. MTP also uses sequence numbering of messages to protect against replay attacks. 

More specifically, SiFT v1.0 MTP uses AES in GCM mode, which provides encryption, integrity protection, and origin authentication of messages. The AES-GCM authentication tag covers the message sequence number (along with all other fields of the message header and the encrypted message payload), which is explicitly put in the message header (i.e., explicit sequence numbering is used). AES-GCM requires a symmetric key, which is established by the SiFT v1.0 Login Protocol.

### Message formats
All SiFT v1.0 MTP messages (except when the payload is a login request) have a specific format that includes a header and encrypted payload.

### Processing
When a TCP connection is established by the client to the server, the first message the client must send is a login request. The client generates a fresh random value and a temporary key, fills in the message header fields, encrypts the payload, and sends it to the server.

## SiFT v1.0 Login Protocol
The SiFT v1.0 Login Protocol is responsible for authenticating the client and the server to each other and for setting up the final transfer key to be used by the MTP protocol to protect MTP messages. 

### Message exchange
The Login Protocol consists of 2 message transfers: the client sends a login request to the server, and the server responds with a login response.

### Message formats
The Login Protocol is a text-based protocol, which means that message payloads are human-readable texts. All payloads must be encoded in UTF-8 coding in this version of the protocol.

## SiFT v1.0 Commands Protocol
The SiFT v1.0 Commands Protocol is responsible for sending the file commands of the client to the server and sending response messages to these commands. The Commands Protocol must only be used after successful login by the client to the server, and establishment of the final MTP transfer key.