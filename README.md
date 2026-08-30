# CN Assignment 1 Secure Chat Application

## Group Members

- Anveshaa Kabir Basnet (2405418) — client + cipher
- Ria Gracy Tigga (2405448) — README + documentation
- Diksha Nandi (2405493) — Server + concurrency + client registration + routing

---

## How to Build

### Requirements

- Windows
- C compiler with Winsock support (MinGW/GCC or Visual Studio)
- Wireshark for packet-capture verification

### GCC / MinGW

powershell
gcc server.c cipher.c -o server.exe -lws2_32
gcc client.c cipher.c -o client.exe -lws2_32

## How to Run

### Start the server

powershell
.\server.exe 5000


### Start a client

powershell
.\client.exe <server_ip> 5000


Example:

powershell
.\client.exe 10.20.66.23 5000

The client asks for a username and encryption key and registers using:

REGISTER <username> KEY <key>

Example:
REGISTER alice KEY mysecretkey
Successful registration:
REGISTERED alice

## Client-to-Client Communication

After registration, a client can send a message to another registered client.

Example:

Enter message to send: HELLO-WIRESHARK-123
Send to username: bob

The complete command is encrypted before it is sent to the server.

The communication flow is:


Client A
   |
   | Encrypt with A's key
   v
Server
   |
   | Decrypt with A's key
   | Parse destination
   | Re-encrypt with B's key
   v
Client B
   |
   | Decrypt with B's key
   v
Plaintext message


This is **hop-by-hop encryption**, not end-to-end encryption. The server temporarily handles the plaintext so it can determine the destination and re-encrypt the message using the receiver's key.

---

## Cipher Choice

The implementation uses a **Repeating-Key XOR cipher**.

The cipher is implemented manually in the project without using any
external cryptographic libraries.

For each byte of plaintext, the implementation XORs the byte with a
corresponding byte from the secret key. The key is repeated when the
plaintext is longer than the key.

Encryption and decryption use the same XOR operation:

    ciphertext = plaintext XOR repeating_key

    plaintext = ciphertext XOR repeating_key

The implementation operates on arbitrary byte values, allowing it to
process printable text as well as protocol delimiter characters.

### Protocol Encryption

All application-level communication is encrypted before being sent over
the TCP socket, including:

- Client registration messages
- Chat commands
- Server responses
- File-transfer related protocol data

The receiver decrypts the ciphertext using the appropriate key before
processing the command or displaying the message.

### Different Keys for Different Users

Each registered client has its own encryption key.

For example:

- Alice → `mysecretkey`
- Bob → `bobkey`

When Alice sends a message to Bob, the server uses Bob's registered key
when preparing the message for Bob. Therefore, the ciphertext transmitted
on the sender side can differ from the ciphertext transmitted on the
receiver side even though the underlying plaintext message is the same.

### Known Weakness

Repeating-Key XOR is a simple symmetric cipher and is not considered
cryptographically secure for real-world applications.

Its main weakness is that the key is reused periodically. If an attacker
obtains enough ciphertext/plaintext pairs or enough ciphertext encrypted
with the same key, information about the repeating key can potentially be
recovered. It also does not provide authentication or integrity protection.

The cipher is used here because it is one of the techniques explicitly
permitted by the assignment and is implemented manually for educational
purposes.

---

## Concurrency Model

The server uses a **thread-per-client** design.

For every accepted TCP connection, the server creates a Windows thread using `CreateThread(...)`. The client also creates a separate receiving thread so incoming messages can be handled while the user enters outgoing messages.

Threads were selected because they provide a direct and simple way to satisfy the assignment's requirement for simultaneous clients.

The current client table supports up to 10 client entries.

---

## Error Handling

### Duplicate username

ERROR username bob already taken

### Offline recipient

ERROR <username> is not online

### Invalid input

The server rejects malformed commands and unknown commands without terminating the server.

Examples:


ERROR invalid command
ERROR invalid SEND TO format
ERROR invalid username
ERROR empty message
ERROR unknown command


### Disconnect

When a client disconnects, the corresponding client state is cleaned up and its socket is closed.

---

## Text File Transfer

The application supports encrypted `.txt` file transfer between clients.

A file can be specified by a filename in the current directory or by a full path.

Examples:
SENDFILE TO bob: notes.txt

SENDFILE TO bob: C:\Users\User\Documents\notes.txt
The file-transfer flow is:

Sender
   |
   | Read .txt file
   | Encrypt using sender key
   v
Server
   |
   | Decrypt using sender key
   | Re-encrypt using receiver key
   v
Receiver
   |
   | Decrypt using receiver key
   | Save received file
```

### File-size limit

The configured maximum file size is **1 MB**.

Files exceeding the limit are rejected. The file protocol uses length-aware framing so file contents containing newlines can be transferred correctly.

---

## Testing

| Test | Status |
|---|---|
| At least 3 clients registered and communicating concurrently | Completed |
| Messages routed only to the intended recipient | Completed |
| Duplicate username rejected | Completed |
| Offline recipient rejected | Completed |
| Abrupt client disconnect handled | Completed |
| Malformed/garbage input handled | Completed |
| Two clients with different keys communicate | Completed |
| Wireshark different-ciphertext verification | Completed |
| Receiver decrypts the message correctly | Completed |
| Encrypt/decrypt round-trip tests | Completed |
| Small `.txt` file transfer | Completed |
| Relative filename transfer | Completed |
| Full-path transfer | Completed |
| Missing-file rejection | Completed |
| Oversized-file rejection | Completed |
| File-size limit documented | Completed |

---

## Wireshark Verification

Wireshark was used to verify that two clients using different keys produce different ciphertexts on the two communication legs while the receiver recovers the same plaintext.

### Test message


HELLO-WIRESHARK-123


The receiver recovered:


MESSAGE FROM alice: HELLO-WIRESHARK-123


### Sender leg — TCP stream 51

Wireshark filter:
tcp.stream eq 51
Observed ciphertext:
C0BFC3AC87CBBA9BDD5DB2A5C8B8BECEC5B3D5C2E0C8E3D3BFCFD8AEC2BBB7


### Receiver leg — TCP stream 52

Wireshark filter:
tcp.stream eq 52
Observed ciphertext:
AFB5B7C1AAC5AD96B0C6BED18EDDCE3D8EFAEA2BEC5C7DCC9B5D3CFD3DBD3D6C3DED2C9B7C6BB


The ciphertexts are different even though the receiver successfully recovers the original message. This demonstrates the required **hop-by-hop re-encryption** behavior.

Recommended evidence files:

screenshots/
├── alice-message.png
├── bob-decryption.png
├── wireshark-stream-51.png
└── wireshark-stream-52.png


---

## Security Model and Known Limitations

### Hop-by-hop encryption

The server decrypts the sender's message, determines the destination, and re-encrypts the message using the destination client's key.

Therefore the architecture is:
Client A <-> Server <-> Client B
rather than direct end-to-end encryption.

### Registration

The assignment's simplified registration protocol supplies the username and key during registration. A production system would require a secure key-establishment mechanism.

### Cryptographic strength

The selected assignment cipher is educational rather than production-grade cryptography. Its specific known weakness is documented in the Cipher Choice section.

### TCP

TCP is a byte stream. Production-quality networking would require comprehensive framing and robust handling of partial sends and receives.

---

## Project Structure


secure-chat/
├── client.c
├── server.c
├── cipher.c
├── cipher.h
├── README.md
├── screenshots/
│   ├── alice-message.png
│   ├── bob-decryption.png
│   ├── wireshark-stream-51.png
│   └── wireshark-stream-52.png
└── test-files/
    └── sample.txt


## Assignment Alignment

The implementation follows the assignment's required model:

1. A client registers with a unique username and symmetric key.
2. Outgoing communication is encrypted before transmission.
3. The server decrypts incoming communication using the sender's key.
4. The server determines the destination client.
5. The server re-encrypts the routed message using the destination client's key.
6. The receiving client decrypts the message using its own key.
7. `.txt` file transfers follow the same hop-by-hop encryption model.
8. Wireshark demonstrates different ciphertexts on the two communication legs when different client keys are used.


