#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include "cipher.h"

#define BUFFER_SIZE 1024

#define MAX_CLIENTS 10
#define MAX_USERNAME 50
#define MAX_KEY 50

#define MAX_FILE_SIZE (1024 * 1024)
#define MAX_FILE_HEX_SIZE (MAX_FILE_SIZE * 2)

/*
 * Maximum encrypted network message.
 *
 * File:
 *   1 MB binary
 *   -> 2 MB hex
 *   -> roughly 4 MB encrypted
 */
#define MAX_NETWORK_BUFFER (MAX_FILE_HEX_SIZE * 2 + 4096)

/*
 * Fixed handshake key, shared by client and server, used ONLY to
 * encrypt the REGISTER command and its REGISTERED/ERROR response.
 *
 * The server cannot know a client's real key until it has read
 * and parsed the REGISTER command, so that command cannot be
 * encrypted with the real key. Every other message (chat, file
 * transfer, ordinary server responses) is still encrypted with
 * the client's own registered key as before.
 *
 * This MUST match the BOOTSTRAP_KEY defined in client.c.
 */
#define BOOTSTRAP_KEY "CN25_REGISTRATION_HANDSHAKE_KEY"

typedef struct {
    SOCKET socket;
    char username[MAX_USERNAME];
    char key[MAX_KEY];
    int active;
} ClientInfo;

ClientInfo clients[MAX_CLIENTS];


/* ==================================================
   Find client by username
   ================================================== */

int find_client_by_username(const char *username)
{
    int i;

    for (i = 0; i < MAX_CLIENTS; i++) {

        if (clients[i].active &&
            strcmp(clients[i].username, username) == 0) {

            return i;
        }
    }

    return -1;
}


/* ==================================================
   Find free client slot
   ================================================== */

int find_free_client(void)
{
    int i;

    for (i = 0; i < MAX_CLIENTS; i++) {

        if (!clients[i].active) {
            return i;
        }
    }

    return -1;
}


/* ==================================================
   Send all bytes
   ================================================== */

int send_all(
    SOCKET socket,
    const char *data,
    int length
)
{
    int total = 0;

    while (total < length) {

        int sent = send(
            socket,
            data + total,
            length - total,
            0
        );

        if (sent == SOCKET_ERROR) {
            return 0;
        }

        if (sent == 0) {
            return 0;
        }

        total += sent;
    }

    return 1;
}


/* ==================================================
   Send encrypted message
   ================================================== */

int send_encrypted(
    SOCKET socket,
    const char *message,
    const char *key
)
{
    size_t encrypted_size =
        strlen(message) * 2 + 1;

    char *encrypted =
        (char *)malloc(encrypted_size);

    if (encrypted == NULL) {
        return 0;
    }

    encrypt_text(
        message,
        key,
        encrypted
    );

    int result =
        send_all(
            socket,
            encrypted,
            (int)strlen(encrypted)
        );

    free(encrypted);

    return result;
}


/* ==================================================
   Hexadecimal conversion
   ================================================== */

int hex_value(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }

    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }

    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }

    return -1;
}


int hex_to_binary(
    const char *hex,
    unsigned char *output,
    size_t output_size
)
{
    size_t hex_length =
        strlen(hex);

    if (hex_length % 2 != 0) {
        return 0;
    }

    size_t binary_length =
        hex_length / 2;

    if (binary_length > output_size) {
        return 0;
    }

    size_t i;

    for (i = 0; i < binary_length; i++) {

        int high =
            hex_value(hex[i * 2]);

        int low =
            hex_value(hex[i * 2 + 1]);

        if (high < 0 || low < 0) {
            return 0;
        }

        output[i] =
            (unsigned char)((high << 4) | low);
    }

    return 1;
}


/* ==================================================
   Normal SEND TO command
   ==================================================

   Plaintext:

       SEND TO bob: Hello Bob

   ================================================== */

void handle_send_command(
    int sender_index,
    const char *command
)
{
    char target_username[MAX_USERNAME];
    char message[BUFFER_SIZE];

    const char *prefix =
        "SEND TO ";

    if (strncmp(
            command,
            prefix,
            strlen(prefix)
        ) != 0) {

        send_encrypted(
            clients[sender_index].socket,
            "ERROR invalid command",
            clients[sender_index].key
        );

        return;
    }


    const char *target_start =
        command + strlen(prefix);

    const char *colon =
        strchr(target_start, ':');


    if (colon == NULL) {

        send_encrypted(
            clients[sender_index].socket,
            "ERROR invalid SEND TO format",
            clients[sender_index].key
        );

        return;
    }


    size_t username_length =
        (size_t)(colon - target_start);


    if (username_length == 0 ||
        username_length >= MAX_USERNAME) {

        send_encrypted(
            clients[sender_index].socket,
            "ERROR invalid username",
            clients[sender_index].key
        );

        return;
    }


    memcpy(
        target_username,
        target_start,
        username_length
    );

    target_username[username_length] =
        '\0';


    /*
     * Remove leading spaces.
     */

    while (target_username[0] == ' ') {

        memmove(
            target_username,
            target_username + 1,
            strlen(target_username)
        );
    }


    /*
     * Remove trailing spaces.
     */

    while (
        strlen(target_username) > 0 &&
        target_username[
            strlen(target_username) - 1
        ] == ' '
    ) {

        target_username[
            strlen(target_username) - 1
        ] = '\0';
    }


    const char *message_start =
        colon + 1;


    while (*message_start == ' ') {
        message_start++;
    }


    if (*message_start == '\0') {

        send_encrypted(
            clients[sender_index].socket,
            "ERROR empty message",
            clients[sender_index].key
        );

        return;
    }


    strncpy(
        message,
        message_start,
        BUFFER_SIZE - 1
    );

    message[BUFFER_SIZE - 1] =
        '\0';


    /*
     * Find target.
     */

    int target_index =
        find_client_by_username(
            target_username
        );


    if (target_index == -1) {

        char error_message[BUFFER_SIZE];

        snprintf(
            error_message,
            sizeof(error_message),
            "ERROR %s is not online",
            target_username
        );

        send_encrypted(
            clients[sender_index].socket,
            error_message,
            clients[sender_index].key
        );

        printf(
            "User %s is not online.\n",
            target_username
        );

        return;
    }


    /*
     * Build outgoing message.
     */

    char outgoing_message[BUFFER_SIZE];

    snprintf(
        outgoing_message,
        sizeof(outgoing_message),
        "MESSAGE FROM %s: %s",
        clients[sender_index].username,
        message
    );


    /*
     * Encrypt with recipient's key.
     */

    size_t encrypted_size =
        strlen(outgoing_message) * 2 + 1;


    char *encrypted =
        (char *)malloc(encrypted_size);


    if (encrypted == NULL) {

        send_encrypted(
            clients[sender_index].socket,
            "ERROR memory allocation failed",
            clients[sender_index].key
        );

        return;
    }


    encrypt_text(
        outgoing_message,
        clients[target_index].key,
        encrypted
    );


    int result =
        send_all(
            clients[target_index].socket,
            encrypted,
            (int)strlen(encrypted)
        );


    free(encrypted);


    if (!result) {

        send_encrypted(
            clients[sender_index].socket,
            "ERROR failed to deliver message",
            clients[sender_index].key
        );

        return;
    }


    /*
     * Confirmation to sender.
     */

    send_encrypted(
        clients[sender_index].socket,
        "MESSAGE SENT",
        clients[sender_index].key
    );


    printf(
        "Message sent from %s to %s.\n",
        clients[sender_index].username,
        target_username
    );
}


/* ==================================================
   File transfer
   ==================================================

   Plaintext:

   SEND FILE TO bob: test.txt|HEXDATA

   ================================================== */

void handle_file_command(
    int sender_index,
    const char *command
)
{
    const char *prefix =
        "SEND FILE TO ";


    if (strncmp(
            command,
            prefix,
            strlen(prefix)
        ) != 0) {

        send_encrypted(
            clients[sender_index].socket,
            "ERROR invalid file command",
            clients[sender_index].key
        );

        return;
    }


    const char *target_start =
        command + strlen(prefix);


    const char *colon =
        strchr(target_start, ':');


    if (colon == NULL) {

        send_encrypted(
            clients[sender_index].socket,
            "ERROR invalid file command format",
            clients[sender_index].key
        );

        return;
    }


    size_t username_length =
        (size_t)(colon - target_start);


    if (username_length == 0 ||
        username_length >= MAX_USERNAME) {

        send_encrypted(
            clients[sender_index].socket,
            "ERROR invalid target username",
            clients[sender_index].key
        );

        return;
    }


    char target_username[MAX_USERNAME];


    memcpy(
        target_username,
        target_start,
        username_length
    );


    target_username[username_length] =
        '\0';


    while (target_username[0] == ' ') {

        memmove(
            target_username,
            target_username + 1,
            strlen(target_username)
        );
    }


    while (
        strlen(target_username) > 0 &&
        target_username[
            strlen(target_username) - 1
        ] == ' '
    ) {

        target_username[
            strlen(target_username) - 1
        ] = '\0';
    }


    /*
     * Find separator between filename
     * and file contents.
     */

    const char *file_info =
        colon + 1;


    while (*file_info == ' ') {
        file_info++;
    }


    const char *separator =
        strchr(file_info, '|');


    if (separator == NULL) {

        send_encrypted(
            clients[sender_index].socket,
            "ERROR invalid file data",
            clients[sender_index].key
        );

        return;
    }


    /*
     * Filename.
     */

    size_t filename_length =
        (size_t)(separator - file_info);


    if (filename_length == 0 ||
        filename_length >= MAX_PATH) {

        send_encrypted(
            clients[sender_index].socket,
            "ERROR invalid filename",
            clients[sender_index].key
        );

        return;
    }


    char filename[MAX_PATH];


    memcpy(
        filename,
        file_info,
        filename_length
    );


    filename[filename_length] =
        '\0';


    /*
     * Only .txt files.
     */

    const char *extension =
        strrchr(filename, '.');


    if (extension == NULL ||
        _stricmp(extension, ".txt") != 0) {

        send_encrypted(
            clients[sender_index].socket,
            "ERROR only .txt files are allowed",
            clients[sender_index].key
        );

        return;
    }


    /*
     * File data.
     */

    const char *hex_data =
        separator + 1;


    size_t hex_length =
        strlen(hex_data);


    if (hex_length % 2 != 0) {

        send_encrypted(
            clients[sender_index].socket,
            "ERROR invalid file encoding",
            clients[sender_index].key
        );

        return;
    }


    size_t file_size =
        hex_length / 2;


    if (file_size > MAX_FILE_SIZE) {

        send_encrypted(
            clients[sender_index].socket,
            "ERROR file exceeds 1 MB limit",
            clients[sender_index].key
        );

        return;
    }


    /*
     * Target must be online.
     */

    int target_index =
        find_client_by_username(
            target_username
        );


    if (target_index == -1) {

        char error_message[BUFFER_SIZE];

        snprintf(
            error_message,
            sizeof(error_message),
            "ERROR %s is not online",
            target_username
        );

        send_encrypted(
            clients[sender_index].socket,
            error_message,
            clients[sender_index].key
        );

        return;
    }


    /*
     * Validate hexadecimal data.
     */

    unsigned char *file_data =
        (unsigned char *)malloc(
            file_size + 1
        );


    if (file_data == NULL) {

        send_encrypted(
            clients[sender_index].socket,
            "ERROR memory allocation failed",
            clients[sender_index].key
        );

        return;
    }


    if (!hex_to_binary(
            hex_data,
            file_data,
            file_size
        )) {

        free(file_data);

        send_encrypted(
            clients[sender_index].socket,
            "ERROR invalid file data",
            clients[sender_index].key
        );

        return;
    }


    free(file_data);


    /*
     * Build outgoing message.
     */

    size_t outgoing_size =
        strlen(filename) +
        strlen(hex_data) +
        strlen(clients[sender_index].username) +
        32;


    char *outgoing =
        (char *)malloc(
            outgoing_size
        );


    if (outgoing == NULL) {

        send_encrypted(
            clients[sender_index].socket,
            "ERROR memory allocation failed",
            clients[sender_index].key
        );

        return;
    }


    snprintf(
        outgoing,
        outgoing_size,
        "FILE FROM %s: %s|%s",
        clients[sender_index].username,
        filename,
        hex_data
    );


    /*
     * Encrypt with target's key.
     */

    size_t encrypted_size =
        strlen(outgoing) * 2 + 1;


    char *encrypted =
        (char *)malloc(
            encrypted_size
        );


    if (encrypted == NULL) {

        free(outgoing);

        send_encrypted(
            clients[sender_index].socket,
            "ERROR memory allocation failed",
            clients[sender_index].key
        );

        return;
    }


    encrypt_text(
        outgoing,
        clients[target_index].key,
        encrypted
    );


    int result =
        send_all(
            clients[target_index].socket,
            encrypted,
            (int)strlen(encrypted)
        );


    free(encrypted);
    free(outgoing);


    if (!result) {

        send_encrypted(
            clients[sender_index].socket,
            "ERROR failed to deliver file",
            clients[sender_index].key
        );

        return;
    }


    send_encrypted(
        clients[sender_index].socket,
        "FILE SENT",
        clients[sender_index].key
    );


    printf(
        "File %s sent from %s to %s (%lu bytes).\n",
        filename,
        clients[sender_index].username,
        target_username,
        (unsigned long)file_size
    );
}


/* ==================================================
   Client thread
   ================================================== */

DWORD WINAPI handle_client(
    LPVOID parameter
)
{
    SOCKET client_socket =
        (SOCKET)parameter;


    /*
     * IMPORTANT:
     *
     * Keep registration buffer small.
     * Do NOT put the multi-MB buffer on
     * the thread stack.
     */

    char registration_buffer[
        BUFFER_SIZE
    ];


    /*
     * Decrypted copy of the registration buffer.
     * Encrypted with BOOTSTRAP_KEY, not the
     * client's own key (which is not yet known).
     */

    char decrypted_registration[
        BUFFER_SIZE
    ];


    char username[
        MAX_USERNAME
    ];


    char key[
        MAX_KEY
    ];


    int bytes_received;


    /*
     * ----------------------------------------------
     * Receive registration
     * ----------------------------------------------
     */

    bytes_received =
        recv(
            client_socket,
            registration_buffer,
            BUFFER_SIZE - 1,
            0
        );


    if (bytes_received <= 0) {

        printf(
            "Client disconnected before registration.\n"
        );

        closesocket(
            client_socket
        );

        return 0;
    }


    registration_buffer[
        bytes_received
    ] = '\0';


    /*
     * ----------------------------------------------
     * Decrypt registration with BOOTSTRAP_KEY.
     *
     * The REGISTER command carries the client's real
     * key, so it cannot itself be encrypted with that
     * key (the server doesn't know it yet). It is
     * encrypted with a fixed, shared bootstrap key
     * instead, matching client.c.
     * ----------------------------------------------
     */

    decrypt_text(
        registration_buffer,
        BOOTSTRAP_KEY,
        decrypted_registration
    );


    printf(
        "Received registration: %s\n",
        decrypted_registration
    );


    /*
     * ----------------------------------------------
     * Parse:
     *
     * REGISTER alice KEY mysecretkey
     * ----------------------------------------------
     */

    if (sscanf(
            decrypted_registration,
            "REGISTER %49s KEY %49s",
            username,
            key
        ) != 2) {

        send_encrypted(
            client_socket,
            "ERROR invalid registration format",
            BOOTSTRAP_KEY
        );


        closesocket(
            client_socket
        );

        return 0;
    }


    /*
     * ----------------------------------------------
     * Duplicate username
     * ----------------------------------------------
     */

    if (
        find_client_by_username(username)
        != -1
    ) {

        char response[
            BUFFER_SIZE
        ];


        snprintf(
            response,
            sizeof(response),
            "ERROR username %s already taken",
            username
        );


        send_encrypted(
            client_socket,
            response,
            BOOTSTRAP_KEY
        );


        closesocket(
            client_socket
        );

        return 0;
    }


    /*
     * ----------------------------------------------
     * Check server capacity
     * ----------------------------------------------
     */

    int client_index =
        find_free_client();


    if (client_index == -1) {

        send_encrypted(
            client_socket,
            "ERROR server full",
            BOOTSTRAP_KEY
        );


        closesocket(
            client_socket
        );

        return 0;
    }


    /*
     * ----------------------------------------------
     * Store client
     * ----------------------------------------------
     */

    clients[client_index].socket =
        client_socket;


    strcpy(
        clients[client_index].username,
        username
    );


    strcpy(
        clients[client_index].key,
        key
    );


    clients[client_index].active =
        1;


    printf(
        "Registered user: %s\n",
        username
    );


    /*
     * ----------------------------------------------
     * Registration response
     *
     * Still sent with BOOTSTRAP_KEY: this is the
     * last message in the handshake exchange, and
     * mirroring the client's expectations keeps the
     * encryption scheme for this exchange symmetric.
     * ----------------------------------------------
     */

    char response[
        BUFFER_SIZE
    ];


    snprintf(
        response,
        sizeof(response),
        "REGISTERED %s",
        username
    );


    if (!send_encrypted(
            client_socket,
            response,
            BOOTSTRAP_KEY
        )) {

        printf(
            "Failed to send registration response.\n"
        );


        clients[client_index].active =
            0;


        closesocket(
            client_socket
        );


        return 0;
    }


    /*
     * ----------------------------------------------
     * Allocate large network buffer on HEAP.
     *
     * This is the important fix.
     * ----------------------------------------------
     */

    char *buffer =
        (char *)malloc(
            MAX_NETWORK_BUFFER
        );


    if (buffer == NULL) {

        printf(
            "Failed to allocate network buffer for %s.\n",
            username
        );


        clients[client_index].active =
            0;


        clients[client_index].username[0] =
            '\0';


        clients[client_index].key[0] =
            '\0';


        closesocket(
            client_socket
        );


        return 0;
    }


    /*
     * ----------------------------------------------
     * Keep connection open
     * ----------------------------------------------
     */

    int client_quit =
        0;


    while (1) {

        bytes_received =
            recv(
                client_socket,
                buffer,
                MAX_NETWORK_BUFFER - 1,
                0
            );


        if (bytes_received <= 0) {
            break;
        }


        buffer[
            bytes_received
        ] = '\0';


        /*
         * ------------------------------------------
         * Allocate decrypted buffer on heap.
         * ------------------------------------------
         */

        size_t decrypted_size =
            (size_t)bytes_received / 2 + 1;


        char *decrypted =
            (char *)malloc(
                decrypted_size
            );


        if (decrypted == NULL) {

            send_encrypted(
                client_socket,
                "ERROR memory allocation failed",
                clients[client_index].key
            );

            continue;
        }


        /*
         * Decrypt using sender's key.
         */

        decrypt_text(
            buffer,
            clients[client_index].key,
            decrypted
        );


        /*
         * Server logging.
         */

        if (bytes_received > 200) {

            printf(
                "Encrypted command from %s: "
                "%.100s... [large data]\n",
                username,
                buffer
            );

        } else {

            printf(
                "Encrypted command from %s: %s\n",
                username,
                buffer
            );
        }


        if (strlen(decrypted) > 200) {

            printf(
                "Decrypted command from %s: "
                "%.100s... [large data]\n",
                username,
                decrypted
            );

        } else {

            printf(
                "Decrypted command from %s: %s\n",
                username,
                decrypted
            );
        }


        /*
         * ------------------------------------------
         * QUIT
         *
         * Client-requested graceful disconnect.
         * Reply GOODBYE <username>, then break out
         * of the loop so the usual cleanup path
         * below runs.
         * ------------------------------------------
         */

        if (
            strcmp(
                decrypted,
                "QUIT"
            ) == 0
        ) {

            char goodbye[BUFFER_SIZE];

            snprintf(
                goodbye,
                sizeof(goodbye),
                "GOODBYE %s",
                username
            );

            send_encrypted(
                client_socket,
                goodbye,
                clients[client_index].key
            );

            printf(
                "Client %s sent QUIT.\n",
                username
            );

            free(
                decrypted
            );

            client_quit =
                1;

            break;
        }


        /*
         * ------------------------------------------
         * Normal message
         * ------------------------------------------
         */

        if (
            strncmp(
                decrypted,
                "SEND TO ",
                8
            ) == 0
        ) {

            handle_send_command(
                client_index,
                decrypted
            );
        }


        /*
         * ------------------------------------------
         * File transfer
         * ------------------------------------------
         */

        else if (
            strncmp(
                decrypted,
                "SEND FILE TO ",
                13
            ) == 0
        ) {

            handle_file_command(
                client_index,
                decrypted
            );
        }


        /*
         * ------------------------------------------
         * Unknown command
         * ------------------------------------------
         */

        else {

            send_encrypted(
                client_socket,
                "ERROR unknown command",
                clients[client_index].key
            );
        }


        free(
            decrypted
        );
    }


    /*
     * ----------------------------------------------
     * Client disconnected
     *
     * Reached either after a QUIT (graceful, with
     * GOODBYE already sent above) or after recv()
     * returned <= 0 (abrupt disconnect / error).
     * Cleanup is identical either way.
     * ----------------------------------------------
     */

    (void)client_quit;


    free(
        buffer
    );


    clients[client_index].active =
        0;


    clients[client_index].username[0] =
        '\0';


    clients[client_index].key[0] =
        '\0';


    closesocket(
        client_socket
    );


    printf(
        "Client %s disconnected.\n",
        username
    );


    return 0;
}


/* ==================================================
   Main
   ================================================== */

int main(
    int argc,
    char *argv[]
)
{
    memset(
        clients,
        0,
        sizeof(clients)
    );


    /*
     * Command line
     */

    if (argc != 2) {

        printf(
            "Usage: %s <port>\n",
            argv[0]
        );

        return 1;
    }


    int port =
        atoi(argv[1]);


    /*
     * Winsock
     */

    WSADATA wsaData;


    int result =
        WSAStartup(
            MAKEWORD(2, 2),
            &wsaData
        );


    if (result != 0) {

        printf(
            "WSAStartup failed: %d\n",
            result
        );

        return 1;
    }


    printf(
        "Winsock initialized.\n"
    );


    /*
     * Create socket
     */

    SOCKET server_socket =
        socket(
            AF_INET,
            SOCK_STREAM,
            IPPROTO_TCP
        );


    if (
        server_socket ==
        INVALID_SOCKET
    ) {

        printf(
            "Socket creation failed: %d\n",
            WSAGetLastError()
        );

        WSACleanup();

        return 1;
    }


    printf(
        "Server socket created.\n"
    );


    /*
     * Server address
     */

    struct sockaddr_in server_address;


    memset(
        &server_address,
        0,
        sizeof(server_address)
    );


    server_address.sin_family =
        AF_INET;


    server_address.sin_addr.s_addr =
        INADDR_ANY;


    server_address.sin_port =
        htons(
            (u_short)port
        );


    /*
     * Bind
     */

    result =
        bind(
            server_socket,
            (struct sockaddr *)&server_address,
            sizeof(server_address)
        );


    if (
        result ==
        SOCKET_ERROR
    ) {

        printf(
            "Bind failed: %d\n",
            WSAGetLastError()
        );


        closesocket(
            server_socket
        );


        WSACleanup();

        return 1;
    }


    printf(
        "Server bound to port %d.\n",
        port
    );


    /*
     * Listen
     */

    result =
        listen(
            server_socket,
            10
        );


    if (
        result ==
        SOCKET_ERROR
    ) {

        printf(
            "Listen failed: %d\n",
            WSAGetLastError()
        );


        closesocket(
            server_socket
        );


        WSACleanup();

        return 1;
    }


    printf(
        "Server is listening...\n"
    );


    /*
     * Accept loop
     */

    while (1) {

        struct sockaddr_in client_address;


        int client_address_length =
            sizeof(client_address);


        SOCKET client_socket =
            accept(
                server_socket,
                (struct sockaddr *)&client_address,
                &client_address_length
            );


        if (
            client_socket ==
            INVALID_SOCKET
        ) {

            printf(
                "Accept failed: %d\n",
                WSAGetLastError()
            );

            continue;
        }


        printf(
            "Client connected.\n"
        );


        /*
         * Create client thread.
         */

        HANDLE client_thread =
            CreateThread(
                NULL,
                0,
                handle_client,
                (LPVOID)client_socket,
                0,
                NULL
            );


        if (client_thread == NULL) {

            printf(
                "Failed to create client thread.\n"
            );


            closesocket(
                client_socket
            );

        } else {

            CloseHandle(
                client_thread
            );
        }
    }


    closesocket(
        server_socket
    );


    WSACleanup();


    return 0;
}