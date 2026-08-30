#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "cipher.h"

#define BUFFER_SIZE 1024

#define MAX_USERNAME 50
#define MAX_KEY 50

#define MAX_FILE_SIZE (1024 * 1024)
#define MAX_FILE_HEX_SIZE (MAX_FILE_SIZE * 2)

#define MAX_NETWORK_BUFFER (MAX_FILE_HEX_SIZE * 2 + 4096)

SOCKET client_socket;

char client_key[MAX_KEY];


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

        int sent =
            send(
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
   Binary -> hexadecimal
   ================================================== */

void binary_to_hex(
    const unsigned char *data,
    size_t length,
    char *hex
)
{
    const char digits[] =
        "0123456789ABCDEF";


    size_t i;


    for (i = 0; i < length; i++) {

        hex[i * 2] =
            digits[
                (data[i] >> 4) & 0x0F
            ];


        hex[i * 2 + 1] =
            digits[
                data[i] & 0x0F
            ];
    }


    hex[length * 2] =
        '\0';
}


/* ==================================================
   Hexadecimal -> binary
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
    unsigned char *data,
    size_t data_size
)
{
    size_t hex_length =
        strlen(hex);


    if (hex_length % 2 != 0) {
        return 0;
    }


    size_t binary_length =
        hex_length / 2;


    if (binary_length > data_size) {
        return 0;
    }


    size_t i;


    for (i = 0; i < binary_length; i++) {

        int high =
            hex_value(
                hex[i * 2]
            );


        int low =
            hex_value(
                hex[i * 2 + 1]
            );


        if (high < 0 || low < 0) {
            return 0;
        }


        data[i] =
            (unsigned char)(
                (high << 4) | low
            );
    }


    return 1;
}


/* ==================================================
   Get filename from path
   ================================================== */

const char *get_filename(
    const char *path
)
{
    const char *slash =
        strrchr(path, '\\');


    const char *forward_slash =
        strrchr(path, '/');


    if (
        forward_slash != NULL &&
        (
            slash == NULL ||
            forward_slash > slash
        )
    ) {

        return forward_slash + 1;
    }


    if (slash != NULL) {
        return slash + 1;
    }


    return path;
}


/* ==================================================
   Receive thread
   ================================================== */

DWORD WINAPI receive_messages(
    LPVOID parameter
)
{
    (void)parameter;


    /*
     * Large buffer is on heap, NOT stack.
     */

    char *buffer =
        (char *)malloc(
            MAX_NETWORK_BUFFER
        );


    if (buffer == NULL) {

        printf(
            "\nReceive buffer allocation failed.\n"
        );

        return 0;
    }


    while (1) {

        int bytes_received =
            recv(
                client_socket,
                buffer,
                MAX_NETWORK_BUFFER - 1,
                0
            );


        if (bytes_received > 0) {

            buffer[
                bytes_received
            ] = '\0';


            /*
             * Display received ciphertext.
             */

            if (bytes_received > 200) {

                printf(
                    "\n\nReceived encrypted data: "
                    "%.100s... [large data]\n",
                    buffer
                );

            } else {

                printf(
                    "\n\nReceived encrypted data: %s\n",
                    buffer
                );
            }


            /*
             * Decryption buffer.
             */

            size_t decrypted_size =
                (size_t)bytes_received / 2 + 1;


            char *decrypted =
                (char *)malloc(
                    decrypted_size
                );


            if (decrypted == NULL) {

                printf(
                    "Decryption buffer allocation failed.\n"
                );

                continue;
            }


            decrypt_text(
                buffer,
                client_key,
                decrypted
            );


            /*
             * Normal message.
             */

            if (
                strncmp(
                    decrypted,
                    "MESSAGE FROM ",
                    13
                ) == 0
            ) {

                printf(
                    "Decrypted message: %s\n",
                    decrypted
                );
            }


            /*
             * File received.
             */

            else if (
                strncmp(
                    decrypted,
                    "FILE FROM ",
                    10
                ) == 0
            ) {

                const char *colon =
                    strchr(
                        decrypted + 10,
                        ':'
                    );


                if (colon == NULL) {

                    printf(
                        "Invalid file message.\n"
                    );

                    free(decrypted);

                    continue;
                }


                const char *file_info =
                    colon + 1;


                while (*file_info == ' ') {
                    file_info++;
                }


                const char *separator =
                    strchr(
                        file_info,
                        '|'
                    );


                if (separator == NULL) {

                    printf(
                        "Invalid file data.\n"
                    );

                    free(decrypted);

                    continue;
                }


                /*
                 * Filename.
                 */

                size_t filename_length =
                    (size_t)(
                        separator - file_info
                    );


                if (
                    filename_length == 0 ||
                    filename_length >= MAX_PATH
                ) {

                    printf(
                        "Invalid filename.\n"
                    );

                    free(decrypted);

                    continue;
                }


                char filename[MAX_PATH];


                memcpy(
                    filename,
                    file_info,
                    filename_length
                );


                filename[
                    filename_length
                ] = '\0';


                /*
                 * Hexadecimal file data.
                 */

                const char *hex_data =
                    separator + 1;


                size_t hex_length =
                    strlen(hex_data);


                if (hex_length % 2 != 0) {

                    printf(
                        "Invalid file encoding.\n"
                    );

                    free(decrypted);

                    continue;
                }


                size_t file_size =
                    hex_length / 2;


                if (
                    file_size >
                    MAX_FILE_SIZE
                ) {

                    printf(
                        "Received file exceeds 1 MB limit.\n"
                    );

                    free(decrypted);

                    continue;
                }


                /*
                 * Decode file.
                 */

                unsigned char *file_data =
                    (unsigned char *)malloc(
                        file_size + 1
                    );


                if (file_data == NULL) {

                    printf(
                        "File buffer allocation failed.\n"
                    );

                    free(decrypted);

                    continue;
                }


                if (!hex_to_binary(
                        hex_data,
                        file_data,
                        file_size
                    )) {

                    printf(
                        "Invalid file contents.\n"
                    );

                    free(file_data);
                    free(decrypted);

                    continue;
                }


                /*
                 * Strip directory information.
                 */

                const char *safe_filename =
                    get_filename(
                        filename
                    );


                /*
                 * Save as received_filename.
                 */

                char output_filename[
                    MAX_PATH + 20
                ];


                snprintf(
                    output_filename,
                    sizeof(output_filename),
                    "received_%s",
                    safe_filename
                );


                FILE *output =
                    fopen(
                        output_filename,
                        "wb"
                    );


                if (output == NULL) {

                    printf(
                        "Could not create received file.\n"
                    );

                    free(file_data);
                    free(decrypted);

                    continue;
                }


                size_t written =
                    fwrite(
                        file_data,
                        1,
                        file_size,
                        output
                    );


                fclose(output);


                if (written != file_size) {

                    printf(
                        "File write failed.\n"
                    );

                } else {

                    printf(
                        "File received successfully: %s\n",
                        output_filename
                    );

                    printf(
                        "File size: %lu bytes\n",
                        (unsigned long)file_size
                    );
                }


                free(file_data);
            }


            /*
             * Server response.
             */

            else {

                printf(
                    "Decrypted message: %s\n",
                    decrypted
                );
            }


            free(decrypted);


            printf(
                "\nEnter message to send: "
            );

            fflush(stdout);
        }


        else if (bytes_received == 0) {

            printf(
                "\nServer closed the connection.\n"
            );

            break;
        }


        else {

            printf(
                "\nReceive failed: %d\n",
                WSAGetLastError()
            );

            break;
        }
    }


    free(buffer);

    return 0;
}


/* ==================================================
   Send normal message
   ================================================== */

int send_message(
    const char *message,
    const char *target_username,
    const char *key
)
{
    char command[
        BUFFER_SIZE
    ];


    snprintf(
        command,
        sizeof(command),
        "SEND TO %s: %s",
        target_username,
        message
    );


    printf(
        "Plaintext command: %s\n",
        command
    );


    size_t encrypted_size =
        strlen(command) * 2 + 1;


    char *encrypted =
        (char *)malloc(
            encrypted_size
        );


    if (encrypted == NULL) {

        printf(
            "Memory allocation failed.\n"
        );

        return 0;
    }


    encrypt_text(
        command,
        key,
        encrypted
    );


    printf(
        "Encrypted command: %s\n",
        encrypted
    );


    int result =
        send_all(
            client_socket,
            encrypted,
            (int)strlen(encrypted)
        );


    free(encrypted);


    if (!result) {

        printf(
            "Send failed: %d\n",
            WSAGetLastError()
        );

        return 0;
    }


    printf(
        "Encrypted command sent.\n"
    );


    return 1;
}


/* ==================================================
   Send .txt file
   ================================================== */

int send_file(
    const char *path,
    const char *target_username,
    const char *key
)
{
    /*
     * Check extension.
     */

    const char *extension =
        strrchr(path, '.');


    if (
        extension == NULL ||
        _stricmp(extension, ".txt") != 0
    ) {

        printf(
            "ERROR: Only .txt files are allowed.\n"
        );

        return 0;
    }


    /*
     * Open file.
     */

    FILE *file =
        fopen(
            path,
            "rb"
        );


    if (file == NULL) {

        printf(
            "ERROR: File does not exist or cannot be opened.\n"
        );

        return 0;
    }


    /*
     * Get file size.
     */

    if (
        fseek(
            file,
            0,
            SEEK_END
        ) != 0
    ) {

        fclose(file);

        printf(
            "ERROR: Could not determine file size.\n"
        );

        return 0;
    }


    long file_size_long =
        ftell(file);


    if (file_size_long < 0) {

        fclose(file);

        printf(
            "ERROR: Could not determine file size.\n"
        );

        return 0;
    }


    /*
     * 1 MB limit.
     */

    if (
        file_size_long >
        MAX_FILE_SIZE
    ) {

        fclose(file);

        printf(
            "ERROR: File exceeds the 1 MB limit.\n"
        );

        return 0;
    }


    if (
        fseek(
            file,
            0,
            SEEK_SET
        ) != 0
    ) {

        fclose(file);

        printf(
            "ERROR: Could not read file.\n"
        );

        return 0;
    }


    size_t file_size =
        (size_t)file_size_long;


    /*
     * Allocate file.
     */

    unsigned char *file_data =
        (unsigned char *)malloc(
            file_size + 1
        );


    if (file_data == NULL) {

        fclose(file);

        printf(
            "ERROR: Memory allocation failed.\n"
        );

        return 0;
    }


    size_t bytes_read =
        fread(
            file_data,
            1,
            file_size,
            file
        );


    fclose(file);


    if (bytes_read != file_size) {

        free(file_data);

        printf(
            "ERROR: Could not read complete file.\n"
        );

        return 0;
    }


    /*
     * Convert to hex.
     */

    size_t hex_size =
        file_size * 2 + 1;


    char *hex_data =
        (char *)malloc(
            hex_size
        );


    if (hex_data == NULL) {

        free(file_data);

        printf(
            "ERROR: Memory allocation failed.\n"
        );

        return 0;
    }


    binary_to_hex(
        file_data,
        file_size,
        hex_data
    );


    free(file_data);


    /*
     * Only transmit filename.
     */

    const char *filename =
        get_filename(path);


    /*
     * Build command.
     */

    size_t command_size =
        strlen(target_username) +
        strlen(filename) +
        strlen(hex_data) +
        32;


    char *command =
        (char *)malloc(
            command_size
        );


    if (command == NULL) {

        free(hex_data);

        printf(
            "ERROR: Memory allocation failed.\n"
        );

        return 0;
    }


    snprintf(
        command,
        command_size,
        "SEND FILE TO %s: %s|%s",
        target_username,
        filename,
        hex_data
    );


    free(hex_data);


    printf(
        "Plaintext file command prepared.\n"
    );


    /*
     * Encrypt.
     */

    size_t encrypted_size =
        strlen(command) * 2 + 1;


    char *encrypted =
        (char *)malloc(
            encrypted_size
        );


    if (encrypted == NULL) {

        free(command);

        printf(
            "ERROR: Memory allocation failed.\n"
        );

        return 0;
    }


    encrypt_text(
        command,
        key,
        encrypted
    );


    free(command);


    printf(
        "Encrypted file data prepared.\n"
    );


    /*
     * Send.
     */

    int result =
        send_all(
            client_socket,
            encrypted,
            (int)strlen(encrypted)
        );


    free(encrypted);


    if (!result) {

        printf(
            "File send failed: %d\n",
            WSAGetLastError()
        );

        return 0;
    }


    printf(
        "Encrypted file sent.\n"
    );


    return 1;
}


/* ==================================================
   Main
   ================================================== */

int main(
    int argc,
    char *argv[]
)
{
    /*
     * Check arguments.
     */

    if (argc != 3) {

        printf(
            "Usage: %s <server_ip> <port>\n",
            argv[0]
        );

        return 1;
    }


    const char *server_ip =
        argv[1];


    int port =
        atoi(argv[2]);


    /*
     * Username.
     */

    char username[
        MAX_USERNAME
    ];


    printf(
        "Enter username: "
    );


    fflush(stdout);


    if (
        fgets(
            username,
            sizeof(username),
            stdin
        ) == NULL
    ) {

        return 1;
    }


    username[
        strcspn(
            username,
            "\r\n"
        )
    ] = '\0';


    /*
     * Encryption key.
     */

    char key[
        MAX_KEY
    ];


    printf(
        "Enter encryption key: "
    );


    fflush(stdout);


    if (
        fgets(
            key,
            sizeof(key),
            stdin
        ) == NULL
    ) {

        return 1;
    }


    key[
        strcspn(
            key,
            "\r\n"
        )
    ] = '\0';


    strcpy(
        client_key,
        key
    );


    /*
     * Winsock.
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
     * Create socket.
     */

    client_socket =
        socket(
            AF_INET,
            SOCK_STREAM,
            IPPROTO_TCP
        );


    if (
        client_socket ==
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
        "Client socket created.\n"
    );


    /*
     * Server address.
     */

    struct sockaddr_in server_address;


    memset(
        &server_address,
        0,
        sizeof(server_address)
    );


    server_address.sin_family =
        AF_INET;


    server_address.sin_port =
        htons(
            (u_short)port
        );


    server_address.sin_addr.s_addr =
        inet_addr(server_ip);


    if (
        server_address.sin_addr.s_addr
        == INADDR_NONE
    ) {

        printf(
            "Invalid server IP address.\n"
        );


        closesocket(
            client_socket
        );


        WSACleanup();

        return 1;
    }


    /*
     * Connect.
     */

    result =
        connect(
            client_socket,
            (struct sockaddr *)&server_address,
            sizeof(server_address)
        );


    if (
        result ==
        SOCKET_ERROR
    ) {

        printf(
            "Connection failed: %d\n",
            WSAGetLastError()
        );


        closesocket(
            client_socket
        );


        WSACleanup();

        return 1;
    }


    printf(
        "Connected to server.\n"
    );


    /*
     * Registration.
     */

    char registration[
        BUFFER_SIZE
    ];


    snprintf(
        registration,
        sizeof(registration),
        "REGISTER %s KEY %s",
        username,
        key
    );


    if (!send_all(
            client_socket,
            registration,
            (int)strlen(registration)
        )) {

        printf(
            "Registration send failed: %d\n",
            WSAGetLastError()
        );


        closesocket(
            client_socket
        );


        WSACleanup();

        return 1;
    }


    printf(
        "Registration sent: %s\n",
        registration
    );


    /*
     * Registration response.
     */

    char registration_response[
        BUFFER_SIZE
    ];


    int bytes_received =
        recv(
            client_socket,
            registration_response,
            BUFFER_SIZE - 1,
            0
        );


    if (bytes_received <= 0) {

        printf(
            "Registration response failed: %d\n",
            WSAGetLastError()
        );


        closesocket(
            client_socket
        );


        WSACleanup();

        return 1;
    }


    registration_response[
        bytes_received
    ] = '\0';


    printf(
        "Server response: %s\n",
        registration_response
    );


    if (
        strncmp(
            registration_response,
            "REGISTERED",
            10
        ) != 0
    ) {

        printf(
            "Registration failed.\n"
        );


        closesocket(
            client_socket
        );


        WSACleanup();

        return 1;
    }


    printf(
        "Registration successful!\n"
    );


    printf(
        "\nConnection is open.\n"
    );


    /*
     * Start receiver thread.
     */

    HANDLE receive_thread =
        CreateThread(
            NULL,
            0,
            receive_messages,
            NULL,
            0,
            NULL
        );


    if (receive_thread == NULL) {

        printf(
            "Failed to create receive thread.\n"
        );


        closesocket(
            client_socket
        );


        WSACleanup();

        return 1;
    }


    /*
     * Main input loop.
     */

    char input[
        BUFFER_SIZE
    ];


    while (1) {

        printf(
            "\nEnter message to send: "
        );


        fflush(stdout);


        if (
            fgets(
                input,
                sizeof(input),
                stdin
            ) == NULL
        ) {

            break;
        }


        input[
            strcspn(
                input,
                "\r\n"
            )
        ] = '\0';


        if (
            strlen(input) == 0
        ) {

            continue;
        }


        /*
         * Quit.
         */

        if (
            strcmp(
                input,
                "/quit"
            ) == 0
        ) {

            printf(
                "Disconnecting...\n"
            );

            break;
        }


        /*
         * File transfer:
         *
         * /file test.txt
         *
         * or:
         *
         * /file C:\Users\...\test.txt
         */

        if (
            strncmp(
                input,
                "/file ",
                6
            ) == 0
        ) {

            char path[
                MAX_PATH
            ];


            strncpy(
                path,
                input + 6,
                sizeof(path) - 1
            );


            path[
                sizeof(path) - 1
            ] = '\0';


            /*
             * Remove surrounding quotes.
             */

            size_t path_length =
                strlen(path);


            if (
                path_length >= 2 &&
                path[0] == '"' &&
                path[path_length - 1] == '"'
            ) {

                memmove(
                    path,
                    path + 1,
                    path_length - 2
                );


                path[
                    path_length - 2
                ] = '\0';
            }


            /*
             * Ask recipient.
             */

            char target_username[
                MAX_USERNAME
            ];


            printf(
                "Send file to username: "
            );


            fflush(stdout);


            if (
                fgets(
                    target_username,
                    sizeof(target_username),
                    stdin
                ) == NULL
            ) {

                break;
            }


            target_username[
                strcspn(
                    target_username,
                    "\r\n"
                )
            ] = '\0';


            if (
                strlen(target_username) == 0
            ) {

                printf(
                    "Username cannot be empty.\n"
                );

                continue;
            }


            send_file(
                path,
                target_username,
                key
            );


            continue;
        }


        /*
         * Normal message.
         */

        char target_username[
            MAX_USERNAME
        ];


        printf(
            "Send to username: "
        );


        fflush(stdout);


        if (
            fgets(
                target_username,
                sizeof(target_username),
                stdin
            ) == NULL
        ) {

            break;
        }


        target_username[
            strcspn(
                target_username,
                "\r\n"
            )
        ] = '\0';


        if (
            strlen(target_username) == 0
        ) {

            printf(
                "Username cannot be empty.\n"
            );

            continue;
        }


        send_message(
            input,
            target_username,
            key
        );
    }


    /*
     * Close connection.
     */

    shutdown(
        client_socket,
        SD_BOTH
    );


    closesocket(
        client_socket
    );


    /*
     * Give receive thread time to exit.
     */

    WaitForSingleObject(
        receive_thread,
        1000
    );


    CloseHandle(
        receive_thread
    );


    WSACleanup();


    printf(
        "Client disconnected.\n"
    );


    return 0;
}