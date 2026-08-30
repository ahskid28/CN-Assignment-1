#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

#define BUFFER_SIZE 1024

int main(int argc, char *argv[]) {

    // Check command-line arguments
    if (argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        return 1;
    }

    int port = atoi(argv[1]);

    // --------------------------------------------------
    // 1. Initialize Winsock
    // --------------------------------------------------

    WSADATA wsaData;

    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);

    if (result != 0) {
        printf("WSAStartup failed: %d\n", result);
        return 1;
    }

    printf("Winsock initialized.\n");


    // --------------------------------------------------
    // 2. Create socket
    // --------------------------------------------------

    SOCKET server_socket = socket(
        AF_INET,
        SOCK_STREAM,
        IPPROTO_TCP
    );

    if (server_socket == INVALID_SOCKET) {
        printf("Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    printf("Server socket created.\n");


    // --------------------------------------------------
    // 3. Configure server address
    // --------------------------------------------------

    struct sockaddr_in server_address;

    memset(&server_address, 0, sizeof(server_address));

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons((u_short)port);


    // --------------------------------------------------
    // 4. Bind socket
    // --------------------------------------------------

    result = bind(
        server_socket,
        (struct sockaddr *)&server_address,
        sizeof(server_address)
    );

    if (result == SOCKET_ERROR) {
        printf("Bind failed: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }

    printf("Server bound to port %d.\n", port);


    // --------------------------------------------------
    // 5. Listen for clients
    // --------------------------------------------------

    result = listen(server_socket, 10);

    if (result == SOCKET_ERROR) {
        printf("Listen failed: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }

    printf("Server is listening...\n");


    // --------------------------------------------------
    // 6. Accept clients
    // --------------------------------------------------

    while (1) {

        struct sockaddr_in client_address;

        int client_address_length =
            sizeof(client_address);

        SOCKET client_socket = accept(
            server_socket,
            (struct sockaddr *)&client_address,
            &client_address_length
        );

        if (client_socket == INVALID_SOCKET) {
            printf("Accept failed: %d\n", WSAGetLastError());
            continue;
        }

        printf("Client connected.\n");


        // --------------------------------------------------
        // 7. Receive test message
        // --------------------------------------------------

        char buffer[BUFFER_SIZE];

        int bytes_received = recv(
            client_socket,
            buffer,
            BUFFER_SIZE - 1,
            0
        );

        if (bytes_received > 0) {

            buffer[bytes_received] = '\0';

            printf("Received: %s\n", buffer);


            // --------------------------------------------------
            // 8. Send response
            // --------------------------------------------------

            const char *response =
                "Hello from server!";

            send(
                client_socket,
                response,
                (int)strlen(response),
                0
            );
        }


        // --------------------------------------------------
        // 9. Close client connection
        // --------------------------------------------------

        closesocket(client_socket);

        printf("Client disconnected.\n");
    }


    // --------------------------------------------------
    // 10. Cleanup
    // --------------------------------------------------

    closesocket(server_socket);

    WSACleanup();

    return 0;
}