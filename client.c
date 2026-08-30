#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define BUFFER_SIZE 1024

#ifdef _MSC_VER
#pragma comment(lib, "Ws2_32.lib")
#endif

int main(int argc, char *argv[]) {

    // 1. Check command-line arguments

    if (argc != 3) {
        printf("Usage: %s <server_ip> <port>\n", argv[0]);
        return 1;
    }
    
    const char *server_ip = argv[1];
    int port = atoi(argv[2]);


    // 2. Initialize Winsock

    WSADATA wsaData;

    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);

    if (result != 0) {
        printf("WSAStartup failed: %d\n", result);
        return 1;
    }

    printf("Winsock initialized.\n");


    // 3. Create socket

    SOCKET client_socket = socket(
        AF_INET,
        SOCK_STREAM,
        IPPROTO_TCP
    );

    if (client_socket == INVALID_SOCKET) {
        printf("Socket creation failed: %d\n",
               WSAGetLastError());

        WSACleanup();
        return 1;
    }

    printf("Client socket created.\n");


    // 4. Configure server address

    struct sockaddr_in server_address;

    memset(&server_address, 0, sizeof(server_address));

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons((u_short)port);

    server_address.sin_addr.s_addr = inet_addr(server_ip);

if (server_address.sin_addr.s_addr == INADDR_NONE) {
    printf("Invalid server IP address.\n");

    closesocket(client_socket);
    WSACleanup();
    return 1;
}


    // 5. Connect to server

    result = connect(
        client_socket,
        (struct sockaddr *)&server_address,
        sizeof(server_address)
    );

    if (result == SOCKET_ERROR) {
        printf("Connection failed: %d\n",
               WSAGetLastError());

        closesocket(client_socket);
        WSACleanup();
        return 1;
    }

    printf("Connected to server.\n");


    // 6. Send test message

    const char *message = "Hello from client!";

    int bytes_sent = send(
        client_socket,
        message,
        (int)strlen(message),
        0
    );

    if (bytes_sent == SOCKET_ERROR) {
        printf("Send failed: %d\n",
               WSAGetLastError());

        closesocket(client_socket);
        WSACleanup();
        return 1;
    }

    printf("Message sent.\n");


    // 7. Receive server response

    char buffer[BUFFER_SIZE];

    int bytes_received = recv(
        client_socket,
        buffer,
        BUFFER_SIZE - 1,
        0
    );

    if (bytes_received > 0) {

        buffer[bytes_received] = '\0';

        printf("Server response: %s\n", buffer);

    } else if (bytes_received == 0) {

        printf("Server closed the connection.\n");

    } else {

        printf("Receive failed: %d\n",
               WSAGetLastError());
    }


    // 8. Close socket

    closesocket(client_socket);

    WSACleanup();

    printf("Client disconnected.\n");

    return 0;
}