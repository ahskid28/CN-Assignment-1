#include <stdio.h>
#include <string.h>
#include "cipher.h"

int main(void) {

    const char *message = "Hello! @CN#2026: Test 1234, []{}() <> /? +-=_%";
    const char *key = "mysecretkey";

    char encrypted[MAX_TEXT_SIZE * 2];
    char decrypted[MAX_TEXT_SIZE];

    encrypt_text(message, key, encrypted);

    printf("Original : %s\n", message);
    printf("Encrypted: %s\n", encrypted);

    decrypt_text(encrypted, key, decrypted);

    printf("Decrypted: %s\n", decrypted);

    if (strcmp(message, decrypted) == 0) {
        printf("\nTEST PASSED!\n");
    } else {
        printf("\nTEST FAILED!\n");
    }

    return 0;
}