#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "cipher.h"

/*
 * Custom symmetric-key cipher
 *
 * Encryption:
 *   1. Take each plaintext character.
 *   2. Add the corresponding key character.
 *   3. Add the character position.
 *   4. Store the result as two hexadecimal characters.
 *
 * Decryption reverses these operations.
 */

void encrypt_text(
    const char *plaintext,
    const char *key,
    char *ciphertext
) {
    size_t key_length = strlen(key);
    size_t plaintext_length = strlen(plaintext);

    if (key_length == 0) {
        ciphertext[0] = '\0';
        return;
    }

    for (size_t i = 0; i < plaintext_length; i++) {

        unsigned char p = (unsigned char)plaintext[i];
        unsigned char k = (unsigned char)key[i % key_length];

        unsigned char encrypted =
            (unsigned char)((p + k + (i % 256)) % 256);

        sprintf(
            ciphertext + (i * 2),
            "%02X",
            encrypted
        );
    }

    ciphertext[plaintext_length * 2] = '\0';
}


static unsigned char hex_to_byte(
    char high,
    char low
) {
    unsigned char value = 0;

    if (high >= '0' && high <= '9')
        value = (high - '0') << 4;
    else if (high >= 'A' && high <= 'F')
        value = (high - 'A' + 10) << 4;
    else if (high >= 'a' && high <= 'f')
        value = (high - 'a' + 10) << 4;

    if (low >= '0' && low <= '9')
        value |= (low - '0');
    else if (low >= 'A' && low <= 'F')
        value |= (low - 'A' + 10);
    else if (low >= 'a' && low <= 'f')
        value |= (low - 'a' + 10);

    return value;
}


void decrypt_text(
    const char *ciphertext,
    const char *key,
    char *plaintext
) {
    size_t key_length = strlen(key);
    size_t ciphertext_length = strlen(ciphertext);

    if (key_length == 0 || ciphertext_length % 2 != 0) {
        plaintext[0] = '\0';
        return;
    }

    size_t plaintext_length = ciphertext_length / 2;

    for (size_t i = 0; i < plaintext_length; i++) {

        unsigned char encrypted =
            hex_to_byte(
                ciphertext[i * 2],
                ciphertext[i * 2 + 1]
            );

        unsigned char k =
            (unsigned char)key[i % key_length];

        unsigned char decrypted =
            (unsigned char)(
                (encrypted - k - (i % 256)) % 256
            );

        plaintext[i] = (char)decrypted;
    }

    plaintext[plaintext_length] = '\0';
}