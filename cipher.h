#ifndef CIPHER_H
#define CIPHER_H

#define MAX_TEXT_SIZE 4096
#define MAX_KEY_SIZE 256

void encrypt_text(
    const char *plaintext,
    const char *key,
    char *ciphertext
);

void decrypt_text(
    const char *ciphertext,
    const char *key,
    char *plaintext
);

#endif