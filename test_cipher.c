#include <stdio.h>
#include <string.h>
#include "cipher.h"

/*
 * Round-trip test harness for the cipher: for each test case,
 * encrypt then decrypt and confirm we get back exactly the
 * original string. Covers the four input categories the
 * assignment asks for -- empty, short, long, and special-
 * character -- plus a "long" case deliberately longer than 256
 * bytes, since this cipher folds a position-dependent term
 * (i % 256) into each byte; a test that never crosses that
 * wraparound boundary wouldn't exercise it.
 */

/* Build a long test string cheaply at runtime. */
void build_long_string(char *out, size_t out_size)
{
    const char *unit = "The quick brown fox jumps over the lazy dog. ";
    size_t unit_len = strlen(unit);
    size_t written = 0;

    out[0] = '\0';

    while (written + unit_len < out_size - 1) {
        strcat(out, unit);
        written += unit_len;
    }
}

typedef struct {
    const char *label;
    const char *key;
    const char *text;
} TestCase;

int run_case(const char *label, const char *key, const char *text)
{
    char encrypted[MAX_TEXT_SIZE * 2];
    char decrypted[MAX_TEXT_SIZE];

    encrypt_text(text, key, encrypted);
    decrypt_text(encrypted, key, decrypted);

    int passed = (strcmp(text, decrypted) == 0);

    printf("[%s] %s\n", passed ? "PASS" : "FAIL", label);

    if (!passed) {
        printf("    Original length : %zu\n", strlen(text));
        printf("    Decrypted length: %zu\n", strlen(decrypted));
    }

    return passed;
}

int main(void)
{
    const char *key = "mysecretkey";
    char long_text[MAX_TEXT_SIZE];

    build_long_string(long_text, sizeof(long_text));

    TestCase cases[] = {
        { "empty string",             key, "" },
        { "short string",             key, "Hi" },
        { "special characters",       key, "Hello! @CN#2026: Test 1234, []{}() <> /? +-=_%" },
        { "long string (>256 bytes)", key, long_text },
    };

    int num_cases = (int)(sizeof(cases) / sizeof(cases[0]));
    int all_passed = 1;
    int i;

    printf("Cipher round-trip tests (key: \"%s\")\n", key);
    printf("=====================================\n");

    for (i = 0; i < num_cases; i++) {
        if (!run_case(cases[i].label, cases[i].key, cases[i].text)) {
            all_passed = 0;
        }
    }

    /* Also confirm decryption fails safely with the wrong key
       (should NOT crash, and should NOT equal the original). */
    {
        char encrypted[MAX_TEXT_SIZE * 2];
        char wrong_decrypted[MAX_TEXT_SIZE];
        const char *text = "Confidential message";

        encrypt_text(text, key, encrypted);
        decrypt_text(encrypted, "a-completely-different-key", wrong_decrypted);

        int mismatched = (strcmp(text, wrong_decrypted) != 0);

        printf("[%s] wrong key does not recover plaintext\n",
               mismatched ? "PASS" : "FAIL");

        if (!mismatched) {
            all_passed = 0;
        }
    }

    printf("=====================================\n");
    printf(all_passed ? "ALL TESTS PASSED\n" : "SOME TESTS FAILED\n");

    return all_passed ? 0 : 1;
}