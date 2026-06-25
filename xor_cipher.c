/*
 * XOR Cipher - Bitwise Encryption in C
 * Author: Krishna Aggarwal
 * GitHub: krishnaaggarwal-Cybersecurity
 *
 * Description:
 *   XOR is the fundamental bitwise operation behind stream ciphers
 *   and One-Time Pad encryption. This implementation:
 *   - XORs each byte of plaintext with repeating key bytes
 *   - Encryption and decryption are identical operations (XOR is its own inverse)
 *   - With a truly random key equal to message length, this is
 *     information-theoretically secure (One-Time Pad).
 *   - With a short repeating key, it's trivially broken by
 *     frequency analysis on the key period.
 *
 *   Output is hex-encoded because XOR often produces non-printable bytes.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define MAX_LEN 256

/* XOR encrypt/decrypt (same operation) */
void xor_process(unsigned char *data, int dlen,
                 const unsigned char *key, int klen) {
    for (int i = 0; i < dlen; i++) {
        data[i] ^= key[i % klen];
    }
}

/* Print bytes as hex */
void print_hex(const unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02X", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
        else printf(" ");
    }
    printf("\n");
}

/* Parse hex string into bytes — returns byte count or -1 on error */
int parse_hex(const char *hex_str, unsigned char *out, int max_out) {
    int len = strlen(hex_str);
    if (len % 2 != 0) return -1;
    int count = len / 2;
    if (count > max_out) return -1;
    for (int i = 0; i < count; i++) {
        unsigned int byte;
        if (sscanf(hex_str + 2*i, "%2X", &byte) != 1) return -1;
        out[i] = (unsigned char)byte;
    }
    return count;
}

int main() {
    int choice;
    printf("=== XOR Cipher ===\n");
    printf("1. Encrypt (text -> hex)\n");
    printf("2. Decrypt (hex -> text)\n");
    printf("Choice: ");
    scanf("%d", &choice);
    getchar();

    unsigned char key[MAX_LEN];
    char key_input[MAX_LEN];
    printf("Enter key (text): ");
    fgets(key_input, sizeof(key_input), stdin);
    key_input[strcspn(key_input, "\n")] = 0;
    int klen = strlen(key_input);
    memcpy(key, key_input, klen);

    if (choice == 1) {
        char plain[MAX_LEN];
        printf("Enter plaintext: ");
        fgets(plain, sizeof(plain), stdin);
        plain[strcspn(plain, "\n")] = 0;
        int plen = strlen(plain);

        unsigned char data[MAX_LEN];
        memcpy(data, plain, plen);
        xor_process(data, plen, key, klen);

        printf("Encrypted (hex): ");
        print_hex(data, plen);
        printf("\nKey length: %d bytes | Message length: %d bytes\n", klen, plen);
        if (klen < plen) {
            printf("WARNING: Key shorter than message -> key repeats -> breakable.\n");
            printf("For OTP security, key must be >= message length and truly random.\n");
        }

    } else {
        char hex_input[MAX_LEN * 3];
        printf("Enter ciphertext (hex, no spaces): ");
        fgets(hex_input, sizeof(hex_input), stdin);
        hex_input[strcspn(hex_input, "\n")] = 0;

        /* Remove spaces if any */
        char clean[MAX_LEN * 3];
        int ci = 0;
        for (int i = 0; hex_input[i]; i++)
            if (!isspace(hex_input[i])) clean[ci++] = hex_input[i];
        clean[ci] = 0;

        unsigned char data[MAX_LEN];
        int dlen = parse_hex(clean, data, MAX_LEN);
        if (dlen < 0) {
            printf("Error: invalid hex input.\n");
            return 1;
        }

        xor_process(data, dlen, key, klen);
        data[dlen] = 0;
        printf("Decrypted: %s\n", (char *)data);
    }

    return 0;
}
