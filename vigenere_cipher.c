/*
 * Vigenere Cipher - Polyalphabetic Encryption/Decryption in C
 * Author: Krishna Aggarwal
 * GitHub: krishnaaggarwal-Cybersecurity
 *
 * Description:
 *   Polyalphabetic substitution cipher using a repeating keyword.
 *   Defeats simple frequency analysis that breaks Caesar cipher.
 *   Still vulnerable to Kasiski examination when key is short.
 *   Demonstrates: key scheduling, polyalphabetic shift, why
 *   key length and randomness matter in symmetric encryption.
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define MAX_LEN 500
#define MAX_KEY 50

/* Encrypt using Vigenere */
void vigenere_encrypt(char *msg, const char *key, int klen) {
    int j = 0;
    for (int i = 0; msg[i] != '\0'; i++) {
        if (isalpha(msg[i])) {
            char base = islower(msg[i]) ? 'a' : 'A';
            int shift = tolower(key[j % klen]) - 'a';
            msg[i] = (char)((msg[i] - base + shift) % 26 + base);
            j++;
        }
    }
}

/* Decrypt using Vigenere */
void vigenere_decrypt(char *msg, const char *key, int klen) {
    int j = 0;
    for (int i = 0; msg[i] != '\0'; i++) {
        if (isalpha(msg[i])) {
            char base = islower(msg[i]) ? 'a' : 'A';
            int shift = tolower(key[j % klen]) - 'a';
            msg[i] = (char)((msg[i] - base - shift + 26) % 26 + base);
            j++;
        }
    }
}

int main() {
    char message[MAX_LEN];
    char key[MAX_KEY];
    int choice;

    printf("=== Vigenere Cipher ===\n");
    printf("1. Encrypt\n2. Decrypt\n");
    printf("Choice: ");
    scanf("%d", &choice);
    getchar();

    printf("Enter message: ");
    fgets(message, sizeof(message), stdin);
    message[strcspn(message, "\n")] = 0;

    printf("Enter keyword (letters only): ");
    fgets(key, sizeof(key), stdin);
    key[strcspn(key, "\n")] = 0;

    /* Validate key */
    int klen = strlen(key);
    if (klen == 0) {
        printf("Error: key cannot be empty.\n");
        return 1;
    }
    for (int i = 0; i < klen; i++) {
        if (!isalpha(key[i])) {
            printf("Error: key must contain only letters.\n");
            return 1;
        }
    }

    if (choice == 1) {
        vigenere_encrypt(message, key, klen);
        printf("Encrypted: %s\n", message);
        printf("\nNote: Vigenere with a short key is still breakable by\n");
        printf("Kasiski examination. Security requires key length >= message length.\n");
    } else {
        vigenere_decrypt(message, key, klen);
        printf("Decrypted: %s\n", message);
    }

    return 0;
}
