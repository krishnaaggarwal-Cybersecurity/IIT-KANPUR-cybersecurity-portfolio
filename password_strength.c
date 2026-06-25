/*
 * Password Strength Checker
 * Author: Krishna Aggarwal
 * GitHub: krishnaaggarwal-Cybersecurity
 *
 * Description:
 *   Evaluates password strength based on:
 *   - Length (longer = exponentially harder to brute-force)
 *   - Character set diversity (lowercase, uppercase, digits, symbols)
 *   - Common pattern detection (keyboard walks, repeated chars, common words)
 *   - Entropy estimate (bits) = log2(charset_size ^ length)
 *
 *   Demonstrates practical security thinking: what makes a password
 *   hard to crack, and why "Pa$$w0rd" is still weak despite
 *   passing naive complexity checks.
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#define MAX_LEN 256

/* Entropy calculation */
double estimate_entropy(int charset_size, int length) {
    return length * log2((double)charset_size);
}

/* Check for common keyboard patterns */
int has_keyboard_pattern(const char *pw) {
    const char *patterns[] = {
        "qwerty", "asdf", "zxcv", "qwer", "asdfg",
        "123456", "654321", "111111", "000000",
        "abcdef", "password", "pass", "admin", "letmein",
        NULL
    };
    char lower[MAX_LEN];
    int len = strlen(pw);
    for (int i = 0; i < len && i < MAX_LEN - 1; i++)
        lower[i] = tolower(pw[i]);
    lower[len < MAX_LEN ? len : MAX_LEN - 1] = 0;

    for (int i = 0; patterns[i] != NULL; i++) {
        if (strstr(lower, patterns[i])) return 1;
    }
    return 0;
}

/* Check for long runs of same character */
int has_repeating_chars(const char *pw) {
    for (int i = 0; pw[i + 2]; i++) {
        if (pw[i] == pw[i+1] && pw[i+1] == pw[i+2]) return 1;
    }
    return 0;
}

/* Score the password, return 0-100 */
int score_password(const char *pw,
                   int *has_lower, int *has_upper,
                   int *has_digit, int *has_symbol,
                   int *length, double *entropy) {
    *has_lower  = 0;
    *has_upper  = 0;
    *has_digit  = 0;
    *has_symbol = 0;
    *length = strlen(pw);

    for (int i = 0; pw[i]; i++) {
        if (islower(pw[i]))            *has_lower  = 1;
        else if (isupper(pw[i]))       *has_upper  = 1;
        else if (isdigit(pw[i]))       *has_digit  = 1;
        else if (ispunct(pw[i]))       *has_symbol = 1;
    }

    int charset = 0;
    if (*has_lower)  charset += 26;
    if (*has_upper)  charset += 26;
    if (*has_digit)  charset += 10;
    if (*has_symbol) charset += 32;
    if (charset == 0) charset = 26;

    *entropy = estimate_entropy(charset, *length);

    int score = 0;

    /* Length scoring */
    if (*length >= 20)      score += 30;
    else if (*length >= 16) score += 25;
    else if (*length >= 12) score += 18;
    else if (*length >= 8)  score += 10;
    else                    score += 0;

    /* Charset diversity */
    score += *has_lower  * 10;
    score += *has_upper  * 10;
    score += *has_digit  * 10;
    score += *has_symbol * 15;

    /* Penalties */
    if (has_keyboard_pattern(pw))   score -= 20;
    if (has_repeating_chars(pw))    score -= 10;
    if (*length < 8)                score -= 15;

    if (score < 0) score = 0;
    if (score > 100) score = 100;

    return score;
}

int main() {
    char pw[MAX_LEN];
    printf("=== Password Strength Checker ===\n");
    printf("Enter password: ");
    fgets(pw, sizeof(pw), stdin);
    pw[strcspn(pw, "\n")] = 0;

    int lower, upper, digit, symbol, length;
    double entropy;
    int score = score_password(pw, &lower, &upper, &digit, &symbol, &length, &entropy);

    printf("\n--- Analysis ---\n");
    printf("Length:        %d characters\n", length);
    printf("Lowercase:     %s\n", lower  ? "Yes" : "No");
    printf("Uppercase:     %s\n", upper  ? "Yes" : "No");
    printf("Digits:        %s\n", digit  ? "Yes" : "No");
    printf("Symbols:       %s\n", symbol ? "Yes" : "No");
    printf("Est. entropy:  %.1f bits\n", entropy);
    printf("Score:         %d / 100\n", score);

    if (has_keyboard_pattern(pw))
        printf("WARNING: Common keyboard pattern or word detected.\n");
    if (has_repeating_chars(pw))
        printf("WARNING: Repeating characters detected.\n");

    printf("\nRating: ");
    if      (score >= 80) printf("STRONG  — Resistant to brute-force attacks.\n");
    else if (score >= 60) printf("GOOD    — Reasonable security, consider adding length.\n");
    else if (score >= 40) printf("MEDIUM  — Vulnerable to targeted attacks.\n");
    else if (score >= 20) printf("WEAK    — Easily cracked by dictionary attack.\n");
    else                  printf("VERY WEAK — Change this immediately.\n");

    printf("\nTip: A 20+ character passphrase with symbols is more secure\n");
    printf("than a short 'complex' password. Entropy beats complexity.\n");

    return 0;
}
