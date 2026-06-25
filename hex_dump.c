/*
 * hex_dump.c — Binary Hex Dump & File Forensics Utility
 * Author: Krishna Aggarwal
 *
 * Displays binary file contents in hexadecimal and printable ASCII —
 * the standard starting point for manual binary analysis, malware header
 * inspection, and forensic artifact examination.
 *
 * Features:
 *   - Full hex + ASCII dump (classic xxd/hexdump format)
 *   - File signature (magic bytes) identification
 *   - Offset + length range viewing
 *   - ASCII string search within binary files
 *   - Entropy estimate per 256-byte block (high entropy → packed/encrypted)
 *
 * Concepts demonstrated:
 *   - File format analysis (magic bytes / file signatures)
 *   - Binary inspection fundamentals used in malware analysis
 *   - Entropy as a heuristic for encryption/packing detection
 *   - Covert data location via string search
 *
 * Compile: gcc -o hex_dump hex_dump.c -lm
 * Usage:
 *   ./hex_dump <file>                           — full dump
 *   ./hex_dump <file> --offset 64 --length 128  — range dump
 *   ./hex_dump <file> --search "password"        — find ASCII strings
 *   ./hex_dump <file> --entropy                  — block entropy analysis
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#define BYTES_PER_ROW  16
#define ENTROPY_BLOCK  256
#define MAX_HEADER_LEN 16

/* ── File Signature Database ───────────────────────────────────── */

typedef struct {
    const char    *name;
    unsigned char  magic[8];
    int            magic_len;
    const char    *security_note;
} Signature;

static const Signature signatures[] = {
    {"JPEG Image",
     {0xFF, 0xD8, 0xFF}, 3,
     "Common payload carrier for steganographic data"},
    {"PNG Image",
     {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, 8,
     "zTXt/tEXt chunks can carry hidden data"},
    {"PDF Document",
     {0x25, 0x50, 0x44, 0x46}, 4,
     "Can contain embedded JavaScript and hidden streams"},
    {"ELF Executable (Linux)",
     {0x7F, 0x45, 0x4C, 0x46}, 4,
     "Check for unusual section headers and .init_array entries"},
    {"ZIP / DOCX / APK Archive",
     {0x50, 0x4B, 0x03, 0x04}, 4,
     "Many formats (DOCX, JAR, APK) are ZIP containers — inspect contents"},
    {"PE Executable (Windows)",
     {0x4D, 0x5A}, 2,
     "Check for packed sections; high-entropy .text indicates obfuscation"},
    {"GIF Image",
     {0x47, 0x49, 0x46, 0x38}, 4,
     "Extension blocks may carry hidden or malicious data"},
    {"7-Zip Archive",
     {0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, 6,
     "Strong encryption — contents not inspectable without password"},
    {"RAR Archive",
     {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07}, 6,
     "May contain password-protected payloads"},
    {NULL, {0}, 0, NULL}
};

void identify_signature(const unsigned char *header, int len) {
    printf("\n[Signature Analysis]\n");
    for (int i = 0; signatures[i].name != NULL; i++) {
        if (len >= signatures[i].magic_len &&
            memcmp(header, signatures[i].magic, (size_t)signatures[i].magic_len) == 0) {
            printf("  Type   : %s\n", signatures[i].name);
            printf("  Note   : %s\n", signatures[i].security_note);
            printf("  Magic  : ");
            for (int j = 0; j < signatures[i].magic_len; j++)
                printf("%02x ", header[j]);
            printf("\n");
            return;
        }
    }
    printf("  Type   : Unknown / Plaintext (no matching magic bytes)\n");
    printf("  Magic  : ");
    for (int i = 0; i < (len < 4 ? len : 4); i++)
        printf("%02x ", header[i]);
    printf("\n");
}

/* ── Entropy Calculation ───────────────────────────────────────── */

/*
 * Shannon entropy of a byte block.
 * Range: 0.0 (all same byte) to 8.0 (perfectly uniform / random).
 * Packed or encrypted data typically > 7.0.
 * Compressed data: 7.5–8.0
 * Normal executable code: 5.0–7.0
 * English plaintext: ~4.0
 */
double shannon_entropy(const unsigned char *data, int len) {
    int freq[256] = {0};
    for (int i = 0; i < len; i++) freq[data[i]]++;

    double H = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / (double)len;
            H -= p * log2(p);
        }
    }
    return H;
}

const char *entropy_label(double H) {
    if (H < 1.0) return "Constant / mostly-zero data";
    if (H < 4.0) return "Low — structured text or config";
    if (H < 6.0) return "Medium — typical executable code";
    if (H < 7.2) return "High — possibly compressed";
    return "Very high — likely encrypted or packed ⚠";
}

void print_entropy(const unsigned char *data, long size) {
    printf("\n[Entropy Analysis — %d-byte blocks]\n", ENTROPY_BLOCK);
    printf("  Block      | Offset     | Entropy | Assessment\n");
    printf("  -----------|------------|---------|----------------------------\n");

    long blocks = (size + ENTROPY_BLOCK - 1) / ENTROPY_BLOCK;
    for (long b = 0; b < blocks; b++) {
        long offset = b * ENTROPY_BLOCK;
        int  blen   = (int)((offset + ENTROPY_BLOCK <= size)
                            ? ENTROPY_BLOCK
                            : size - offset);
        double H = shannon_entropy(data + offset, blen);
        printf("  Block %-4ld | 0x%08lx | %.4f  | %s\n",
               b + 1, offset, H, entropy_label(H));
    }
}

/* ── Hex Dump ──────────────────────────────────────────────────── */

void hex_dump(const unsigned char *data, long size, long start_offset, long length) {
    if (start_offset >= size) {
        fprintf(stderr, "[!] Offset %ld exceeds file size %ld.\n", start_offset, size);
        return;
    }

    long end = (length == -1) ? size : (start_offset + length);
    if (end > size) end = size;

    printf("\n[Hex Dump]  offset 0x%08lx – 0x%08lx  (%ld bytes)\n",
           start_offset, end - 1, end - start_offset);
    printf("  Offset    | 00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f | ASCII\n");
    printf("  ----------|--------------------------------------------------|-----------------\n");

    for (long pos = start_offset; pos < end; pos += BYTES_PER_ROW) {
        printf("  %08lx  | ", pos);

        int row_len = (int)((pos + BYTES_PER_ROW <= end)
                            ? BYTES_PER_ROW
                            : end - pos);

        /* Hex */
        for (int i = 0; i < BYTES_PER_ROW; i++) {
            if (i < row_len)
                printf("%02x ", data[pos + i]);
            else
                printf("   ");
            if (i == 7) printf(" ");
        }

        printf("| ");

        /* ASCII */
        for (int i = 0; i < row_len; i++)
            printf("%c", isprint(data[pos + i]) ? data[pos + i] : '.');
        printf("\n");
    }
}

/* ── String Search ─────────────────────────────────────────────── */

void search_string(const unsigned char *data, long size, const char *pattern) {
    size_t plen  = strlen(pattern);
    int    found = 0;

    printf("\n[String Search]  Pattern: \"%s\"\n", pattern);

    for (long i = 0; i <= size - (long)plen; i++) {
        if (memcmp(data + i, pattern, plen) == 0) {
            printf("  [+] Found at offset 0x%08lx (%ld)\n", i, i);
            /* Show 8 bytes of context before */
            long ctx_start = (i >= 8) ? i - 8 : 0;
            printf("      Context: ...");
            for (long j = ctx_start; j < i + (long)plen + 8 && j < size; j++) {
                unsigned char c = data[j];
                printf("%c", isprint(c) ? c : '.');
            }
            printf("...\n");
            found++;
        }
    }

    if (!found)
        printf("  [-] Pattern not found.\n");
    else
        printf("  [*] Total occurrences: %d\n", found);
}

/* ── Entry Point ───────────────────────────────────────────────── */

void print_help(const char *prog) {
    printf("\nHex Dump & Binary Forensics Utility\n");
    printf("Author: Krishna Aggarwal\n\n");
    printf("Usage:\n");
    printf("  %s <file>                             Full hex dump\n", prog);
    printf("  %s <file> --offset N --length N       Range dump\n", prog);
    printf("  %s <file> --search \"string\"           Find ASCII pattern\n", prog);
    printf("  %s <file> --entropy                   Entropy block analysis\n\n", prog);
    printf("Examples:\n");
    printf("  %s malware.bin\n", prog);
    printf("  %s binary --offset 0 --length 256\n", prog);
    printf("  %s dump.bin --search \"password\"\n", prog);
    printf("  %s suspect.exe --entropy\n", prog);
}

int main(int argc, char *argv[]) {
    if (argc < 2) { print_help(argv[0]); return 1; }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { fprintf(stderr, "[!] Cannot open: %s\n", argv[1]); return 1; }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);

    unsigned char *data = malloc((size_t)size);
    if (!data) { fprintf(stderr, "[!] Memory error.\n"); fclose(f); return 1; }
    fread(data, 1, (size_t)size, f);
    fclose(f);

    printf("\n[File] %s  |  Size: %ld bytes\n", argv[1], size);
    identify_signature(data, size < MAX_HEADER_LEN ? (int)size : MAX_HEADER_LEN);

    /* Parse mode flags */
    long        offset      = 0;
    long        length      = -1;
    char       *search_term = NULL;
    int         do_entropy  = 0;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--offset")  == 0 && i + 1 < argc) offset  = atol(argv[++i]);
        else if (strcmp(argv[i], "--length")  == 0 && i + 1 < argc) length  = atol(argv[++i]);
        else if (strcmp(argv[i], "--search")  == 0 && i + 1 < argc) search_term = argv[++i];
        else if (strcmp(argv[i], "--entropy") == 0) do_entropy = 1;
    }

    if (search_term)  search_string(data, size, search_term);
    if (do_entropy)   print_entropy(data, size);

    if (!search_term && !do_entropy) {
        /* Default: dump (cap at 512 bytes with notice) */
        if (length == -1 && size > 512) {
            printf("\n[Note] File is %ld bytes. Showing first 512 bytes.\n", size);
            printf("       Use --offset / --length to view other ranges.\n");
            length = 512;
        }
        hex_dump(data, size, offset, length);
    }

    free(data);
    return 0;
}
