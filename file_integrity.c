/*
 * file_integrity.c — File Integrity Monitor (FIM)
 * Author: Krishna Aggarwal
 *
 * Detects unauthorized modifications to monitored files by comparing
 * Adler-32 checksums against a stored baseline. This is the core concept
 * behind Host-based Intrusion Detection Systems (HIDS) such as Tripwire,
 * AIDE, and OSSEC.
 *
 * How it works:
 *   1. BASELINE mode: compute checksums + metadata for each target file,
 *      save to a baseline file.
 *   2. VERIFY mode: recompute checksums, compare against baseline.
 *      Alert on modification, deletion, or size mismatch.
 *
 * Adler-32 is used here (MOD_ADLER = 65521, a prime) because it is
 * fast, simple to implement in pure C, and sufficient for demonstration.
 * Production FIM tools use SHA-256 or SHA-512 for collision resistance.
 *
 * Concepts demonstrated:
 *   - Host-based intrusion detection (HIDS) principles
 *   - Checksum/hash-based tamper detection
 *   - Baseline establishment and drift detection
 *   - File metadata analysis (size, modification time)
 *   - Why integrity monitoring is a fundamental defensive control
 *
 * Compile: gcc -o file_integrity file_integrity.c
 * Usage:
 *   Create baseline: ./file_integrity --baseline /etc/passwd /etc/hosts
 *   Verify files:    ./file_integrity --verify
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define MOD_ADLER      65521U
#define MAX_PATH_LEN   512
#define MAX_FILES      128
#define BASELINE_FILE  ".fim_baseline.dat"
#define FIM_VERSION    1

typedef struct {
    char          filepath[MAX_PATH_LEN];
    unsigned long checksum;
    long          filesize;
    time_t        last_modified;
} FileRecord;

typedef struct {
    int version;
    int count;
    time_t created_at;
} BaselineHeader;

/*
 * Adler-32 checksum
 * Two running sums A and B, both modulo the prime 65521.
 * A = sum of all bytes; B = sum of all values of A.
 * Result = (B << 16) | A
 */
unsigned long adler32(const unsigned char *data, size_t len) {
    unsigned long a = 1, b = 0;
    for (size_t i = 0; i < len; i++) {
        a = (a + data[i]) % MOD_ADLER;
        b = (b + a)       % MOD_ADLER;
    }
    return (b << 16) | a;
}

/*
 * Read entire file, compute Adler-32, store file size.
 * Returns 0 on error.
 */
unsigned long checksum_file(const char *path, long *out_size) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "  [!] Cannot open: %s\n", path);
        *out_size = -1;
        return 0;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);
    *out_size = size;

    if (size == 0) {
        fclose(f);
        return adler32((unsigned char *)"", 0);
    }

    unsigned char *buf = malloc((size_t)size);
    if (!buf) {
        fclose(f);
        fprintf(stderr, "  [!] Memory allocation failed.\n");
        return 0;
    }

    fread(buf, 1, (size_t)size, f);
    fclose(f);

    unsigned long csum = adler32(buf, (size_t)size);
    free(buf);
    return csum;
}

const char *format_time(time_t t) {
    static char buf[64];
    struct tm *tm_info = localtime(&t);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);
    return buf;
}

/* ── BASELINE MODE ─────────────────────────────────────────────── */

void create_baseline(char *files[], int count) {
    FileRecord records[MAX_FILES];
    int        valid = 0;

    printf("\n[FIM] Creating integrity baseline\n");
    printf("[FIM] Baseline file: %s\n\n", BASELINE_FILE);

    for (int i = 0; i < count && valid < MAX_FILES; i++) {
        long size = 0;
        unsigned long csum = checksum_file(files[i], &size);

        if (csum == 0 && size == -1) {
            printf("  [SKIP] %s (cannot read)\n", files[i]);
            continue;
        }

        struct stat st;
        if (stat(files[i], &st) != 0) {
            printf("  [SKIP] %s (stat failed)\n", files[i]);
            continue;
        }

        strncpy(records[valid].filepath, files[i], MAX_PATH_LEN - 1);
        records[valid].filepath[MAX_PATH_LEN - 1] = '\0';
        records[valid].checksum      = csum;
        records[valid].filesize      = size;
        records[valid].last_modified = st.st_mtime;

        printf("  [OK]   %-40s  %8ld bytes  checksum: %08lx\n",
               files[i], size, csum);
        valid++;
    }

    FILE *base = fopen(BASELINE_FILE, "wb");
    if (!base) {
        fprintf(stderr, "\n[!] Cannot write baseline to %s\n", BASELINE_FILE);
        return;
    }

    BaselineHeader hdr;
    hdr.version    = FIM_VERSION;
    hdr.count      = valid;
    hdr.created_at = time(NULL);

    fwrite(&hdr,     sizeof(BaselineHeader), 1,     base);
    fwrite(records,  sizeof(FileRecord),     valid, base);
    fclose(base);

    printf("\n[FIM] Baseline saved. %d file(s) registered at %s\n",
           valid, format_time(hdr.created_at));
    printf("[FIM] Store this baseline file in a write-protected location.\n");
    printf("[FIM] If an attacker modifies BOTH the files AND the baseline, detection fails.\n");
    printf("      → In production: baseline lives on read-only media or a separate host.\n");
}

/* ── VERIFY MODE ───────────────────────────────────────────────── */

void verify_integrity(void) {
    FILE *base = fopen(BASELINE_FILE, "rb");
    if (!base) {
        fprintf(stderr, "[!] No baseline found at '%s'.\n", BASELINE_FILE);
        fprintf(stderr, "    Run with --baseline <file1> <file2> ... first.\n");
        return;
    }

    BaselineHeader hdr;
    if (fread(&hdr, sizeof(BaselineHeader), 1, base) != 1 ||
        hdr.version != FIM_VERSION || hdr.count <= 0) {
        fprintf(stderr, "[!] Baseline file is corrupt or incompatible.\n");
        fclose(base);
        return;
    }

    FileRecord *records = malloc((size_t)hdr.count * sizeof(FileRecord));
    if (!records) {
        fprintf(stderr, "[!] Memory error.\n");
        fclose(base);
        return;
    }
    fread(records, sizeof(FileRecord), (size_t)hdr.count, base);
    fclose(base);

    printf("\n[FIM] Integrity Verification\n");
    printf("[FIM] Baseline created: %s (%d file(s))\n\n",
           format_time(hdr.created_at), hdr.count);

    int alerts = 0;
    int ok     = 0;

    for (int i = 0; i < hdr.count; i++) {
        long size = 0;
        unsigned long csum = checksum_file(records[i].filepath, &size);

        if (size == -1) {
            printf("  [ALERT] MISSING        %s\n", records[i].filepath);
            printf("          Expected: checksum %08lx, size %ld bytes\n",
                   records[i].checksum, records[i].filesize);
            alerts++;
            continue;
        }

        if (csum != records[i].checksum) {
            printf("  [ALERT] MODIFIED       %s\n", records[i].filepath);
            printf("          Checksum: expected %08lx  got %08lx\n",
                   records[i].checksum, csum);
            printf("          Size:     expected %ld      got %ld bytes\n",
                   records[i].filesize, size);
            alerts++;
            continue;
        }

        printf("  [OK]    %-40s  checksum: %08lx  INTACT\n",
               records[i].filepath, csum);
        ok++;
    }

    printf("\n══════════════════════════════════\n");
    if (alerts == 0) {
        printf("[FIM] All %d file(s) verified. No tampering detected.\n", ok);
    } else {
        printf("[FIM] ⚠  %d INTEGRITY VIOLATION(S) DETECTED\n", alerts);
        printf("[FIM] Investigate immediately. Do not trust affected files.\n");
    }
    free(records);
}

/* ── ENTRY POINT ───────────────────────────────────────────────── */

void print_help(const char *prog) {
    printf("\nFile Integrity Monitor — HIDS concept demonstration\n");
    printf("Author: Krishna Aggarwal\n\n");
    printf("Usage:\n");
    printf("  %s --baseline <file1> [file2 ...]\n", prog);
    printf("      Compute and store checksums for listed files.\n\n");
    printf("  %s --verify\n", prog);
    printf("      Compare current file state against stored baseline.\n\n");
    printf("Security note:\n");
    printf("  Adler-32 is used here for simplicity. Production systems use\n");
    printf("  SHA-256 or SHA-512 to prevent checksum collision attacks.\n");
    printf("  (Adler-32 is NOT cryptographically secure.)\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_help(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--baseline") == 0) {
        if (argc < 3) {
            fprintf(stderr, "[!] Provide at least one file path after --baseline.\n");
            return 1;
        }
        create_baseline(&argv[2], argc - 2);

    } else if (strcmp(argv[1], "--verify") == 0) {
        verify_integrity();

    } else {
        fprintf(stderr, "[!] Unknown option: %s\n", argv[1]);
        print_help(argv[0]);
        return 1;
    }

    return 0;
}
