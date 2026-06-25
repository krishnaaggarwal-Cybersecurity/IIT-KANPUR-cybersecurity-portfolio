/*
 * lsb_steganography.c — LSB Image Steganography in 24-bit BMP Files
 * Author: Krishna Aggarwal
 *
 * Hides (and extracts) text messages in the Least Significant Bit of
 * pixel bytes in uncompressed 24-bit BMP images. The 1-bit change per
 * channel is visually imperceptible to the human eye.
 *
 * Why this matters in cybersecurity:
 *   - APT groups use steganography to hide C2 instructions inside
 *     innocent-looking image files shared on social media or CDNs.
 *   - DLP (Data Loss Prevention) bypass: data exfiltrated via images
 *     evades keyword-based network inspection.
 *   - Digital forensics teams must know how to detect these channels
 *     (chi-square attack, RS analysis, StegExpose tool).
 *
 * How LSB works:
 *   Each pixel byte has 8 bits. The LSB (bit 0) contributes only 0 or 1
 *   to the color value. Flipping it changes red 200 (11001000) to 201
 *   (11001001) — a difference humans cannot see.
 *   We store 1 bit of our message per pixel byte. For a 1024×768 BMP:
 *     capacity = 1024 × 768 × 3 bytes/pixel ÷ 8 bits/char
 *             = 294,912 characters
 *
 * BMP format used:
 *   - BITMAPFILEHEADER (14 bytes)
 *   - BITMAPINFOHEADER (40 bytes)
 *   - Uncompressed 24-bit pixel data (BGR ordering, row-padded to 4 bytes)
 *
 * Detection notes (included as comments throughout):
 *   A forensic analyst can detect this via chi-square statistical test
 *   on the LSB distribution of pixel bytes (should be 50/50 if steg is
 *   present; natural images skew toward even values).
 *
 * Compile: gcc -o lsb_steganography lsb_steganography.c
 * Usage:
 *   Embed:   ./lsb_steganography --embed input.bmp output.bmp "secret message"
 *   Extract: ./lsb_steganography --extract image.bmp
 *   Analyze: ./lsb_steganography --analyze image.bmp   (LSB distribution stats)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* ── BMP Structures ────────────────────────────────────────────── */

#pragma pack(push, 1)
typedef struct {
    unsigned short type;         /* 0x4D42 = "BM" */
    unsigned int   file_size;
    unsigned short reserved1;
    unsigned short reserved2;
    unsigned int   pixel_offset; /* byte offset to first pixel */
} BMPFileHeader;

typedef struct {
    unsigned int   header_size;  /* 40 for BITMAPINFOHEADER */
    int            width;
    int            height;       /* negative = top-down; positive = bottom-up */
    unsigned short planes;
    unsigned short bit_count;    /* 24 = RGB, no palette */
    unsigned int   compression;  /* 0 = BI_RGB (uncompressed) */
    unsigned int   image_size;   /* can be 0 for BI_RGB */
    int            x_ppm;
    int            y_ppm;
    unsigned int   colors_used;
    unsigned int   colors_important;
} BMPInfoHeader;
#pragma pack(pop)

/* ── BMP I/O ───────────────────────────────────────────────────── */

typedef struct {
    BMPFileHeader fh;
    BMPInfoHeader ih;
    unsigned char *header_raw;   /* exact bytes before pixel data */
    unsigned char *pixels;       /* raw pixel bytes (no padding) */
    long           pixel_count;  /* total pixel bytes */
    int            row_stride;   /* padded bytes per row in file */
    int            width;
    int            height_abs;
} BMPImage;

void bmp_free(BMPImage *img) {
    if (img->header_raw) free(img->header_raw);
    if (img->pixels)     free(img->pixels);
}

int bmp_load(const char *path, BMPImage *out) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "[!] Cannot open: %s\n", path); return -1; }

    fread(&out->fh, sizeof(out->fh), 1, f);
    fread(&out->ih, sizeof(out->ih), 1, f);

    if (out->fh.type != 0x4D42) {
        fprintf(stderr, "[!] Not a BMP file (magic: 0x%04x)\n", out->fh.type);
        fclose(f); return -1;
    }
    if (out->ih.bit_count != 24) {
        fprintf(stderr, "[!] Only 24-bit uncompressed BMP is supported (got %d-bit).\n",
                out->ih.bit_count);
        fclose(f); return -1;
    }
    if (out->ih.compression != 0) {
        fprintf(stderr, "[!] Compressed BMP not supported.\n");
        fclose(f); return -1;
    }

    /* Save complete header for bit-perfect output */
    out->header_raw = malloc(out->fh.pixel_offset);
    rewind(f);
    fread(out->header_raw, 1, out->fh.pixel_offset, f);

    out->width      = out->ih.width;
    out->height_abs = abs(out->ih.height);

    /* BMP rows are padded to 4-byte alignment */
    out->row_stride = (out->width * 3 + 3) & ~3;

    /* Read full pixel data including padding */
    long full_pixel_bytes = (long)out->row_stride * out->height_abs;
    out->pixels = malloc((size_t)full_pixel_bytes);
    fread(out->pixels, 1, (size_t)full_pixel_bytes, f);
    fclose(f);

    /* Count usable (non-padding) pixel bytes */
    out->pixel_count = (long)out->width * out->height_abs * 3;

    return 0;
}

int bmp_save(const char *path, BMPImage *img) {
    FILE *f = fopen(path, "wb");
    if (!f) { fprintf(stderr, "[!] Cannot write: %s\n", path); return -1; }

    fwrite(img->header_raw, 1, img->fh.pixel_offset, f);

    /* Write pixel data row by row, preserving existing padding bytes */
    long full_bytes = (long)img->row_stride * img->height_abs;
    fwrite(img->pixels, 1, (size_t)full_bytes, f);
    fclose(f);
    return 0;
}

/*
 * Extract only the usable (non-padding) pixel bytes into a flat array.
 * Returns malloc'd buffer; caller must free.
 */
unsigned char *bmp_get_pixels_flat(BMPImage *img) {
    unsigned char *flat = malloc((size_t)img->pixel_count);
    for (int row = 0; row < img->height_abs; row++) {
        unsigned char *src = img->pixels + (long)row * img->row_stride;
        unsigned char *dst = flat + (long)row * img->width * 3;
        memcpy(dst, src, (size_t)(img->width * 3));
    }
    return flat;
}

/*
 * Write modified flat pixel bytes back into img->pixels (with padding).
 */
void bmp_set_pixels_flat(BMPImage *img, const unsigned char *flat) {
    for (int row = 0; row < img->height_abs; row++) {
        unsigned char *dst = img->pixels + (long)row * img->row_stride;
        const unsigned char *src = flat + (long)row * img->width * 3;
        memcpy(dst, src, (size_t)(img->width * 3));
    }
}

/* ── Bit-level I/O ─────────────────────────────────────────────── */

/* Write one bit into LSB of pixel byte at index */
#define SET_BIT(pixels, index, bit) \
    (pixels)[(index)] = ((pixels)[(index)] & 0xFE) | ((bit) & 1)

/* Read one bit from LSB of pixel byte at index */
#define GET_BIT(pixels, index) \
    ((pixels)[(index)] & 1)

/* ── Embed ─────────────────────────────────────────────────────── */

int cmd_embed(const char *in_path, const char *out_path, const char *message) {
    BMPImage img;
    if (bmp_load(in_path, &img) != 0) return -1;

    /* Include null terminator so we know where message ends on extraction */
    size_t msg_len  = strlen(message) + 1;
    long   bits_needed = (long)msg_len * 8;

    if (bits_needed > img.pixel_count) {
        fprintf(stderr, "[!] Message too long. Capacity: %ld chars, message: %zu chars.\n",
                img.pixel_count / 8, msg_len);
        bmp_free(&img);
        return -1;
    }

    unsigned char *flat = bmp_get_pixels_flat(&img);

    /* Embed each bit MSB-first */
    for (long i = 0; i < bits_needed; i++) {
        int byte_idx = (int)(i / 8);
        int bit_pos  = 7 - (int)(i % 8);
        int bit      = (message[byte_idx] >> bit_pos) & 1;
        SET_BIT(flat, i, bit);
    }

    bmp_set_pixels_flat(&img, flat);
    free(flat);

    int rc = bmp_save(out_path, &img);
    bmp_free(&img);

    if (rc == 0) {
        printf("[+] Message embedded into '%s'\n", out_path);
        printf("[*] %ld bits used out of %ld available (%.1f%% capacity)\n",
               bits_needed, img.pixel_count,
               100.0 * (double)bits_needed / (double)img.pixel_count);
        printf("[*] Image dimensions: %dx%d  |  Carrier size: %ld bytes\n",
               img.width, img.height_abs, img.pixel_count / 8);
        printf("[!] Detection note: chi-square test on LSB distribution\n");
        printf("    will show near-50/50 split in modified pixels.\n");
        printf("    StegExpose and zsteg tools can identify this method.\n");
    }
    return rc;
}

/* ── Extract ───────────────────────────────────────────────────── */

int cmd_extract(const char *path) {
    BMPImage img;
    if (bmp_load(path, &img) != 0) return -1;

    unsigned char *flat = bmp_get_pixels_flat(&img);

    size_t max_chars = (size_t)(img.pixel_count / 8);
    unsigned char *message = calloc(max_chars + 1, 1);

    for (long i = 0; i < img.pixel_count; i++) {
        long byte_idx = i / 8;
        int  bit_pos  = 7 - (int)(i % 8);
        message[byte_idx] |= (unsigned char)(GET_BIT(flat, i) << bit_pos);

        /* Null terminator found at byte boundary */
        if (message[byte_idx] == '\0' && (i % 8) == 7 && byte_idx > 0) {
            printf("[+] Message extracted:\n");
            printf("    \"%s\"\n", message);
            printf("[*] Length: %ld characters\n", byte_idx);
            free(flat);
            free(message);
            bmp_free(&img);
            return 0;
        }
    }

    printf("[-] No null-terminated message found (may not contain embedded data).\n");
    free(flat);
    free(message);
    bmp_free(&img);
    return 0;
}

/* ── LSB Distribution Analysis (detection simulation) ─────────── */

int cmd_analyze(const char *path) {
    BMPImage img;
    if (bmp_load(path, &img) != 0) return -1;

    unsigned char *flat = bmp_get_pixels_flat(&img);

    long ones  = 0, zeros = 0;
    for (long i = 0; i < img.pixel_count; i++) {
        if (GET_BIT(flat, i)) ones++;
        else                  zeros++;
    }

    double ratio = 100.0 * (double)ones / (double)img.pixel_count;

    printf("\n[LSB Distribution Analysis]  %s\n", path);
    printf("  Image: %dx%d  |  Pixel bytes: %ld\n",
           img.width, img.height_abs, img.pixel_count);
    printf("  LSB zeros : %ld (%.2f%%)\n", zeros, 100.0 - ratio);
    printf("  LSB ones  : %ld (%.2f%%)\n", ones, ratio);
    printf("\n  Interpretation:\n");
    if (ratio > 48.0 && ratio < 52.0) {
        printf("  ⚠  Near-equal distribution (%.2f%% ones)\n", ratio);
        printf("     SUSPICIOUS — consistent with LSB steganography.\n");
        printf("     Natural images tend toward more even LSBs in smooth areas\n");
        printf("     but not this uniformly. Recommend full steg analysis.\n");
    } else {
        printf("  ✓  Distribution appears natural (%.2f%% ones).\n", ratio);
        printf("    Less consistent with LSB steganography (not conclusive).\n");
    }

    free(flat);
    bmp_free(&img);
    return 0;
}

/* ── Entry Point ───────────────────────────────────────────────── */

void print_help(const char *prog) {
    printf("\nLSB Steganography Tool — 24-bit BMP Images\n");
    printf("Author: Krishna Aggarwal\n\n");
    printf("Commands:\n");
    printf("  %s --embed <input.bmp> <output.bmp> \"message\"\n", prog);
    printf("      Hide message in LSBs of output BMP.\n\n");
    printf("  %s --extract <image.bmp>\n", prog);
    printf("      Recover hidden message from image.\n\n");
    printf("  %s --analyze <image.bmp>\n", prog);
    printf("      LSB distribution analysis (steg detection heuristic).\n\n");
    printf("Notes:\n");
    printf("  - Only uncompressed 24-bit BMP files are supported.\n");
    printf("  - Convert PNG/JPG: 'convert image.jpg -compress None image.bmp' (ImageMagick)\n");
    printf("  - Detection: chi-square test, RS analysis, StegExpose, zsteg\n");
}

int main(int argc, char *argv[]) {
    if (argc < 3) { print_help(argv[0]); return 1; }

    if (strcmp(argv[1], "--embed") == 0 && argc == 5)
        return cmd_embed(argv[2], argv[3], argv[4]);

    if (strcmp(argv[1], "--extract") == 0 && argc == 3)
        return cmd_extract(argv[2]);

    if (strcmp(argv[1], "--analyze") == 0 && argc == 3)
        return cmd_analyze(argv[2]);

    print_help(argv[0]);
    return 1;
}
