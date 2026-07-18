//
// Created by Hunter Prescott on 7/11/26.
//

/* regf_header.c
 * Parses the 4096-byte "base block" that begins every Windows registry hive.
 * Format reference: public documentation of the REGF header (offsets are stable across hive versions
 * in practice, though msregistry docs mark v1.5 nuances).
 *
 * Build: gcc -o regf_header regf_header.c
 * Usage: ./regf_header /path/to/NTUSER.DAT
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#define REGF_HEADER_SIZE    4096
#define REGF_SIG            "regf"

/* Little-endian readers. never cast a struct over the buffer -- alignment
 * and padding rules differ across compilers/platforms and will silently corrupt your offsets.
 * Read every multi-byte field by hand. */

static uint32_t read_u321e(const uint8_t *buf, size_t off) {
    return (uint32_t)buf[off]     |
           (uint32_t)buf[off+1] << 8  |
           (uint32_t)buf[off+2] << 16 |
           (uint32_t)buf[off+3] << 24;
}

static uint64_t read_u641e(const uint8_t *buf, size_t off) {
    uint64_t lo = read_u321e(buf, off);
    uint64_t hi = read_u321e(buf, off+4);
    return lo | (hi << 32);
}

/* Windows FILETIME: 100ns intervals since 1601-01-01.
 * Convert to Unix epoch (seconds since 1970-01-01) for display. */
static void print_filetime(uint64_t filetime) {
    if (filetime == 0) {
        printf("(none)\n");
        return;
    }
    const uint64_t EPOCH_DIFF=116444736000000000ULL; /* 1601->1970 in 100ns units */
    if (filetime < EPOCH_DIFF) {
        printf("(invalid/pre-epoch)\n");
        return;
    }
    time_t unix_secs = (time_t)((filetime - EPOCH_DIFF) / 10000000ULL);
    char buf[64];
    struct tm tm_utc;
    gmtime_r(&unix_secs, &tm_utc);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tm_utc);
    printf("%s\n", buf);
}

/* Checksum is XOR-32 of the first 508 bytes (127 DWORDSs), stored at offset 508. */
static uint32_t compute_checksum(const uint8_t *buf) {
    uint32_t sum = 0;
    for (int i = 0; i <508; i += 4) {
        sum ^= read_u321e(buf, i);
    }
    return sum;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <hive file>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    uint8_t header[REGF_HEADER_SIZE];
    size_t n = fread(header, 1, REGF_HEADER_SIZE, fp);
    fclose(fp);

    if (n < 512) {
        fprintf(stderr, "File too small to contain a valid REGF header (%zu bytes read)\n", n);
        return 1;
    }

    /* --- Signature --- */
    if (memcmp(header, REGF_SIG, 4) != 0) {
        fprintf(stderr, "Not a registry hive: bad signature (expected \"regf\")\n");
        return 1;
    }
    printf("Signature:              regf (valid)\n");

    /* --- Sequence numbers (offsets 4, 8) ---
     * These should match in a cleanly-closed hive. A mismatch can indicate
     * the hive wasn't flushed properly -- worth flagging in your anomaly logic later. */
    uint32_t seq1 = read_u321e(header, 4);
    uint32_t seq2 = read_u321e(header, 8);
    printf("Primary sequence:       %u\n", seq1);
    printf("Secondary sequence:     %u\n", seq2);
    printf("Sequences match:        %s\n", (seq1 == seq2) ? "yes" : "NO (dirty hive?)");

    /* --- Last written timestamp (offset 12, 8 bytes) --- */
    uint64_t last_written = read_u641e(header, 12);
    printf("Last written:           ");
    print_filetime(last_written);

    /* --- Version (offsets 20, 24) --- */
    uint32_t major = read_u321e(header, 20);
    uint32_t minor = read_u321e(header, 24);
    printf("Version:                %u.%u\n", major, minor);

    /* File type / format (offsets 28, 32) --- */
    printf("File type:          %u\n", read_u321e(header, 28));
    printf("File format:        %u\n", read_u321e(header, 32));

    /* --- Root cell offset (offset 36) ---
     * Rlative to the start of the hive bins data (i.e. add 4096). This is
     * your entry point into the key/value tree once you write cells.c. */
    uint32_t root_cell_offset = read_u321e(header, 36);
    printf("Root cell offset:       0x%X (absolute: 0x%X)\n",
           root_cell_offset, root_cell_offset + REGF_HEADER_SIZE);

    /* --- Hive bins data size (offset 40) --- */
    uint32_t hbin_size = read_u321e(header, 40);
    printf("Hive bins data size:    %u bytes\n", hbin_size);

    /* --- Hive name (offset 48, 64 bytes, UTF-16LE, may be truncated/legacy) --- */
    printf("Embedded file name:     ");
    for (int i = 48; i < 48 + 64; i += 2) {
        uint16_t wc = header[i] | (header[i+1] << 8);
        if (wc == 0) break;
        if (wc < 128) putchar((char)wc); /* ASCII subset only, good enough here */
    }
    printf("\n");

    /* --- Checksum validation (offset 508) --- */
    uint32_t stored_checksum = read_u321e(header, 508);
    uint32_t computed = compute_checksum(header);
    printf("Stored checksum:        0x%08X\n", stored_checksum);
    printf("Computed checksum:      0x%08X\n", computed);
    printf("Checksum valid:         %s\n", (stored_checksum == computed) ? "yes" : "NO (corrupt or tampered header)");

    return 0;
}