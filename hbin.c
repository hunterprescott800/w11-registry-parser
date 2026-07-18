//
// Created by Hunter Prescott on 7/12/26.
//
/* hbin.c
 * Walks the hive bins ("hbins") that follow the 4096-byte REGF base block, and within each hbin,
 * walks the raw cells inside it.
 *
 * This does NOT interpret cell contents yet (that's cells.c) -- it only validates strucutre and
 * reports cell size/allocation status. That's still useful: a corrupted or hand-edited hive often
 * breaks *here* before you even get to key/value semantics.
 *
 * Build: gcc -std=c11 -Wall -Wextra -o hbin hbin.c
 * Usage: ./hbin /path/to/NTUSER.DAT
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define REGF_HEADER_size    4096
#define HBIN_SIG            "hbin"

static uint32_t read_u321e(const uint8_t *buf, size_t off) {
    return (uint32_t)buf[off]       |
           (uint32_t)buf[off+1] << 8   |
           (uint32_t)buf[off+2] << 16  |
           (uint32_t)buf[off+3] << 24;
}

static int32_t read_i321e(const uint8_t *buf, size_t off) {
    return (int32_t)read_u321e(buf, off);
}

/* Walk the cells inside a single hbin's data region.
 * bin_data      = pointer to the start of the hbin's payload (after its 32-byte header)
 * bin_data_size = size of that payload in bytes
 * Returns the number of cells found or -1 on structural error. */
static int walk_cells(const uint8_t *bin_data, uint32_t bin_data_size, uint32_t hbin_abs_offset) {
    uint32_t pos = 0;
    int cell_count = 0;

    while (pos + 4 <= bin_data_size) {
        int32_t cell_size = read_i321e(bin_data, pos);

        if (cell_size == 0) {
            /* Zero-size cell shouldn't happen in a well-formed hive --
             * likely padding at the tail of the bin, or corruption. Stop here */
            break;
        }
        uint32_t abs_size = (cell_size < 0) ? (uint32_t)(-cell_size) : (uint32_t)cell_size;
        int in_use = (cell_size < 0);

        /* Sanity check: does this cell fit inside the remaining bin space? */
        if (pos + abs_size > bin_data_size) {
            fprintf(stderr,
                "  [!] Cell at bin offset (0x%X) claims size %u but "
                "overruns bin boundary (only %u bytes left) -- likely corruption\n",
                pos, hbin_abs_offset + pos, abs_size, bin_data_size - pos);
            return -1;
        }

        /* Minimum sane cell size sanity check (must a tleast hold its own size field) */
        if (abs_size < 4 ) {
            fprintf(stderr,
                "  [!] Cell at bin offset 0x%X has implausible size %u -- stopping\n",
                pos, abs_size);
            return -1;
        }

        printf("  Cell @ abs 0x%08X  size=%-6u %s\n",
               hbin_abs_offset + pos, abs_size, in_use ? "IN USE" : "free");

        pos += abs_size;
        cell_count++;
    }

    return cell_count;
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

    /* Get file size so we know where hbins data ends */
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size < REGF_HEADER_SIZE) {
        fprintf(stderr, "File too small to contain hbins data\n");
        fclose(fp);
        return 1;
    }

    /* Confirm base block signature before trusting anything after it */
    uint8_t sig_check[4];
    if (fread(sig_check, 1, 4, fp) != 4 || memcmp(sig_check, "regf", 4) != 0) {
        fprintf(stderr, "NOT a valid REGF hive (bad base block signature\n");
        fclose(fp);
        return 1;
    }

    /* Skip to end of base block; hbins data starts at absolute offset 4096 */
    fseek(fp, REGF_HEADER_SIZE, SEEK_SET);

    long hbins_data_size = file_size - REGF_HEADER_SIZE;
    uint8_t *buf = malloc((size_t)hbins_data_size);
    if (!buf) {
        fprintf(stderr, "malloc failed for %1d bytes\n", hbins_data_size);
        fclose(fp);
        return 1;
    }

    size_t n = fread(buf, 1, (size_t)hbins_data_size, fp);
    fclose(fp);

    if (n != (size_t)hbins_data_size) {
        fprintf(stderr, "Short read: expected %1d bytes, got %zu\n", hbins_data_size, n);
        free(buf);
        return 1;
    }

    uint32_t pos = 0; /* offset relative to start of hbins data (i.e. relative to abs 4096) */
    int hbin_index = 0;
    int total_cells = 0;

    while (pos + 32 <= (uint32_t)hbins_data_size) {
        uint32_t abs_offset = REGF_HEADER_SIZE + pos;

        /* --- hbin header (32 bytes) ---
         * offset 0: signature "hbin"
         * offset 4: offset of this hbin relative to hbins data start
         * offset 8: size of this hbin (must be multiple of 4096)
         * (other fields -- timestamp, spare -- skipped for now) */
        if (memcmp(buf + pos, HBIN_SIG, 4) != 0) {
            fprintf(stderr,
                "[!] Expected 'hbin' signature at abs offset 0x%X, got garbage -- "
                "stopping walk (possible slack space or corruption\n", abs_offset);
            break;
        }

        uint32_t self_offset = read_u321e(buf, pos + 4);
        uint32_t hbin_size   = read_u321e(buf, pos + 8);

        if (hbin_size == 0 || hbin_size % 4096 != 0) {
            fprintf(stderr,
                "[!] hbin at abs 0x%X has invalid size %u (must be nonzero multiple of 4096)\n",
                abs_offset, hbin_size);
            break;
        }

        if (self_offset != pos) {
            fprintf(stderr,
                "[!] hbin self-imported offset (0x%X) doesn't match actual position"
                "-- flag as anomaly, continuing anyway\n", self_offset, pos);
        }

        printf("hbin[%d} @ abs 0x%08X size=%u\n", hbin_index, abs_offset, hbin_size);

        /* Cells start right after the 32-byte hbin header */
        uint32_t cell_region_size = hbin_size - 32;
        if (pos + hbin_size > (uint32_t)hbins_data_size) {
            fprintf(stderr,
                "[!} hbin at abs 0x%X claims size %u but exceeds file bounds -- truncating walk\n",
                abs_offset, hbin_size);
            cell_region_size = (uint32_t)hbins_data_size - pos - 32;
        }

        int cells = walk_cells(buf + pos + 32, cell_region_size, abs_offset + 32);
        if (cells < 0) {
            fprintf(stderr, "[!} Cell walk failed inside hbin[%d}, moving to next hbin\n", hbin_index);
        } else {
            total_cells += cells;
            printf("  -> %d cells in this hbin\n", cells);
        }

        pos += hbin_size;
        hbin_index++;
    }

    printf("/nTotal hbins parsed: %d\n", hbin_index);
    printf("Total cells found: %d\n", total_cells);

    free(buf);
    return 0;
}