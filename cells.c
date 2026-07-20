//
// Created by Hunter Prescott on 7/18/26.
//
/* cells.c
 * parses nk (key), vk (value), and lf/lh (subkey list) cells, and walks the registry tree recursively
 * starting from the root key.
 *
 * Build: gcc -std=c11 -Wall -Wextra -o cells cells.c
 * Usage: ./cells /path/to/NTUSER.DAT
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "regf.h"

static uint8_t *g_hbins_data        = NULL;
static uint32_t g_hbins_data_size   = 0;    /* size of buffer, hbins region only (starts at abs 4096) */

static uint32_t read_u321e(const uint8_t *buf, size_t off) {
    return (uint32_t)buf[off]       |
           (uint32_t)buf[off+1] << 8  |
           (uint32_t)buf[off+2] << 16 |
           (uint32_t)buf[off+3] << 24;
}

static int32_t read_i321e(const uint8_t *buf, size_t off) {
    return (int32_t)read_u321e(buf, off);
}

static uint16_t read_u161e(const uint8_t *buf, size_t off) {
    return (uint16_t)(buf[off] | (buf[off+1] << 8));
}

static uint64_t read_u641e(const uint8_t *buf, size_t off) {
    uint64_t lo = read_u321e(buf, off);
    uint64_t hi = read_u321e(buf, off + 4);
    return lo | (hi << 32);
}

/* Convert an absolute file offset into a pointer inside our in-memory buffer.
 * Returns NULL if the offset is out of bound -- ALWAYS check this before use
 * This is the single choke point for bounds safety across the entire parser. */
static const uint8_t *abs_ptr(uint32_t abs_offset, uint32_t min_size_needed) {
    if (abs_offset < REGF_HEADER_SIZE) return NULL;
    uint32_t rel = abs_offset - REGF_HEADER_SIZE;
    if (rel + min_size_needed > g_hbins_data_size) return NULL;
    return g_hbins_data + rel;
}

/* Relative-to-hbins-data offsets (as stored in nk/vk fields) are relative to absolute 4096,
 * same as everything else. This centralizes the +4096. */
static uint32_t rel_to_abs(uint32_t rel_offset) {
    return REGF_HEADER_SIZE + rel_offset;
}

/* Name decode attempt. Registry key/value names are usually ASCII but can be UTF-16LE depending
 * on a flag in the nk cell. Handle common ASCII case cleanly and degrade gracefuly otherwise */
static void copy_name_ascii(char *dst, size_t dst_size, const uint8_t *src, uint16_t len) {
    size_t n = (len < dst_size - 1) ? len: dst_size -1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* --- Parse a 'vk' (value) cell at the given absolute offset --- */
static int parse_vk(uint32_t abs_offset, regf_value_t *out) {
    /* vk cell layout (after the 4-byte cell size, which the caller already took in:
     * 0: signature "vk" (2 bytes)
     * 2: name length (uint16)
     * 4: data size (uint32) -- high bit set means data is stored INLINE here
     * 8: data offset (uint32) -- relative offset to data, OR the inline data itself
     * 12: data type (uint32)
     * 16: flags (uint16) -- bit 0 set means the name is ASCII, unset means UTF-16LE
     * 18: spare (uint16)
     * 20: name (variable length, name_length bytes) */
    const uint8_t *p = abs_ptr(abs_offset, 20);
    if (!p) {
        fprintf(stderr, " [!] vk cell at abs 0x%X out of bounds\n", abs_offset);
        return -1;
    }
    if (memcmp(p, "vk", 2) != 0) {
        fprintf(stderr, " [!] Expected 'vk' signature at abs 0x%X, found '%c%c'\n", abs_offset, p[0], p[1]);
        return -1;
    }
    uint16_t name_len   = read_u161e(p, 2);
    uint32_t raw_size   = read_u321e(p, 4);
    uint32_t data_offset= read_u321e(p, 8);
    uint32_t data_type  = read_u321e(p, 12);

    out->abs_offset = abs_offset;
    out->data_type  = data_type;

    /* Top bit of the size field flags inline storage (data fits in 4 bytes) */
    if (raw_size & 0x80000000) {
        out->inline_data = 1;
        out->data_size   = raw_size & 0x7FFFFFFF;
        memcpy(out->inline_bytes, &data_offset, 4); /* data_offset field IS the data here */
    }else {
        out->inline_data = 0;
        out->data_size   = raw_size;
        out->data_offset = data_offset;
    }

    if (name_len == 0) {
        strcpy(out->name, "(default");
    } else {
        const uint8_t *name_ptr = abs_ptr(abs_offset + 20, name_len);
        if (!name_ptr) {
            fprintf(stderr, " [!] vk name at abs 0x%X out of bounds\n", abs_offset + 20);
            return -1;
        }
        copy_name_ascii(out->name, sizeof(out->name), name_ptr, name_len);
    }
    return 0;
}

/* --- Parse a 'nk' (key) cell at the given absolute offset --- */
static int parse_nk(uint32_t abs_offset, regf_key_t *out) {
    /* nk cell layout (selected fields -- there are more we aren't using yet)
     * 0: signature "nk"
     * 2: flags (uint16)
     * 4: last written time (FILETIME, 8 bytes)
     * 16: access bits (uints32) -- skip
     * 20: parent key offset (uint32) -- skip for now
     * 24: subkey count (uint32)
     * 28: (volatile subkey count -- skip, uint32)
     * 32: subkey list offset (uint32)
     * 36: (volatile subkey list offset -- skip, uint32)
     * 40: value count (uint32)
     * 44: value list offset (uint32)
     * 48: security key offset (uint32) -- skip for now
     * 52: class name offset (uint32) -- skip for now
     * ... (more fields) ...
     * 76: name length (uint16)
     * 78: class name length (uint16)
     * 80: name (variable length) */

    const uint8_t *p = abs_ptr(abs_offset, 80);
    if (!p) {
        fprintf(stderr, " [!] nk cell at abs 0x%X out of bounds\n", abs_offset);
        return -1;
    }
    if (memcmp(p, "nk", 2) != 0) {
        fprintf(stderr, " [!] Expected 'nk' signature at abs 0x%X, found '%c%c'\n",
                abs_offset, p[0], p[1]);
        return -1;
    }
    out->abs_offset         = abs_offset;
    out->last_written       = read_u641e(p, 4);
    out->subkey_count       = read_u321e(p, 24);
    out->subkey_list_offset = read_u321e(p, 32);
    out->value_count        = read_u321e(p, 40);
    out->value_list_offset  = read_u321e(p, 44);

    uint16_t name_len = read_u161e(p, 76);
    if (name_len == 0 || name_len >= sizeof(out->name)) {
        strcpy(out->name, "(unnamed/oversized)");
    } else {
        const uint8_t *name_ptr = abs_ptr(abs_offset + 80, name_len);
        if (!name_ptr) {
            fprintf(stderr, " [!] name at abs 0x%X out of bounds\n", abs_offset + 80);
            return -1;
        }
        copy_name_ascii(out->name, sizeof(out->name), name_ptr, name_len);
    }
    return 0;
}

/* --- Walk a subkey list (lf/lh) and recurse into each subkey ---
 * depth is just for indentation in the printout. */
static void walk_subkeys(uint32_t list_abs_offset, int depth);

static void print_indent(int depth) {
    for (int i = 0; i < depth; i++) printf(" ");
}

static void walk_values(uint32_t value_list_abs_offset, uint32_t value_count, int depth) {
    /* The value list is a plain array of uint32 offsets, no signature of its own. */
    const uint8_t *p = abs_ptr(value_list_abs_offset, value_count * 4);
    if (!p) {
        print_indent(depth);
        fprintf(stderr, "[!] value list at abs 0x%X out of bounds\n", value_list_abs_offset);
        return;
    }

    for (uint32_t i = 0; i < value_count; i++) {
        uint32_t vk_rel = read_u321e(p, i * 4);
        uint32_t vk_abs = rel_to_abs(vk_rel);

        regf_value_t val;
        if (parse_vk(vk_abs, &val) != 0) {
            print_indent(depth);
            fprintf(stderr, "[!] failed to parse value #%u\n", i);
            continue;
        }
        print_indent(depth);
        printf("- %s (type=%u, size=%u%s)\n",
               val.name, val.data_type, val.data_size,
               val.inline_data ? ", inline" : "");
    }
}

static void walk_subkeys(uint32_t list_abs_offset, int depth) {
    /* lf/lh cell layout:
     * 0: signature "lf" or "lh" (2 bytes)
     * 2: numbre of elements (uint16)
     * 4: array of (offset uint32, hash uint32) pairs, 8 bytes each
     * We only need the offset; the hash (used for fast name lookup) is skipped. */
    const uint8_t *p = abs_ptr(list_abs_offset, 4);
    if (!p) {
        print_indent(depth);
        fprintf(stderr, " [!] subkey list at abs 0x%X out of bounds\n", list_abs_offset);
        return;
    }
    int is_lf = (memcmp(p, "lf", 2) == 0);
    int is_lh = (memcmp(p, "lh", 2) == 0);
    int is_ri = (memcmp(p, "ri", 2) == 0);

    if (is_ri) {
        /* 'ri' is an indirect list: an array of offsets to other lf/lh lists.
         * Used when a key has enough subkeys that one list is not sufficient.
         * We recurse into each sub-list. */
        uint16_t count = read_u161e(p, 2);
        const uint8_t *arr = abs_ptr(list_abs_offset + 4, count * 4);
        if (!arr) {
            print_indent(depth);
            fprintf(stderr, "[!] ri list at the abs 0x%X out of bounds\n", list_abs_offset);
            return;
        }
        for (uint16_t i = 0; i < count; i++) {
            uint32_t sub_list_rel = read_u321e(arr, i * 4);
            walk_subkeys(rel_to_abs(sub_list_rel), depth);
        }
        return;
    }

    if (!is_lf && !is_lh) {
        print_indent(depth);
        fprintf(stderr, "[!] Unrecognized subkey list signature at abs 0x%X: '%c%c'\n",
                list_abs_offset, p[0], p[1]);
        return;
    }

    uint16_t count = read_u161e(p, 2);
    const uint8_t *arr = abs_ptr(list_abs_offset + 4, (uint32_t)count * 8);
    if (!arr) {
        print_indent(depth);
        fprintf(stderr, "[!] %s list at abs 0x%X out of bounds \n",
                is_lf ? "lf" : "lh", list_abs_offset);
        return;
    }

    for (uint16_t i = 0; i < count; i++) {
        uint32_t nk_rel = read_u321e(arr, i * 8); /* each entry is 8 bytes: offset + hash */
        uint32_t nk_abs = rel_to_abs(nk_rel);

        regf_key_t key;
        if (parse_nk(nk_abs, &key) != 0) {
            print_indent(depth);
            fprintf(stderr, "[!] failed to parse subkey #%u\n", i);
            continue;
        }
        print_indent(depth);
        printf("[%s] (subkeys=%u, values=%u)\n", key.name, key.subkey_count, key.value_count);

        if (key.value_count > 0 && key.value_list_offset != 0xFFFFFFFF) {
            walk_values(rel_to_abs(key.value_list_offset), key.value_count, depth + 1);
        }

        if (key.subkey_count > 0 && key.subkey_list_offset != 0xFFFFFFFF) {
            walk_subkeys(rel_to_abs(key.subkey_list_offset), depth + 1);
        }
    }
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

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size < REGF_HEADER_SIZE) {
        fprintf(stderr, "File too small\n");
        fclose(fp);
        return 1;
    }
    uint8_t header[REGF_HEADER_SIZE];
    if (fread(header, 1, REGF_HEADER_SIZE, fp) != REGF_HEADER_SIZE) {
        fprintf(stderr, "Failed to read header\n");
        fclose(fp);
        return 1;
    }
    if (memcmp(header, "regf", 4) != 0) {
        fprintf(stderr, "Not a valid REGF hive\n");
        fclose(fp);
        return 1;
    }

    uint32_t root_cell_rel = read_u321e(header, 36); /* from regf_header.c */

    long hbins_size = file_size - REGF_HEADER_SIZE;
    g_hbins_data = malloc((size_t)hbins_size);
    if (!g_hbins_data) {
        fprintf(stderr, "malloc failed\n");
        fclose(fp);
        return 1;
    }
    if (fread(g_hbins_data, 1, (size_t)hbins_size, fp) != (size_t)hbins_size) {
        fprintf(stderr, "Short read on hbins data\n");
        free(g_hbins_data);
        fclose(fp);
        return 1;
    }
    fclose(fp);
    g_hbins_data_size = (uint32_t)hbins_size;

    uint32_t root_abs = rel_to_abs(root_cell_rel);
    regf_key_t root;
    if (parse_nk(root_abs, &root) != 0) {
        fprintf(stderr, "Failed to parse root key at abs 0x%X\n", root_abs);
        free(g_hbins_data);
        return 1;
    }

    printf("ROOT: [%s]  (subkeys=%u, values=%u)\n", root.name, root.subkey_count, root.value_count);

    if (root.value_count > 0 && root.value_list_offset != 0xFFFFFFFF) {
        walk_values(rel_to_abs(root.value_list_offset), root.value_count, 1);
    }
    if (root.subkey_count > 0 && root.subkey_list_offset != 0xFFFFFFFF) {
        walk_subkeys(rel_to_abs(root.subkey_list_offset), 1);
    }

    free(g_hbins_data);
    return 0;
}