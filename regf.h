// Hunter Prescott
// 6/18/26

/* regf.h
 * Shared structures and constants for the registry hive parser.
 */

#ifndef REGF_H
#define REGF_H

#include <stdint.h>

#define REGF_HEADER_SIZE 4096

/* --- Value data types (from the 'vk' cell's type field) ---
 * These match the standard Windows registry value types */
#define REG_NONE_T              0
#define REG_SZ_T                1
#define REG_EXPAND_SZ_T         2
#define REG_BINARY_T            3
#define REG_DWORD_T             4
#define REG_DWORD_BIG_ENDIAN_T  5
#define REG_LINK_T              6
#define REG_MULTI_SZ_T          7
#define REG_QWORD_T             11

/* A parsed key node ('nk' cell) */
typedef struct regf_key {
    char     name[256];         /* key name, converted to plain ASCII/UTF-8 (best-effort) */
    uint64_t last_written;      /* raw FILETIME */
    uint32_t subkey_count;
    uint32_t subkey_list_offset;   /* relative offset, 0xFFFFFFFF if none */
    uint32_t value_count;
    uint32_t value_list_offset;    /* relative offset, 0xFFFFFFFF if none */
    uint32_t abs_offset;           /* absolute file offset of this nk cell, for reference */
} regf_key_t;

/* A parsed value node ('vk' cell) */
typedef struct regf_value {
    char     name[256];         /* "(default)" if unnamed */
    uint32_t data_type;
    uint32_t data_size;
    uint32_t data_offset;       /* relative offset to data, meaningful only if not inline */
    int      inline_data;       /* 1 if data is stored directly in the size/offset field */
    uint8_t inline_bytes[4];    /* raw bytes when inline_data is set */
    uint32_t abs_offset;
} regf_value_t;

#endif /* REGF_H */