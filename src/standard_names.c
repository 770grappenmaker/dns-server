#include "standard_names.h"
#include <string.h>

char * KNOWN_CLAZZ_NAMES[KNOWN_CLAZZ_NAMES_CNT] = {
    "IN",
    "CS",
    "CH",
    "HS"
};

char * clazz_to_name(uint16_t clazz_host_byte_order) {
    return clazz_host_byte_order - 1 < KNOWN_CLAZZ_NAMES_CNT ? KNOWN_CLAZZ_NAMES[clazz_host_byte_order - 1] : "??";
}

uint16_t sv_to_clazz(String_View sv) {
    for (int i = 0; i < KNOWN_CLAZZ_NAMES_CNT; i++) {
        if (sv_eq(sv, sv_from_cstr(KNOWN_CLAZZ_NAMES[i]))) return i + 1;
    }
    
    return 0;
}

uint16_t name_to_clazz(char *clazz) {
    return sv_to_clazz(sv_from_cstr(clazz));
}

char * BASIC_TYPE_NAMES[BASIC_TYPE_NAMES_CNT] = {
    "A",
    "NS",
    "MD",
    "MF",
    "CNAME",
    "SOA",
    "MB",
    "MG",
    "MR",
    "NULL",
    "WKS",
    "PTR",
    "HINFO",
    "MINFO",
    "MX",
    "TXT"
};

char * type_to_name(uint16_t type_host_byte_order) {
    if (type_host_byte_order - 1 < BASIC_TYPE_NAMES_CNT) return BASIC_TYPE_NAMES[type_host_byte_order - 1];
    if (type_host_byte_order == 28) return "AAAA";
    
    return "??"; 
}

uint16_t sv_to_type(String_View sv) {
    if (sv_eq(sv, sv_from_cstr("AAAA"))) return 28;

    for (int i = 0; i < BASIC_TYPE_NAMES_CNT; i++) {
        if (sv_eq(sv, sv_from_cstr(BASIC_TYPE_NAMES[i]))) return i + 1;
    }

    return 0;
}

uint16_t name_to_type(char *name) {
    return sv_to_type(sv_from_cstr(name));
}