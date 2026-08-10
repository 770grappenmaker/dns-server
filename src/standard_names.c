#include "standard_names.h"

char * KNOWN_CLAZZ_NAMES[KNOWN_CLAZZ_NAMES_CNT] = {
    "IN",
    "CS",
    "CH",
    "HS"
};

char * clazz_to_name(uint16_t clazz_host_byte_order) {
    return clazz_host_byte_order - 1 < KNOWN_CLAZZ_NAMES_CNT ? KNOWN_CLAZZ_NAMES[clazz_host_byte_order - 1] : "??";
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