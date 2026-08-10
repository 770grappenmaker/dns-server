#ifndef STANDARD_NAMES_H
#define STANDARD_NAMES_H

#include "stdint.h"

#define KNOWN_CLAZZ_NAMES_CNT 4
extern char * KNOWN_CLAZZ_NAMES[KNOWN_CLAZZ_NAMES_CNT];

char * clazz_to_name(uint16_t clazz_host_byte_order);

#define BASIC_TYPE_NAMES_CNT 16
extern char * BASIC_TYPE_NAMES[BASIC_TYPE_NAMES_CNT];
char * type_to_name(uint16_t type_host_byte_order);

#endif