#ifndef STANDARD_NAMES_H
#define STANDARD_NAMES_H

#include "stdint.h"
#include <nob.h>

#define KNOWN_CLAZZ_NAMES_CNT 4
extern char * KNOWN_CLAZZ_NAMES[KNOWN_CLAZZ_NAMES_CNT];

char * clazz_to_name(uint16_t clazz_host_byte_order);

#define BASIC_TYPE_NAMES_CNT 16
extern char * BASIC_TYPE_NAMES[BASIC_TYPE_NAMES_CNT];
char * type_to_name(uint16_t type_host_byte_order);

uint16_t name_to_clazz(char *clazz);
uint16_t name_to_type(char *name);

uint16_t sv_to_clazz(String_View sv);
uint16_t sv_to_type(String_View sv);

#endif