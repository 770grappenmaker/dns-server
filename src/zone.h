#ifndef ZONE_H_
#define ZONE_H_

#include "nob.h"
#include "packet.h"

#define DIRECTIVE_CHAR ('$')

typedef struct {
    rr *items;
    size_t count;
    size_t capacity;
} rrs;

typedef struct {
    rrs rrs;
    uint32_t ttl;
    strings origin;
    char * loaded_path;
} zonefile;

void reset_zonefile(zonefile *file);
int load_zonefile(zonefile *file, char * path);
void parse_name_str(strings *da, String_View name);

#endif