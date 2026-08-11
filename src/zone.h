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
    uint16_t ttl;
} zonefile;

void reset_zonefile(zonefile *file);
int load_zonefile(zonefile *file, char * path);
bool zonefile_has_domain(zonefile *file, strings name);
rr *lookup_zonefile(zonefile *file, question q);

void parse_name_str(strings *da, String_View name);

#endif