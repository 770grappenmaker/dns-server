#ifndef ZONE_H_
#define ZONE_H_

#include "nob.h"
#include "packet.h"

typedef struct {
    rr *items;
    size_t count;
    size_t capacity;
} rrs;

int load_zonefile(char * path);
rr *lookup_zonefile(question q);

#endif