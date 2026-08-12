#ifndef RESOLVER_H_
#define RESOLVER_H_

#include "packet.h"
#include "zone.h"

typedef struct {
    uint8_t rcode;
    rrs rrs;
} answer;

answer query(rrs *rrs, question q);

bool rrs_has_domain(rrs *rrs, strings name);
void rrs_lookup(rrs *rrs_from, question q, rrs *result);

#endif