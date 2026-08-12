#ifndef RESOLVER_H_
#define RESOLVER_H_

#include "packet.h"
#include "zone.h"

typedef struct {
    uint8_t rcode;
    rrs rrs;
} answer;

answer query(rrs *rrs, question q, String_Builder rdata_sb);

bool rrs_has_domain(rrs *rrs, strings name);
rr *rrs_lookup(rrs *rrs, question q);

#endif