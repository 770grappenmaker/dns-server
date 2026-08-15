#ifndef RESOLVER_H_
#define RESOLVER_H_

#include "packet.h"
#include "zone.h"

typedef struct {
    uint8_t rcode;
    rrs answers;
    rrs additional;
    rrs authority;
} answer;

answer query(rrs *rrs, question q);

bool rrs_has_domain(rrs *rrs, strings name);
void rrs_lookup(rrs *rrs_from, question q, rrs *result);

void write_and_free_rr(String_Builder *dest, rr v);

#endif