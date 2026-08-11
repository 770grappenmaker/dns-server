#ifndef RESOLVER_H_
#define RESOLVER_H_

#include "packet.h"
#include "zone.h"

typedef struct {
    uint8_t rcode;
    rrs rrs;
} answer;

answer query(question q, String_Builder rdata_sb);

#endif