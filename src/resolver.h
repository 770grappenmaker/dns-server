#ifndef RESOLVER_H_
#define RESOLVER_H_

#include "packet.h"

typedef struct {
    uint8_t rcode;
    rr rr;
} answer;

answer query(question q, String_Builder rdata_sb);

#endif