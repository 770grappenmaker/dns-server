#include "resolver.h"
#include "zone.h"
#include <arpa/inet.h>

#define return_empty(code) { \
    rr nx = {0}; \
    answer a = { .rr = nx, .rcode = code }; \
    return a; \
}

answer query(question q, String_Builder rdata_sb) {
    if (!has_domain(q.name)) {
        printf("NXDOMAIN\n");
        return_empty(RCODE_NOERROR);
    }

    rr *result = lookup_zonefile(q);
    if (result == NULL) {
        printf("NO ANSWER\n");
        return_empty(RCODE_NXDOMAIN);
    }
    
    printf("NOERROR\n");
    answer a = { .rr = *result, .rcode = RCODE_NOERROR };
    return a;
}