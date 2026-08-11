#include "resolver.h"
#include "zone.h"
#include <arpa/inet.h>

#define return_empty(code) { \
    answer a = { .rrs = {0}, .rcode = code }; \
    return a; \
}

answer query(question q, String_Builder rdata_sb) {
    if (!has_domain(q.name)) {
        printf("NXDOMAIN\n");
        return_empty(RCODE_NXDOMAIN);
    }

    rr *result = lookup_zonefile(q);
    if (result == NULL) {
        printf("NO ANSWER\n");
        return_empty(RCODE_NOERROR);
    }
    
    rrs da = {0};
    da_append(&da, *result);
    
    // CNAME lowering
    while (result != NULL && ntohs(result->footer.type) == 5) {
        strings name_da = {0};
        String_View rdata_cpy = result->rdata;
        parse_name(&name_da, &rdata_cpy);
        
        question lower = q;
        lower.name = name_da;
        result = lookup_zonefile(lower);
        da_free(name_da);
        
        if (result != NULL) da_append(&da, *result);
    }
    
    answer a = { .rrs = da, .rcode = RCODE_NOERROR };
    printf("NOERROR (%lu answers)\n", da.count);
    return a;
}