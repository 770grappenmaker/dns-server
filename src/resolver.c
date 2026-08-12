#include "resolver.h"
#include <arpa/inet.h>

#define return_empty(code) { \
    answer a = { .rrs = {0}, .rcode = code }; \
    return a; \
}

answer query(rrs *rrs_from, question q, String_Builder rdata_sb) {
    if (!rrs_has_domain(rrs_from, q.name)) {
        printf("NXDOMAIN\n");
        return_empty(RCODE_NXDOMAIN);
    }

    rr *result = rrs_lookup(rrs_from, q);
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
        result = rrs_lookup(rrs_from, lower);
        da_free(name_da);
        
        if (result != NULL) da_append(&da, *result);
    }
    
    answer a = { .rrs = da, .rcode = RCODE_NOERROR };
    printf("NOERROR (%lu answers)\n", da.count);
    return a;
}

bool rrs_has_domain(rrs *rrs, strings name) {
    da_foreach(rr, curr, rrs) {
        if (strings_eq(name, curr->name)) return true;
    }

    return false;
}

rr *rrs_lookup(rrs *rrs, question q) {
    bool is_cnamable = htons(q.footer.type) == 1 || htons(q.footer.type) == 28;

    da_foreach(rr, curr, rrs) {
        if (q.footer.clazz != curr->footer.clazz) continue;
        if (q.footer.type != curr->footer.type && !(is_cnamable && htons(curr->footer.type) == 5)) continue;
        if (!strings_eq(q.name, curr->name)) continue;
        return curr;
    }

    return NULL;
}