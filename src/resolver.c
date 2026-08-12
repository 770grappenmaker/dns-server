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

    rr result;
    
    if (rrs_lookup(rrs_from, q, &result)) {
        printf("NO ANSWER\n");
        return_empty(RCODE_NOERROR);
    }
    
    rrs da = {0};
    da_append(&da, result);
    
    // CNAME lowering
    while (ntohs(result.footer.type) == 5) {
        question lower = q;
        lower.name = result.cname;
        int res = rrs_lookup(rrs_from, lower, &result);
        
        if (res) break;
        da_append(&da, result);
    }
    
    answer a = { .rrs = da, .rcode = RCODE_NOERROR };
    printf("NOERROR (%lu answers)\n", da.count);
    return a;
}

bool name_match_wildcard(strings to_match, strings pattern) {
    if (pattern.count > 0 && sv_eq(pattern.items[0], sv_from_cstr("*"))) return strings_eq_fromidx(to_match, pattern, 1);
    return strings_eq(to_match, pattern);
}

bool rrs_has_domain(rrs *rrs, strings name) {
    da_foreach(rr, curr, rrs) {
        if (name_match_wildcard(name, curr->name)) return true;
    }

    return false;
}

int rrs_lookup(rrs *rrs, question q, rr *result) {
    bool is_cnamable = htons(q.footer.type) == 1 || htons(q.footer.type) == 28;

    da_foreach(rr, curr, rrs) {
        if (q.footer.clazz != curr->footer.clazz) continue;
        if (q.footer.type != curr->footer.type && !(is_cnamable && htons(curr->footer.type) == 5)) continue;
        if (!name_match_wildcard(q.name, curr->name)) continue;

        *result = *curr;
        result->name = q.name;
        return 0;
    }

    return 1;
}