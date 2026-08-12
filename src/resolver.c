#include "resolver.h"
#include <arpa/inet.h>

#define MAX_CNAME_DEPTH 5

#define return_empty(code) { \
    answer a = { .rrs = {0}, .rcode = code }; \
    return a; \
}

answer query(rrs *rrs_from, question q, String_Builder rdata_sb) {
    if (!rrs_has_domain(rrs_from, q.name)) {
        printf("NXDOMAIN\n");
        return_empty(RCODE_NXDOMAIN);
    }

    rrs da = {0};
    rrs_lookup(rrs_from, q, &da);
    
    if (da.count == 0) {
        printf("NO ANSWER\n");
        return_empty(RCODE_NOERROR);
    }
    
    // CNAME lowering
    rr last = da.items[da.count - 1];
    int depth = 0;
    while (ntohs(last.footer.type) == 5 && ++depth < MAX_CNAME_DEPTH) {
        int old_count = da.count;

        question lower = q;
        lower.name = last.cname;
        
        rrs_lookup(rrs_from, lower, &da);
        last = da.items[da.count - 1];
        
        if (old_count == da.count) break;
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

void rrs_lookup(rrs *rrs_from, question q, rrs *result) {
    bool is_cnamable = htons(q.footer.type) == 1 || htons(q.footer.type) == 28;

    da_foreach(rr, curr, rrs_from) {
        if (q.footer.clazz != curr->footer.clazz) continue;
        if (q.footer.type != curr->footer.type && !(is_cnamable && htons(curr->footer.type) == 5)) continue;
        if (!name_match_wildcard(q.name, curr->name)) continue;

        rr copy = *curr;
        copy.name = q.name;
        da_append(result, copy);
    }
}