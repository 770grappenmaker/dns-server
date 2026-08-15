#include "resolver.h"
#include <arpa/inet.h>

#define MAX_CNAME_DEPTH 5

#define return_empty(code) { \
    answer a = { .answers = {0}, .additional = {0}, .rcode = code }; \
    return a; \
}

answer query(rrs *rrs_from, question q) {
    if (!rrs_has_domain(rrs_from, q.name)) {
        printf("NXDOMAIN\n");
        return_empty(RCODE_NXDOMAIN);
    }

    bool axfr = ntohs(q.footer.type) == 252;

    rrs answers = {0};
    rrs additional = {0};
    rrs_lookup(rrs_from, q, &answers);
    
    if (answers.count == 0) {
        printf("NO ANSWER\n");
        return_empty(RCODE_NOERROR);
    }
    
    if (!axfr) {
        // CNAME lowering
        rr last = answers.items[answers.count - 1];
        int depth = 0;
        
        while (ntohs(last.footer.type) == 5 && ++depth < MAX_CNAME_DEPTH) {
            int old_count = answers.count;
        
            question lower = q;
            lower.name = last.cname;
            
            rrs_lookup(rrs_from, lower, &answers);
            last = answers.items[answers.count - 1];
            
            if (old_count == answers.count) break;
        }
    
        // Additional section
        int checkpoint = answers.count;
        for (int i = 0; i < checkpoint; i++) {
            rr curr = answers.items[i];
            String_View rdata = curr.rdata;
            int skip_cnt = -1;
        
            // SRV record
            if (curr.footer.type == ntohs(33)) skip_cnt = 3;
        
            // MX record
            if (curr.footer.type == ntohs(15)) skip_cnt = 1;
        
            // not SRV or MX
            if (skip_cnt == -1) continue;
        
            sv_chop_left(&rdata, skip_cnt * 2);
        
            strings temp_da = {0};
            parse_name(&temp_da, &rdata);
        
            question_footer additional_q_ftr = { .clazz = q.footer.clazz, .type = htons(1) };
            question additional_q = { .name = temp_da, .footer = additional_q_ftr };
            rrs_lookup(rrs_from, additional_q, &additional);
            
            additional_q_ftr.type = ntohs(28);
            additional_q.footer = additional_q_ftr;
            rrs_lookup(rrs_from, additional_q, &additional);
        }
    }

    answer a = { .answers = answers, .additional = additional, .rcode = RCODE_NOERROR };
    printf("NOERROR (%lu answers, %lu additional)\n", answers.count, additional.count);
    return a;
}

bool is_wildcard_pattern(strings pattern) {
    return pattern.count > 0 && sv_eq(pattern.items[0], sv_from_cstr("*"));
}

bool name_match_wildcard(strings to_match, strings pattern) {
    if (is_wildcard_pattern(pattern)) return strings_eq_fromidx(to_match, pattern, 1);
    return strings_eq(to_match, pattern);
}

bool strings_endswith(strings to_match, strings suffix) {
    if (to_match.count < suffix.count) return false;

    for (size_t i = 0; i < suffix.count; i++) {
        size_t j = to_match.count - suffix.count + i;
        if (!sv_eq(to_match.items[j], suffix.items[i])) return false;
    }

    return true;
}

bool rrs_has_domain(rrs *rrs, strings name) {
    da_foreach(rr, curr, rrs) {
        if (name_match_wildcard(name, curr->name)) return true;
    }

    return false;
}

void rrs_lookup(rrs *rrs_from, question q, rrs *result) {
    // AXFR
    if (q.footer.type == htons(252)) {
        da_foreach(rr, curr, rrs_from) {
            if (!strings_endswith(curr->name, q.name)) continue;

            rr result_rr = *curr;
            strings dup = {0};
            strings_dup_shallow(&dup, curr->name);
            result_rr.name = dup;

            da_append(result, result_rr);
        }

        return;
    }

    int checkpoint = result->count;

    bool is_cnamable = ntohs(q.footer.type) == 1 || ntohs(q.footer.type) == 28;
    bool wildcard_allowed = true;

    da_foreach(rr, curr, rrs_from) {
        if (q.footer.clazz != curr->footer.clazz) continue;
        if (q.footer.type != curr->footer.type && !(is_cnamable && ntohs(curr->footer.type) == 5)) continue;
        if (!name_match_wildcard(q.name, curr->name)) continue;

        bool was_wildcard = is_wildcard_pattern(curr->name);
        if (!wildcard_allowed && was_wildcard) continue;

        if (!was_wildcard) {
            if (wildcard_allowed) result->count = checkpoint;
            wildcard_allowed = false;
        }

        rr result_rr = *curr;

        strings dup = {0};
        strings_dup_shallow(&dup, q.name);
        result_rr.name = dup;

        da_append(result, result_rr);
    }
}

void write_and_free_rr(String_Builder *dest, rr v) {
    write_rr(dest, v);
    da_free(v.name);
}