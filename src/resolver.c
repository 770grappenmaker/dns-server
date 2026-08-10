#include "resolver.h"
#include <arpa/inet.h>

#define TTL 3600

rr query(question q, String_Builder rdata_sb) {
    if (ntohs(q.footer.type) != 1) {
        rr nx = {0};
        return nx;
    }

    rr_footer response_ftr = {
        .clazz = q.footer.clazz,
        .type = q.footer.type,
        .ttl = htonl(TTL),
    };

    sb_append(&rdata_sb, 127);
    sb_append(&rdata_sb, 0);
    sb_append(&rdata_sb, 0);
    sb_append(&rdata_sb, 1);

    rr response_rr = {
        .name = q.name,
        .footer = response_ftr,
        .rdata = sb_to_sv(rdata_sb)
    };

    return response_rr;
}