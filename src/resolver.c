#include "resolver.h"
#include "zone.h"
#include <arpa/inet.h>

answer query(question q, String_Builder rdata_sb) {
    rr *result = lookup_zonefile(q);
    if (result == NULL) {
        rr nx = {0};
        printf("NXDOMAIN\n");

        answer a = { .rr = nx, .rcode = RCODE_NXDOMAIN };
        return a;
    }

    if (ntohs(q.footer.type) != 1) {
        rr nx = {0};
        printf("NO ANSWER\n");

        answer a = { .rr = nx, .rcode = RCODE_NOERROR };
        return a;
    }

    struct in_addr resolved = { .s_addr = *((uint32_t *)result->rdata.data) };
    char str_rep[16];
    inet_ntop(AF_INET, &resolved, str_rep, sizeof(str_rep));
    printf("%s\n", str_rep);

    answer a = { .rr = *result, .rcode = RCODE_NOERROR };
    return a;
}