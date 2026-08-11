#include "resolver.h"
#include "zone.h"
#include <arpa/inet.h>

rr query(question q, String_Builder rdata_sb) {
    if (ntohs(q.footer.type) != 1) {
        rr nx = {0};
        return nx;
    }

    rr *result = lookup_zonefile(q);
    if (result == NULL) {
        rr nx = {0};
        printf("NXDOMAIN\n");
        return nx;
    }

    struct in_addr resolved = { .s_addr = htonl(*((uint32_t *)result->rdata.data)) };
    char str_rep[16];
    inet_ntop(AF_INET, &resolved, str_rep, sizeof(str_rep));
    printf("%s\n", str_rep);

    return *result;
}