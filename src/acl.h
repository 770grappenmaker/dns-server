#ifndef ACL_H_
#define ACL_H_

#include <arpa/inet.h>
#include <stdbool.h>

typedef struct {
    char *addr;
    size_t addr_len;
    uint8_t prefix_len;
} cidr;

typedef struct {
    cidr *items;
    size_t count;
    size_t capacity;
} cidrs;

int load_acls(cidrs *dest, char * file_name);
bool is_allowed(cidrs *allowlist, char *addr, size_t addr_len);
void cidr_free(cidr *c);

#endif