#include "acl.h"

#include <nob.h>
#include <stdio.h>
#include <unistd.h>

bool is_allowed(cidrs *allowlist, char *addr, size_t addr_len) {
    da_foreach(cidr *, c_ptr, allowlist) {
        cidr *c = *c_ptr;
        if (addr_len != c->addr_len) continue;
        
        uint8_t prefix = c->prefix_len;
        uint8_t prefix_bytes = prefix >> 3;
        uint8_t prefix_bits_rem = prefix & 0b111;
        
        bool match = true;
        for (int j = 0; j < prefix_bytes; j++) {
            if (c->addr[j] != addr[j]) {
                match = false;
                break;
            }
        }

        if (!match) continue;
        if (prefix_bits_rem == 0) return true;

        uint8_t mask = ((1 << prefix_bits_rem) - 1) << (8 - prefix_bits_rem);
        if ((c->addr[prefix_bytes] & mask) == (addr[prefix_bytes] & mask))
            return true;
    }

    return false;
}

int parse_prefix_len(cidr *dest, String_View cidr_part, int default_prefix) {
    if (cidr_part.count == 0) {
        dest->prefix_len = default_prefix;
        return 0;
    }

    String_Builder sb = {0};
    sb_append_sv(&sb, cidr_part);
    sb_append_null(&sb);

    int prefix = atoi(sb.items);
    sb_free(sb);

    if (prefix <= 0 || prefix > default_prefix) {
        fprintf(stderr, "Illegal prefix " SV_Fmt "\n", SV_Arg(cidr_part));
        return 1;
    }

    dest->prefix_len = prefix;
    return 0;
}

void cidr_free(cidr *c) {
    free(c->addr);
    free(c);
}

int load_acl_line(cidrs *dest, String_View line) {
    line = sv_trim(line);
    if (line.count == 0) return 0;

    String_View addr_str = sv_chop_by_delim(&line, '/');
    String_Builder addr_str_temp = {0};
    sb_append_sv(&addr_str_temp, addr_str);
    sb_append_null(&addr_str_temp);

    struct in_addr ipv4;
    struct in6_addr ipv6;
    int res = 0;

    if (inet_pton(AF_INET, addr_str_temp.items, &ipv4) == 1) {
        char *ptr = malloc(4);
        memcpy(ptr, &ipv4, 4);
        
        cidr *c = malloc(sizeof(cidr));
        c->addr = ptr;
        c->addr_len = 4;
        parse_prefix_len(c, line, 32);

        da_append(dest, c);
    } else if (inet_pton(AF_INET6, addr_str_temp.items, &ipv6) == 1) {
        char *ptr = malloc(16);
        memcpy(ptr, &ipv6, 16);

        cidr *c = malloc(sizeof(cidr));
        c->addr = ptr;
        c->addr_len = 16;
        parse_prefix_len(c, line, 128);

        da_append(dest, c);
    } else {
        res = 1;
        fprintf(stderr, "Failed to parse address part of CIDR: " SV_Fmt "\n",
                SV_Arg(addr_str));
    }

    sb_free(addr_str_temp);
    return res;
}

int load_acls(cidrs *dest, char *file_name) {
    FILE *fd = fopen(file_name, "r");
    if (fd == NULL) {
        perror("fopen");
        return 1;
    }
    
    String_Builder line_sb = {0};
    char buffer[4096];
    size_t read;
    
    int code = 0;
    
    while ((read = fread(buffer, 1, sizeof(buffer), fd))) {
        if (read <= 0) continue;

        for (int i = 0; i < read; i++) {
            char c = buffer[i];

            if (c == '\n') {
                if (load_acl_line(dest, sb_to_sv(line_sb))) {
                    code = 1;
                    goto freeing;
                }

                line_sb.count = 0;
                continue;
            }

            sb_append(&line_sb, c);
        }

        if (feof(fd)) {
            if (load_acl_line(dest, sb_to_sv(line_sb))) {
                code = 1;
                goto freeing;
            }
            break;
        }
    }

    if (ferror(fd)) {
        perror("fread");
        sb_free(line_sb);
        return 1;
    }

freeing:
    sb_free(line_sb);

    if (fclose(fd)) {
        perror("fclose");
        return 1;
    }

    return code;
}