#include <stdio.h>
#include "zone.h"
#include "packet.h"
#include "standard_names.h"
#include <arpa/inet.h>

rrs loaded_rrs = {0};

int parse_addr_str_A(String_Builder *rdata, String_View addr_str) {
    String_Builder sb = {0};
    sb_append_sv(&sb, addr_str);
    sb_append_null(&sb);

    struct in_addr parsed;
    if (inet_pton(AF_INET, sb.items, &parsed) != 1) {
        sb_free(sb);
        perror("while parsing zonefile address: inet_pton");
        return 1;
    }

    sb_free(sb);
    write_long(rdata, ntohl(parsed.s_addr));

    return 0;
}

int parse_addr_str_AAAA(String_Builder *rdata, String_View addr_str) {
    String_Builder sb = {0};
    sb_append_sv(&sb, addr_str);
    sb_append_null(&sb);
    
    struct in6_addr parsed;
    if (inet_pton(AF_INET6, sb.items, &parsed) != 1) {
        sb_free(sb);
        perror("while parsing zonefile address: inet_pton");
        return 1;
    }
    
    sb_free(sb);
    sb_append_buf(rdata, (void*) &parsed, sizeof(parsed));

    return 0;
}

int parse_addr_str(String_Builder *rdata, String_View addr_str, String_View type_str) {
    if (sv_eq(type_str, sv_from_cstr("A"))) return parse_addr_str_A(rdata, addr_str);
    if (sv_eq(type_str, sv_from_cstr("AAAA"))) return parse_addr_str_AAAA(rdata, addr_str);

    fprintf(stderr, "Unsupported type '" SV_Fmt "'\n", SV_Arg(type_str));
    return 1;
}

void parse_name_str(strings *da, String_View name) {
    while (name.count > 0) {
        String_View part = sv_chop_by_delim(&name, '.');
        da_append(da, part);
    }
}

#define print_empty(type) { \
    if (line.count <= 0) { \
        fprintf(stderr, "Warning: ignoring line '" SV_Fmt "': seems like no " type " present\n", SV_Arg(orig)); \
        return 0; \
    } \
}

bool zonefile_comment = false;

int push_zonefile_line(String_View line) {
    sv_chop_suffix(&line, sv_from_cstr("\n"));
    sv_chop_suffix(&line, sv_from_cstr("\r"));

    if (line.count <= 0) return 0;

    String_View orig = line;

    String_View name = sv_chop_by_delim(&line, ' ');
    line = sv_trim_left(line);
    print_empty("class (usually IN)");
    
    String_View clazz_str = sv_chop_by_delim(&line, ' ');
    line = sv_trim_left(line);
    print_empty("type (like A, AAAA, etc.)");
    
    String_View type_str = sv_chop_by_delim(&line, ' ');
    line = sv_trim_left(line);
    print_empty("address");

    String_View addr_str = sv_chop_by_delim(&line, ' ');
    
    strings da = {0};
    parse_name_str(&da, name);

    String_Builder rdata = {0};
    if (parse_addr_str(&rdata, addr_str, type_str)) {
        fprintf(stderr, "Failed to parse address of record on line: " SV_Fmt "\n", SV_Arg(orig));
        return 1;
    }

    rr parsed_rr = {
        .name = da,
        .footer = {
            .clazz = htons(sv_to_clazz(clazz_str)),
            .type = htons(sv_to_type(type_str)),
            .ttl = htonl(3600)
        },
        .rdata = sb_to_sv(rdata)
    };

    if (parsed_rr.footer.clazz == 0) {
        fprintf(stderr, "Failed to parse class of record on line: " SV_Fmt "\n", SV_Arg(orig));
        return 1;
    }

    if (parsed_rr.footer.type == 0) {
        fprintf(stderr, "Failed to parse type of record on line: " SV_Fmt "\n", SV_Arg(orig));
        return 1;
    }

    da_append(&loaded_rrs, parsed_rr);
    return 0;
}

int push_zonefile(String_Builder *sb, String_View *read) {
    while (read->count > 0) {
        char c = read->items[0];
        sv_chop_left(read, 1);

        if (c == ';') {
            zonefile_comment = true;
            continue;
        }

        if (c == '\n') {
            zonefile_comment = false;

            if (push_zonefile_line(sb_to_sv(*sb))) {
                return 1;
            }

            String_Builder new_sb = {0};
            *sb = new_sb;
            continue;
        }

        if (zonefile_comment) continue;
        sb_append(sb, c);
    }

    return 0;
}

void reset_zonefile() {
    da_foreach(rr, curr, &loaded_rrs) {
        da_free(curr->name);
        free(curr->rdata.data);
    }
    
    zonefile_comment = false;
    loaded_rrs.count = 0;
}

int load_zonefile(char * path) {
    FILE * fd = fopen(path, "r");
    if (fd == NULL) {
        perror("fopen");
        return -1;
    }

    char buffer[1024];
    size_t read_bytes;
    String_Builder sb = {0};

    int err = 0;

    while ((read_bytes = fread(buffer, 1, sizeof(buffer), fd))) {
        if (ferror(fd)) {
            perror("fread");
            err = errno;
            goto freeing;
        }

        if (read_bytes <= 0) continue;

        String_View sv = sv_from_parts(buffer, read_bytes);
        if (push_zonefile(&sb, &sv)) {
            err = -1;
            goto freeing;
        }

        if (feof(fd)) {
            String_View sv = sv_from_cstr("\n");
            if (push_zonefile(&sb, &sv)) {
                err = -1;
                goto freeing;
            }

            break;
        }
    }

freeing:
    sb_free(sb);
    if (fclose(fd) == EOF) {
        perror("fclose");
        return -1;
    }

    return err;
}

bool has_domain(strings name) {
    da_foreach(rr, curr, &loaded_rrs) {
        if (strings_eq(name, curr->name)) return true;
    }

    return false;
}

rr *lookup_zonefile(question q) {
    da_foreach(rr, curr, &loaded_rrs) {
        if (q.footer.clazz != curr->footer.clazz) continue;
        if (q.footer.type != curr->footer.type) continue;
        if (!strings_eq(q.name, curr->name)) continue;
        return curr;
    }

    return NULL;
}