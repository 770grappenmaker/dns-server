#include <stdio.h>
#include "zone.h"
#include "packet.h"
#include "standard_names.h"
#include <arpa/inet.h>

int parse_addr_str_A(String_Builder *rdata, String_View addr_str) {
    addr_str = sv_trim(addr_str);

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
    addr_str = sv_trim(addr_str);

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

int parse_addr_str_TXT(String_Builder *rdata, String_View addr_str) {
    while (addr_str.count > 0) {
        addr_str = sv_trim_left(addr_str);
        if (addr_str.count == 0) break;

        if (!sv_chop_prefix(&addr_str, sv_from_cstr("\""))) {
            fprintf(stderr, "TXT record must start with quote (\")\n");
            return 1;
        }

        String_View txt_content = sv_chop_by_delim(&addr_str, '"');

        if (txt_content.count >= 256) {
            fprintf(stderr, "TXT record part too long (must be at most 256 characters)\n");
            return 1;
        }

        sb_append(rdata, txt_content.count);
        sb_append_sv(rdata, txt_content);
    }

    return 0;
}

int parse_addr_str_CNAME(String_Builder *rdata, strings *cname, String_View addr_str) {
    addr_str = sv_trim(addr_str);
    parse_name_str(cname, addr_str);
    write_strings(rdata, cname);
    return 0;
}

int parse_addr_str_MX(String_Builder *rdata, String_View addr_str) {
    addr_str = sv_trim(addr_str);
    String_View prio_str = sv_chop_by_delim(&addr_str, ' ');

    String_Builder sb = {0};
    sb_append_sv(&sb, prio_str);
    sb_append_null(&sb);

    int prio = atoi(sb.items);
    sb_free(sb);

    if (prio <= 0 || prio >= UINT16_MAX) {
        fprintf(stderr, "Invalid MX record priority\n");
        return 1;
    } 

    write_short(rdata, prio);

    strings dest = {0};
    addr_str = sv_trim(addr_str);
    parse_name_str(&dest, addr_str);
    write_strings(rdata, &dest);

    da_free(dest);
    return 0;
}

int parse_addr_str(String_Builder *rdata, strings *cname, String_View addr_str, String_View type_str) {
    if (sv_eq(type_str, sv_from_cstr("A"))) return parse_addr_str_A(rdata, addr_str);
    if (sv_eq(type_str, sv_from_cstr("AAAA"))) return parse_addr_str_AAAA(rdata, addr_str);
    if (sv_eq(type_str, sv_from_cstr("TXT"))) return parse_addr_str_TXT(rdata, addr_str);
    if (sv_eq(type_str, sv_from_cstr("CNAME"))) return parse_addr_str_CNAME(rdata, cname, addr_str);
    if (sv_eq(type_str, sv_from_cstr("MX"))) return parse_addr_str_MX(rdata, addr_str);

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

int push_zonefile_line(zonefile *file, String_View line) {
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

    String_View addr_str = line;
    
    strings da = {0};
    parse_name_str(&da, name);
    da_append_da(&da, file->origin);

    String_Builder rdata = {0};
    strings cname = {0};

    if (parse_addr_str(&rdata, &cname, addr_str, type_str)) {
        fprintf(stderr, "Failed to parse address of record on line: " SV_Fmt "\n", SV_Arg(orig));
        return 1;
    }

    rr parsed_rr = {
        .name = da,
        .footer = {
            .clazz = htons(sv_to_clazz(clazz_str)),
            .type = htons(sv_to_type(type_str)),
            .ttl = htonl(file->ttl)
        },
        .rdata = sb_to_sv(rdata),
        .cname = cname
    };

    if (parsed_rr.footer.clazz == 0) {
        fprintf(stderr, "Failed to parse class of record on line: " SV_Fmt "\n", SV_Arg(orig));
        return 1;
    }

    if (parsed_rr.footer.type == 0) {
        fprintf(stderr, "Failed to parse type of record on line: " SV_Fmt "\n", SV_Arg(orig));
        return 1;
    }

    da_append(&file->rrs, parsed_rr);
    return 0;
}

int parse_comment_directive_TTL(zonefile *file, String_View rhs) {
    String_Builder sb = {0};
    sb_append_sv(&sb, rhs);
    sb_append_null(&sb);
    int res = atoi(sb.items);
    sb_free(sb);

    if (res <= 0 || res >= UINT16_MAX) {
        fprintf(stderr, "Invalid TTL: " SV_Fmt "\n", SV_Arg(rhs));
        return 1;
    }

    file->ttl = res;
    return 0;
}

int parse_comment_directive_ORIGIN(zonefile *file, String_View rhs) {
    file->origin.count = 0;
    parse_name_str(&file->origin, rhs);
    return 0;
}

int parse_comment_directive(zonefile *file, String_View comment) {
    comment = sv_trim(comment);
    if (comment.count <= 0 || comment.items[0] != DIRECTIVE_CHAR) return 0;
    
    sv_chop_left(&comment, 1);
    if (comment.count <= 0) {
        fprintf(stderr, "Directive start ($) but nothing to be seen afterwards...\n");
        return 1;
    }

    String_View name = sv_chop_by_delim(&comment, '=');
    name = sv_trim(name);
    comment = sv_trim(comment);

    if (sv_eq(name, sv_from_cstr("TTL"))) return parse_comment_directive_TTL(file, comment);
    if (sv_eq(name, sv_from_cstr("ORIGIN"))) return parse_comment_directive_ORIGIN(file, comment);

    fprintf(stderr, "Unsupported directive " SV_Fmt "\n", SV_Arg(name));
    return 1;
}

typedef struct {
    zonefile *file;
    String_Builder *content_buffer;
    String_Builder *comment_buffer;
    bool *is_comment;
    bool *is_quoted;
} zonefile_parser;

int push_zonefile(zonefile_parser parser, String_View *read) {
    while (read->count > 0) {
        char c = read->items[0];
        sv_chop_left(read, 1);

        if (c == ';' && !(*parser.is_quoted)) {
            *parser.is_comment = true;
            continue;
        }

        if (c == '"') *parser.is_quoted = !(*parser.is_quoted);

        if (c == '\n') {
            if (*parser.is_comment && parse_comment_directive(parser.file, sb_to_sv(*parser.comment_buffer))) {
                return 1;
            }

            *parser.is_comment = false;
            *parser.is_quoted = false;

            if (push_zonefile_line(parser.file, sb_to_sv(*parser.content_buffer))) {
                return 1;
            }

            String_Builder new_sb = {0};
            *parser.content_buffer = new_sb;

            String_Builder new_sb2 = {0};
            *parser.comment_buffer = new_sb2;

            continue;
        }

        sb_append(*parser.is_comment ? parser.comment_buffer : parser.content_buffer, c);
    }

    return 0;
}

void reset_zonefile(zonefile *file) {
    da_foreach(rr, curr, &file->rrs) {
        da_free(curr->name);
        da_free(curr->cname);
        free(curr->rdata.data);
    }
    
    file->rrs.count = 0;
    file->origin.count = 0;
}

int load_zonefile(zonefile *file, char * path) {
    FILE * fd = fopen(path, "r");
    if (fd == NULL) {
        perror("fopen");
        return -1;
    }

    char buffer[1024];
    size_t read_bytes;

    String_Builder content_buffer = {0};
    String_Builder comment_buffer = {0};
    bool is_comment = false;
    bool is_quoted = false;
    
    zonefile_parser parser = {
        .content_buffer = &content_buffer,
        .comment_buffer = &comment_buffer,
        .file = file,
        .is_comment = &is_comment,
        .is_quoted = &is_quoted
    };

    int err = 0;

    while ((read_bytes = fread(buffer, 1, sizeof(buffer), fd))) {
        if (ferror(fd)) {
            perror("fread");
            err = errno;
            goto freeing;
        }

        if (read_bytes <= 0) continue;

        String_View sv = sv_from_parts(buffer, read_bytes);
        if (push_zonefile(parser, &sv)) {
            err = -1;
            goto freeing;
        }

        if (feof(fd)) {
            String_View sv = sv_from_cstr("\n");
            if (push_zonefile(parser, &sv)) {
                err = -1;
                goto freeing;
            }

            break;
        }
    }

freeing:
    sb_free(content_buffer);
    sb_free(comment_buffer);

    if (fclose(fd) == EOF) {
        perror("fclose");
        return -1;
    }

    return err;
}