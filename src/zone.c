#include <stdio.h>
#include "zone.h"
#include "packet.h"
#include <arpa/inet.h>

rrs loaded_rrs = {0};

void parse_name_str(strings *da, String_View name) {
    while (name.count > 0) {
        String_View part = sv_chop_by_delim(&name, '.');
        da_append(da, part);
    }
}

int push_zonefile_line(String_View line) {
    sv_chop_suffix(&line, sv_from_cstr("\n"));
    sv_chop_suffix(&line, sv_from_cstr("\r"));

    if (line.count <= 0) return 0;

    String_View orig = line;
    String_View name = sv_chop_by_delim(&line, ' ');
    line = sv_trim_left(line);

    if (line.count <= 0) {
        fprintf(stderr, "Warning: ignoring line '" SV_Fmt "': seems like no address or fully empty\n", SV_Arg(orig));
        return 0;
    }

    String_Builder sb = {0};
    sb_append_sv(&sb, line);
    sb_append_null(&sb);

    struct in_addr parsed;
    if (inet_pton(AF_INET, sb.items, &parsed) != 1) {
        sb_free(sb);
        perror("inet_pton");
        return 1;
    }

    sb_free(sb);

    strings da = {0};
    parse_name_str(&da, name);

    String_Builder rdata = {0};
    write_long(&rdata, ntohl(parsed.s_addr));

    rr parsed_rr = {
        .name = da,
        .footer = {
            .clazz = htons(1),
            .type = htons(1),
            .ttl = htonl(3600)
        },
        .rdata = sb_to_sv(rdata)
    };

    da_append(&loaded_rrs, parsed_rr);
    return 0;
}

int push_zonefile(String_Builder *sb, String_View *read) {
    while (read->count > 0) {
        char c = read->items[0];
        sv_chop_left(read, 1);

        if (c == '\n') {
            if (push_zonefile_line(sb_to_sv(*sb))) {
                return 1;
            }

            String_Builder new_sb = {0};
            *sb = new_sb;
            continue;
        }

        sb_append(sb, c);
    }

    return 0;
}

void reset_zonefile() {
    da_foreach(rr, curr, &loaded_rrs) {
        da_free(curr->name);
        free(curr->rdata.data);
    }

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

rr *lookup_zonefile(question q) {
    da_foreach(rr, curr, &loaded_rrs) {
        if (!strings_eq(q.name, curr->name)) continue;
        return curr;
    }

    return NULL;
}