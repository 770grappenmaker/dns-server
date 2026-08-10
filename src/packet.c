#include "packet.h"
#include "handler.h"

int parse_name(strings *da, String_View *sv) {
    char label_len;

    while (sv->count > 0 && (label_len = sv->data[0]) != 0 && da->count <= MAX_NAME_PARTS) {
        sv_chop_left(sv, 1);
        if (label_len > sv->count) return -1;
        da_append(da, sv_chop_left(sv, label_len));
    }

    int res = sv->data[0] == 0 ? 0 : -1;
    if (sv->count > 0) sv_chop_left(sv, 1);
    return res;
}

void sprint_name(String_Builder *dest, strings *name) {
    da_foreach(String_View, sv, name) {
        sb_append_sv(dest, *sv);
        sb_append(dest, '.');
    }
}

void write_strings(String_Builder *dest, strings *name) {
    da_foreach(String_View, sv, name) {
        sb_append(dest, sv->count);
        sb_append_sv(dest, *sv);
    }

    sb_append(dest, 0);
}

void write_rr(String_Builder *dest, rr v) {
    write_strings(dest, &v.name);
    
    char temp[sizeof(rr_footer)];
    memcpy(&temp, &v.footer, sizeof(temp));
    sb_append_buf(dest, temp, sizeof(temp));
    write_short(dest, v.rdata.count);
    sb_append_sv(dest, v.rdata);
}

void write_short(String_Builder *dest, uint16_t value) {
    sb_append(dest, (value >> 8) & 0xff);
    sb_append(dest, value & 0xff);
}