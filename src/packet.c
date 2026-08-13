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

void write_question(String_Builder *dest, question v) {
    write_strings(dest, &v.name);
    
    char temp[sizeof(question_footer)];
    memcpy(&temp, &v.footer, sizeof(temp));
    sb_append_buf(dest, temp, sizeof(temp));
}

void write_short(String_Builder *dest, uint16_t value) {
    sb_append(dest, (value >> 8) & 0xff);
    sb_append(dest, value & 0xff);
}

void write_long(String_Builder *dest, uint32_t value) {
    sb_append(dest, (value >> 24) & 0xff);
    sb_append(dest, (value >> 16) & 0xff);
    sb_append(dest, (value >> 8) & 0xff);
    sb_append(dest, value & 0xff);
}

bool strings_eq(strings first, strings second) {
    if (first.count != second.count) return false;

    for (int i = 0; i < first.count; i++) {
        String_View fsv = first.items[i];
        String_View ssv = second.items[i];
        if (!sv_eq(fsv, ssv)) return false;
    }

    return true;
}

bool strings_eq_fromidx(strings first, strings second, int start) {
    if (first.count != second.count) return false;
    if (start >= first.count) return false;

    for (int i = start; i < first.count; i++) {
        String_View fsv = first.items[i];
        String_View ssv = second.items[i];
        if (!sv_eq(fsv, ssv)) return false;
    }

    return true;
}

void strings_dup_shallow(strings *dst, strings src) {
    da_foreach(String_View, curr, &src) da_append(dst, *curr);
}