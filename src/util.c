#include "util.h"

char parse_hex_digit(char c) {
    if (c >= 48 && c <= 57) return c - 48;
    if (c >= 97 && c <= 102) return c - 87;
    if (c >= 65 && c <= 70) return c - 55;

    return -1;
}

int parse_hex(String_Builder *dest, String_View source) {
    bool even = true;
    char so_far = 0;

    for (int i = 0; i < source.count; i++) {
        char c = source.items[i];
        if (isspace(c)) continue;

        char parsed = parse_hex_digit(c);
        if (parsed == -1) {
            fprintf(stderr, "Illegal hex string: " SV_Fmt "\n", SV_Arg(source));
            return 1;
        }

        even = !even;
        so_far = (so_far << 4) | parsed;

        if (even) {
            sb_append(dest, so_far);
            so_far = 0;
        }
    }

    if (!even) sb_append(dest, so_far);
    return 0;
}