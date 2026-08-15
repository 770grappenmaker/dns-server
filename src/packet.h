#ifndef PACKET_H_
#define PACKET_H_

#include <stdint.h>
#include <nob.h>

#define RCODE_NOERROR 0
#define RCODE_FORMERR 1
#define RCODE_SERVFAIL 2
#define RCODE_NXDOMAIN 3
#define RCODE_BADVERS 16

typedef struct __attribute__((__packed__)) {
    uint16_t tid;
    uint16_t flags;
    uint16_t questions_cnt;
    uint16_t answers_cnt;
    uint16_t authority_cnt;
    uint16_t additional_cnt;
} dns_header;

typedef struct __attribute__((__packed__)) {
    uint16_t type;
    uint16_t clazz;
} question_footer;

typedef struct __attribute__((__packed__)) {
    uint16_t type;
    uint16_t clazz;
    uint32_t ttl;
} rr_footer;

typedef struct {
    String_View *items;
    size_t count;
    size_t capacity;
} strings;

typedef struct {
    strings name;
    rr_footer footer;
    String_View rdata;
    strings cname;
} rr;

typedef struct {
    strings name;
    question_footer footer;
} question;

typedef struct __attribute__((__packed__)) {
    uint16_t code;
    uint16_t length;
} edns_option_hdr;

void sprint_name(String_Builder *dest, strings *name);
int parse_name(strings *da, String_View *sv);

void write_strings(String_Builder *dest, strings *name);
void write_rr(String_Builder *dest, rr rr);
void write_question(String_Builder *dest, question q);
void write_short(String_Builder *dest, uint16_t value);
void write_long(String_Builder *dest, uint32_t value);

bool strings_eq(strings first, strings second);
bool strings_eq_fromidx(strings first, strings second, int start);

void strings_dup_shallow(strings *dst, strings src);

#endif