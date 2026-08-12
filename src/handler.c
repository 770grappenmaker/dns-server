#include <string.h>

#include "handler.h"
#include "packet.h"
#include "standard_names.h"
#include "resolver.h"

void connection_send(connection conn, char * buffer, size_t length) {
    if (sendto(conn.sockfd, buffer, length, 0, conn.remote_addr, conn.remote_addr_len) == -1) {
        perror("sendto");
    }
}

void handle_packet(rrs *rrs_from, connection conn, char * buffer, size_t length) {
    String_View sv = nob_sv_from_parts(buffer, length);

    dns_header hdr = {0};
    memcpy(&hdr, buffer, sizeof(hdr));
    sv_chop_left(&sv, sizeof(hdr));

    uint16_t flags = ntohs(hdr.flags);
    int opcode = (flags >> 11) & 0xf;
    int qr = flags >> 15;

    if (qr != 0) return; // do not even reply, waste of time, very bad remote

    uint16_t qcnt = ntohs(hdr.questions_cnt);
    if (opcode != 0 || hdr.answers_cnt != 0 || hdr.authority_cnt != 0 || qcnt > 5) {
        dns_header resp_header = {
            .tid = hdr.tid,
            .flags = htons(0b1000000000000001),
            0
        };

        memcpy(buffer, &resp_header, sizeof(resp_header));
        connection_send(conn, buffer, sizeof(resp_header));
        return;
    }

    String_Builder answers_section = {0};
    String_Builder questions_section = {0};
    uint8_t rcode = RCODE_NOERROR;
    uint16_t answers_cnt = 0;

    for (int i = 0; i < qcnt; i++) {
        strings name = {0};
        if (parse_name(&name, &sv)) {
            sb_free(name);
            goto free_end;
            return; // very broken remote, don't waste our efforts
        }
        
        question_footer ftr;
        String_View ftr_sv = sv_chop_left(&sv, sizeof(ftr));
        memcpy(&ftr, ftr_sv.data, sizeof(ftr));
        
        question q = {
            .name = name,
            .footer = ftr
        };

        write_question(&questions_section, q);
        
        String_Builder sb = {0};
        sprint_name(&sb, &name);

        String_View name_sv = sb_to_sv(sb);
        uint16_t clazz = ntohs(ftr.clazz);
        uint16_t type = ntohs(ftr.type);

        printf("? " SV_Fmt " %s %s ", SV_Arg(name_sv), clazz_to_name(clazz), type_to_name(type));

        sb.count = 0;
        answer a = query(rrs_from, q, sb);

        if (a.rcode != RCODE_NOERROR) {
            rcode = a.rcode;
        } else {
            answers_cnt += a.rrs.count;
            da_foreach(rr, curr, &a.rrs) write_rr(&answers_section, *curr);
            da_free(a.rrs);
        }

        sb_free(sb);
        da_free(name);
    }

    String_Builder response = {0};
    dns_header resp_header = {
        .tid = hdr.tid,
        .flags = htons(0b1000000000000000 | (rcode & 0xf)),
        .answers_cnt = htons(answers_cnt),
        .questions_cnt = hdr.questions_cnt
    };

    memcpy(buffer, &resp_header, sizeof(resp_header));
    sb_append_buf(&response, buffer, sizeof(resp_header));
    sb_append_sv(&response, sb_to_sv(questions_section));
    sb_append_sv(&response, sb_to_sv(answers_section));

    connection_send(conn, response.items, response.count);

    free_end:
    sb_free(response);
    sb_free(answers_section);
    sb_free(questions_section);
}