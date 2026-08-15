#include <string.h>

#include "handler.h"
#include "packet.h"
#include "standard_names.h"
#include "resolver.h"

#define MIN(x, y) (((x) < (y) ? (x) : (y)))

void connection_send(connection conn, char * buffer, ssize_t length) {
    if (conn.remote_addr_len != 0) {
        if (sendto(conn.sockfd, buffer, length, 0, conn.remote_addr, conn.remote_addr_len) == -1) {
            perror("sendto");
        }
    } else {
        size_t total = 0;
        while (total < length) {
            size_t sent = send(conn.sockfd, buffer + total, length - total, 0);
            if (sent == -1) {
                perror("send");
                return;
            }

            total += sent;
        }
    }
}

void handle_packet(rrs *rrs_from, connection conn, char * buffer, ssize_t length, bool tcp) {
    // Initial header parsing and checks
    String_View sv = nob_sv_from_parts(buffer, length);
    
    dns_header hdr = {0};
    if (sv.count < sizeof(hdr)) return;
    
    memcpy(&hdr, buffer, sizeof(hdr));
    sv_chop_left(&sv, sizeof(hdr));
    
    uint16_t flags = ntohs(hdr.flags);
    int opcode = (flags >> 11) & 0xf;
    int qr = flags >> 15;
    int rd = (flags >> 8) & 1;
    
    if (qr != 0) return; // do not even reply, waste of time, very bad remote
    
    // read question counts, quit early if it is too big
    uint16_t qcnt = ntohs(hdr.questions_cnt);
    uint16_t acnt = ntohs(hdr.additional_cnt);
    if (opcode != 0 || hdr.answers_cnt != 0 || hdr.authority_cnt != 0 || qcnt > 5) {
        dns_header resp_header = {
            .tid = hdr.tid,
            .flags = htons(0b1000000000000001 | (rd << 8)),
            0
        };
        
        memcpy(buffer, &resp_header, sizeof(resp_header));
        connection_send(conn, buffer, sizeof(resp_header));
        return;
    }
    
    // organise responses into sections
    String_Builder answers_section = {0};
    String_Builder additional_section = {0};
    String_Builder questions_section = {0};
    String_Builder response = {0};
    
    uint8_t rcode = RCODE_NOERROR;
    uint16_t rcode_ext = RCODE_NOERROR;
    uint16_t answers_cnt = 0;
    uint16_t additional_cnt = 0;

    for (int i = 0; i < qcnt; i++) {
        // read questions
        strings name = {0};
        if (parse_name(&name, &sv)) {
            sb_free(name);
            goto free_end; // very broken remote, don't waste our efforts
        }
        
        question_footer ftr;
        if (sv.count < sizeof(ftr)) {
            sb_free(name);
            goto free_end;
        }

        String_View ftr_sv = sv_chop_left(&sv, sizeof(ftr));
        memcpy(&ftr, ftr_sv.data, sizeof(ftr));
        
        question q = {
            .name = name,
            .footer = ftr
        };

        // echo back question (why is this spec)
        write_question(&questions_section, q);
        
        String_Builder sb = {0};
        sprint_name(&sb, &name);

        // log the request being made for debugging
        String_View name_sv = sb_to_sv(sb);
        uint16_t clazz = ntohs(ftr.clazz);
        uint16_t type = ntohs(ftr.type);
        printf("? " SV_Fmt " %s %s ", SV_Arg(name_sv), clazz_to_name(clazz), type_to_name(type));

        sb.count = 0;

        // ask the resolver for the result
        answer a = query(rrs_from, q);

        // if successful, write result
        if (a.rcode != RCODE_NOERROR) {
            rcode = a.rcode;
            rcode_ext = a.rcode;
        } else {
            answers_cnt += a.answers.count;
            additional_cnt += a.additional.count;
            da_foreach(rr, curr, &a.answers) write_and_free_rr(&answers_section, *curr);
            da_foreach(rr, curr, &a.additional) write_and_free_rr(&additional_section, *curr);
            da_free(a.answers);
            da_free(a.additional);
        }

        sb_free(sb);
        da_free(name);
    }

    // handle additional section / EDNS(0)
    bool seen_edns = false;
    uint16_t mtu = 512;

    for (int i = 0; i < acnt; i++) {
        // basic header checks
        strings name = {0};
        if (parse_name(&name, &sv)) {
            sb_free(name);
            goto free_end; // very broken remote, don't waste our efforts
        }
        
        rr_footer ftr;
        if (sv.count < sizeof(ftr) + 2) {
            sb_free(name);
            goto free_end;
        }

        // read rr
        String_View ftr_sv = sv_chop_left(&sv, sizeof(ftr));
        memcpy(&ftr, ftr_sv.data, sizeof(ftr));

        uint16_t rdlen = 0;
        memcpy(&rdlen, sv.data, 2);
        rdlen = ntohs(rdlen);
        sv_chop_left(&sv, 2);

        if (sv.count < rdlen) {
            sb_free(name);
            goto free_end;
        }

        String_View rdata = sv_chop_left(&sv, rdlen);

        // if not EDNS, stop
        if (ftr.type != htons(41)) continue;
        
        // if duplicate OPT/EDNS or not root name RR, quit early
        if (seen_edns || name.count > 0) {
            // FORMERR
            dns_header resp_header = {
                .tid = hdr.tid,
                .flags = htons(0b1000000000000001 | (rd << 8)),
                0
            };

            memcpy(buffer, &resp_header, sizeof(resp_header));
            connection_send(conn, buffer, sizeof(resp_header));

            sb_free(name);
            goto free_end;
        }

        seen_edns = true;
        sb_free(name);

        // parse EDNS header
        uint32_t ttl = ntohl(ftr.ttl);
        uint32_t xrcode = (ttl >> 24) & 0xff;
        uint32_t version = (ttl >> 16) & 0xff;

        // version check
        if (version != 0) rcode_ext = RCODE_BADVERS;
        mtu = MIN(ntohs(ftr.clazz), 1232);

        // read options
        while (rdata.count > 0) {
            edns_option_hdr opt_hdr;
            if (rdata.count < sizeof(opt_hdr)) {
                rcode_ext = RCODE_FORMERR;
                break;
            }

            memcpy(&opt_hdr, rdata.items, sizeof(opt_hdr));
            sv_chop_left(&rdata, sizeof(opt_hdr));
            uint16_t opt_len = ntohs(opt_hdr.length);

            if (rdata.count < opt_len) {
                rcode_ext = RCODE_FORMERR;
                break;
            }

            String_View opt_dat = sv_chop_left(&rdata, opt_len);
            switch (ntohs(opt_hdr.code)) {
            }
        }

        // compose response
        rr edns_resp = {
            .name = {0},
            .footer = {
                .clazz = htons(mtu),
                .ttl = (((rcode_ext >> 4) & 0xf) << 24),
                .type = htons(41)
            },
            .rdata = {0}
        };
        
        additional_cnt++;
        write_rr(&additional_section, edns_resp);
    }

    // build final response
    dns_header resp_header = {
        .tid = hdr.tid,
        .flags = htons(0b1000010000000000 | ((seen_edns ? rcode_ext : rcode) & 0xf) | (rd << 8)),
        0
    };

    response.count += sizeof(resp_header) + (tcp ? 2 : 0);

    // truncation handling while writing sections
    // TODO: individual RRS and TCP
    #define RESP_OR_TRUNCATE(sv, block) { \
        if (!tcp && response.count + sv.count >= mtu) { \
            resp_header.flags |= htons(1 << 9); \
        } else { \
            sb_append_sv(&response, (sv)); \
            {block;}; \
        } \
    }

    RESP_OR_TRUNCATE(sb_to_sv(questions_section), resp_header.questions_cnt = hdr.questions_cnt);
    RESP_OR_TRUNCATE(sb_to_sv(answers_section), resp_header.answers_cnt = htons(answers_cnt));
    RESP_OR_TRUNCATE(sb_to_sv(additional_section), resp_header.additional_cnt = htons(additional_cnt));

    // copy header into response
    memcpy(response.items + (tcp ? 2 : 0), &resp_header, sizeof(resp_header));

    // copy size into response if tcp and send
    if (tcp) {
        uint16_t len = response.count - 2;
        len = htons(len);
        memcpy(response.items, &len, 2);
    }

    connection_send(conn, response.items, response.count);

    if (sv.count > 0) {
        fprintf(stderr, "Warning: %lu dangling bytes left unread, even with successful response, this should never happen...\n", sv.count);
    }

    free_end:
    sb_free(response);
    sb_free(answers_section);
    sb_free(questions_section);
    sb_free(additional_section);
}