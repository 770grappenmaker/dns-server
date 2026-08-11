#ifndef HANDLER_H_
#define HANDLER_H_

#include <arpa/inet.h>
#include "packet.h"
#include "zone.h"

#define MAX_NAME_PARTS 100

typedef struct {
    int sockfd;
    struct sockaddr *remote_addr;
    socklen_t remote_addr_len;
} connection;

void connection_send(connection conn, char * buffer, size_t length);
void handle_packet(zonefile *zf, connection conn, char * buffer, size_t length);

#endif