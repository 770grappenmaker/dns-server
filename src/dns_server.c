#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "handler.h"

#define NOB_IMPLEMENTATION
#include <nob.h>

#define BACKLOG 100

extern char * optarg;

int main(int argc, char *argv[])
{
	int opt;
	char *host = "0.0.0.0";
	int port = 0;

	while ((opt = getopt(argc, argv, "h:p:")) != -1)
	{
		switch (opt)
		{
		case 'h':
			host = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		default:
			fprintf(stderr, "Usage: %s [-h host] [-p port]\n",
					argv[0]);
			exit(1);
		}
	}

	struct in_addr addr;
	if (!inet_pton(AF_INET, host, &addr)) {
		perror("inet_pton");
		return 1;
	}

	if (port < 0) {
		fprintf(stderr, "Port is negative or invalid\n");
		return 1;
	}

	struct sockaddr_in listen_addr = {
		.sin_addr = addr,
		.sin_family = AF_INET,
		.sin_port = htons(port)
	};

	int local_addr_size = sizeof(listen_addr);

	int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock_fd < 0) {
		perror("socket");
		return 1;
	}

	if (bind(sock_fd, (struct sockaddr *) &listen_addr, local_addr_size) == -1) {
		perror("bind");
		return 1;
	}

	if (getsockname(sock_fd, (struct sockaddr *) &listen_addr, &local_addr_size) == -1) {
		perror("getsockname");
		return 1;
	}

	if (!listen(sock_fd, BACKLOG)) {
		perror("listen");
		return 1;
	}

	fprintf(stderr, "Listening on %s:%d\n", host, ntohs(listen_addr.sin_port));

	int read_bytes;
	struct sockaddr_in remote_addr;
	socklen_t remote_addr_len;

	char buffer[4096];

	while ((read_bytes = recvfrom(sock_fd, buffer, sizeof(buffer), MSG_WAITALL, (struct sockaddr *) &remote_addr, &remote_addr_len)) != -1) {
		if (read_bytes <= 0) continue;

		connection conn = {
			.sockfd = sock_fd,
			.remote_addr = (struct sockaddr *) &remote_addr,
			.remote_addr_len = remote_addr_len
		};

		handle_packet(conn, buffer, read_bytes);
	}

	perror("recvfrom");
	return 1;
}
