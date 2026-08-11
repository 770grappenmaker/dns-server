#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <signal.h>
#include <limits.h>

#include "handler.h"
#include "zone.h"

#define NOB_IMPLEMENTATION
#include <nob.h>

#define BACKLOG 100

extern char * optarg;
char * zonefile_path = NULL;

static zonefile global_zonefile = {
	.rrs = {0},
	.ttl = 3600
};

static void signal_handler(int sig) {
	fprintf(stderr, "Got SIGHUP, attempting to reload zonefile\n");
	if (zonefile_path == NULL) {
		fprintf(stderr, "Refusing to reload zone as there is no file loaded\n");
		return;
	}

	char resolved_path[4097];
	char *res = realpath(zonefile_path, resolved_path);

	if (res == NULL) {
		fprintf(stderr, "Path resolution of filename %s failed! Does it exist?\n", zonefile_path);
		perror("realpath");
		return;
	}
	
	fprintf(stderr, "Zonefile is at %s\n", resolved_path);
	reset_zonefile(&global_zonefile);
	
    if (load_zonefile(&global_zonefile, zonefile_path)) {
		fprintf(stderr, "Zonefile reload from %s failed!\n", resolved_path);
		perror("load_zonefile");
		return;
	}

	fprintf(stderr, "Zonefile reload from %s successful!\n", resolved_path);
	fprintf(stderr, "%lu records loaded\n", global_zonefile.rrs.count);
}

int main(int argc, char *argv[])
{
	int opt;
	char *host = "0.0.0.0";
	int port = 0;

	while ((opt = getopt(argc, argv, "h:p:z:")) != -1)
	{
		switch (opt)
		{
		case 'h':
			host = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'z':
			zonefile_path = strdup(optarg);

			if (load_zonefile(&global_zonefile, optarg)) {
				fprintf(stderr, "load_zonefile failed\n");
				return 1;
			}

			fprintf(stderr, "%lu records loaded\n", global_zonefile.rrs.count);

			break;
		default:
			fprintf(stderr, "Usage: %s [-h host] [-p port] [-z zonefile]\n",
					argv[0]);
			exit(1);
		}
	}

	struct in_addr addr;
	if (inet_pton(AF_INET, host, &addr) != 1) {
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

	signal(SIGHUP, signal_handler);
	fprintf(stderr, "Listening on %s:%d\n", host, ntohs(listen_addr.sin_port));

	int read_bytes;
	struct sockaddr_in remote_addr;
	socklen_t remote_addr_len = sizeof(remote_addr);

	char buffer[4096];

	for (;;) {
		remote_addr_len = sizeof(remote_addr);

		if ((read_bytes = recvfrom(sock_fd, buffer, sizeof(buffer), MSG_WAITALL, (struct sockaddr *) &remote_addr, &remote_addr_len)) == -1) {
			perror("recvfrom");
			continue;
		}

		if (read_bytes <= 0) continue;
		
		connection conn = {
			.sockfd = sock_fd,
			.remote_addr = (struct sockaddr *) &remote_addr,
			.remote_addr_len = remote_addr_len
		};
		
		handle_packet(&global_zonefile, conn, buffer, read_bytes);
	}

	return 1;
}
