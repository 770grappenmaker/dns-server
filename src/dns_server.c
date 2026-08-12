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
static zonefiles global_zonefiles = {0};
static rrs global_rrs = {0};

static void reload_zonefiles() {
	global_rrs.count = 0;
	
	char resolved_path[4097];
	da_foreach(zonefile, zf, &global_zonefiles) {
		if (zf->loaded_path == NULL) continue;
		
		char *res = realpath(zf->loaded_path, resolved_path);
		
		if (res == NULL) {
			fprintf(stderr, "Path resolution of filename %s failed! Does it exist?\n", zf->loaded_path);
			perror("realpath");
			return;
		}
		
		reset_zonefile(zf);
		
    	if (load_zonefile(zf, zf->loaded_path)) {
			fprintf(stderr, "Zonefile reload from %s failed!\n", resolved_path);
			return;
		}
		
		da_append_da(&global_rrs, zf->rrs);
		fprintf(stderr, "Zonefile reload from %s successful!\n", resolved_path);
		fprintf(stderr, "%lu records loaded\n", zf->rrs.count);
	}
}

static void signal_handler(int sig) {
	if (sig != SIGHUP) return;
	fprintf(stderr, "Got SIGHUP, attempting to reload zonefiles\n");
	reload_zonefiles();
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
			char * zonefile_path = strdup(optarg);
			zonefile zf = { .ttl = 3600, .loaded_path = zonefile_path };
			da_append(&global_zonefiles, zf);

			break;
		default:
			fprintf(stderr, "Usage: %s [-h host] [-p port] [-z zonefile]\n",
					argv[0]);
			exit(1);
		}
	}

	reload_zonefiles();

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
		
		handle_packet(&global_rrs, conn, buffer, read_bytes);
	}

	return 1;
}
