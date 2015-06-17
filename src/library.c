/*
 * Copyright (c) 2015 Justin Liu
 * Author: Justin Liu <rssnsj@gmail.com>
 * https://github.com/rssnsj/minivtun
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include "library.h"

int v4pair_to_sockaddr(const char *pair, char sep, struct sockaddr_in *addr)
{
	char host[64], *portp;
	struct addrinfo hints, *result;
	int rc;

	/* Only getting an INADDR_ANY address. */
	if (pair == NULL) {
		addr->sin_family = AF_INET;
		addr->sin_addr.s_addr = 0;
		addr->sin_port = 0;
		return 0;
	}

	strncpy(host, pair, sizeof(host));
	host[sizeof(host) - 1] = '\0';

	if (!(portp = strchr(host, sep)))
		return -EINVAL;
	*(portp++) = '\0';

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;  /* For wildcard IP address */
	hints.ai_protocol = 0;        /* Any protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;
	if ((rc = getaddrinfo(host, portp, &hints, &result)))
		return -EINVAL;

	/* Get the first resolution. */
	*addr = *(struct sockaddr_in *)result->ai_addr;
	freeaddrinfo(result);
	return 0;
}

int do_daemonize(void)
{
	pid_t pid;

	if ((pid = fork()) < 0) {
		fprintf(stderr, "*** fork() error: %s.\n", strerror(errno));
		return -1;
	} else if (pid > 0) {
		/* In parent process */
		exit(0);
	} else {
		/* In child process */
		int fd;
		setsid();
		chdir("/tmp");
		if ((fd = open("/dev/null", O_RDWR)) >= 0) {
			dup2(fd, 0);
			dup2(fd, 1);
			dup2(fd, 2);
			if (fd > 2)
				close(fd);
		}
	}
	return 0;
}


