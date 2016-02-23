/*
 * Copyright (c) 2015 Justin Liu
 * Author: Justin Liu <rssnsj@gmail.com>
 * https://github.com/rssnsj/minivtun
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "minivtun.h"

static time_t last_recv = 0, last_keepalive = 0, current_ts = 0;

static int network_receiving(int tunfd, int sockfd)
{
	char read_buffer[NM_PI_BUFFER_SIZE], crypt_buffer[NM_PI_BUFFER_SIZE];
	struct minivtun_msg *nmsg;
	struct tun_pi pi;
	void *out_data;
	size_t ip_dlen, out_dlen;
	struct sockaddr_in real_peer;
	socklen_t real_peer_alen;
	struct iovec iov[2];
	int rc;

	real_peer_alen = sizeof(real_peer);
	rc = recvfrom(sockfd, &read_buffer, NM_PI_BUFFER_SIZE, 0,
			(struct sockaddr *)&real_peer, &real_peer_alen);
	if (rc <= 0)
		return -1;

	out_data = crypt_buffer;
	out_dlen = (size_t)rc;
	netmsg_to_local(read_buffer, &out_data, &out_dlen);
	nmsg = out_data;

	if (out_dlen < MINIVTUN_MSG_BASIC_HLEN)
		return 0;

	/* Verify password. */
	if (memcmp(nmsg->hdr.auth_key, config.crypto_key, 
		sizeof(nmsg->hdr.auth_key)) != 0)
		return 0;

	last_recv = current_ts;

	switch (nmsg->hdr.opcode) {
	case MINIVTUN_MSG_KEEPALIVE:
		break;
	case MINIVTUN_MSG_IPDATA:
		if (nmsg->ipdata.proto == htons(ETH_P_IP)) {
			/* No packet is shorter than a 20-byte IPv4 header. */
			if (out_dlen < MINIVTUN_MSG_IPDATA_OFFSET + 20)
				return 0;
		} else if (nmsg->ipdata.proto == htons(ETH_P_IPV6)) {
			if (out_dlen < MINIVTUN_MSG_IPDATA_OFFSET + 40)
				return 0;
		} else {
			fprintf(stderr, "*** Invalid protocol: 0x%x.\n", ntohs(nmsg->ipdata.proto));
			return 0;
		}

		ip_dlen = ntohs(nmsg->ipdata.ip_dlen);
		/* Drop incomplete IP packets. */
		if (out_dlen - MINIVTUN_MSG_IPDATA_OFFSET < ip_dlen)
			return 0;

		pi.flags = 0;
		pi.proto = nmsg->ipdata.proto;
		osx_ether_to_af(&pi.proto);
		iov[0].iov_base = &pi;
		iov[0].iov_len = sizeof(pi);
		iov[1].iov_base = (char *)nmsg + MINIVTUN_MSG_IPDATA_OFFSET;
		iov[1].iov_len = ip_dlen;
		rc = writev(tunfd, iov, 2);
		break;
	}

	return 0;
}

static int tunnel_receiving(int tunfd, int sockfd)
{
	char read_buffer[NM_PI_BUFFER_SIZE], crypt_buffer[NM_PI_BUFFER_SIZE];
	struct tun_pi *pi = (void *)read_buffer;
	struct minivtun_msg nmsg;
	void *out_data;
	size_t ip_dlen, out_dlen;
	int rc;

	rc = read(tunfd, pi, NM_PI_BUFFER_SIZE);
	if (rc < sizeof(struct tun_pi))
		return -1;

	osx_af_to_ether(&pi->proto);

	ip_dlen = (size_t)rc - sizeof(struct tun_pi);

	/* We only accept IPv4 or IPv6 frames. */
	if (pi->proto == htons(ETH_P_IP)) {
		if (ip_dlen < 20)
			return 0;
	} else if (pi->proto == htons(ETH_P_IPV6)) {
		if (ip_dlen < 40)
			return 0;
	} else {
		fprintf(stderr, "*** Invalid protocol: 0x%x.\n", ntohs(pi->proto));
		return 0;
	}

	nmsg.hdr.opcode = MINIVTUN_MSG_IPDATA;
	memset(nmsg.hdr.rsv, 0x0, sizeof(nmsg.hdr.rsv));
	memcpy(nmsg.hdr.auth_key, config.crypto_key, sizeof(nmsg.hdr.auth_key));
	nmsg.ipdata.proto = pi->proto;
	nmsg.ipdata.ip_dlen = htons(ip_dlen);
	memcpy(nmsg.ipdata.data, pi + 1, ip_dlen);

	/* Do encryption. */
	out_data = crypt_buffer;
	out_dlen = MINIVTUN_MSG_IPDATA_OFFSET + ip_dlen;
	local_to_netmsg(&nmsg, &out_data, &out_dlen);

	rc = send(sockfd, out_data, out_dlen, 0);
	/**
	 * NOTICE: Don't update this on each tunnel packet
	 * transmit. We always need to keep the local virtual IP
	 * (-a local/...) alive.
	 */
	/* last_keepalive = current_ts; */

	return 0;
}

static int peer_keepalive(int sockfd)
{
	char in_data[64], crypt_buffer[64];
	struct minivtun_msg *nmsg = (struct minivtun_msg *)in_data;
	void *out_msg;
	size_t out_len;
	int rc;

	nmsg->hdr.opcode = MINIVTUN_MSG_KEEPALIVE;
	memset(nmsg->hdr.rsv, 0x0, sizeof(nmsg->hdr.rsv));
	memcpy(nmsg->hdr.auth_key, config.crypto_key, sizeof(nmsg->hdr.auth_key));
	nmsg->keepalive.loc_tun_in = config.local_tun_in;
	nmsg->keepalive.loc_tun_in6 = config.local_tun_in6;

	out_msg = crypt_buffer;
	out_len = MINIVTUN_MSG_BASIC_HLEN + sizeof(nmsg->keepalive);
	local_to_netmsg(nmsg, &out_msg, &out_len);

	rc = send(sockfd, out_msg, out_len, 0);

	/* Update 'last_keepalive' only when it's really sent out. */
	if (rc > 0) {
		last_keepalive = current_ts;
	}

	return rc;
}

static int try_resolve_and_connect(const char *peer_addr_pair,
		struct sockaddr_inx *peer_addr)
{
	int sockfd, rc;

	if ((rc = get_sockaddr_inx_pair(peer_addr_pair, peer_addr)) < 0)
		return rc;

	if ((sockfd = socket(peer_addr->sa.sa_family, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		fprintf(stderr, "*** socket() failed: %s.\n", strerror(errno));
		return -1;
	}
	if (connect(sockfd, (struct sockaddr *)peer_addr, sizeof_sockaddr(peer_addr)) < 0) {
		close(sockfd);
		return -EAGAIN;
	}
	set_nonblock(sockfd);

	return sockfd;
}

int run_client(int tunfd, const char *peer_addr_pair)
{
	struct timeval timeo;
	int sockfd = -1, rc;
	fd_set rset;
	char s_peer_addr[50];
	struct sockaddr_inx peer_addr;

	if ((sockfd = try_resolve_and_connect(peer_addr_pair, &peer_addr)) >= 0) {
		/* DNS resolve OK, start service normally. */
		last_recv = time(NULL);
		inet_ntop(peer_addr.sa.sa_family, addr_of_sockaddr(&peer_addr),
				  s_peer_addr, sizeof(s_peer_addr));
		printf("Mini virtual tunnelling client to %s:%u, interface: %s.\n",
				s_peer_addr, ntohs(port_of_sockaddr(&peer_addr)), config.devname);
	} else if (sockfd == -EAGAIN && config.wait_dns) {
		/* Resolve later (last_recv = 0). */
		last_recv = 0;
		printf("Mini virtual tunnelling client, interface: %s. \n", config.devname);
		printf("WARNING: Connection to '%s' temporarily unavailable, "
			   "to be tried later.\n", peer_addr_pair);
	} else if (sockfd == -EINVAL) {
		fprintf(stderr, "*** Invalid address pair '%s'.\n", peer_addr_pair);
		return -1;
	} else {
		fprintf(stderr, "*** Unable to connect to '%s'.\n", peer_addr_pair);
		return -1;
	}

	/* Run in background. */
	if (config.in_background)
		do_daemonize();

	if (config.pid_file) {
		FILE *fp;
		if ((fp = fopen(config.pid_file, "w"))) {
			fprintf(fp, "%d\n", (int)getpid());
			fclose(fp);
		}
	}

	/* For triggering the first keep-alive packet to be sent. */
	last_keepalive = 0;

	for (;;) {
		FD_ZERO(&rset);
		FD_SET(tunfd, &rset);
		if (sockfd >= 0)
			FD_SET(sockfd, &rset);

		timeo.tv_sec = 2;
		timeo.tv_usec = 0;

		rc = select((tunfd > sockfd ? tunfd : sockfd) + 1, &rset, NULL, NULL, &timeo);
		if (rc < 0) {
			fprintf(stderr, "*** select(): %s.\n", strerror(errno));
			return -1;
		}

		current_ts = time(NULL);
		if (last_recv > current_ts)
			last_recv = current_ts;
		if (last_keepalive > current_ts)
			last_keepalive = current_ts;

		/* Packet transmission timed out, send keep-alive packet. */
		if (current_ts - last_keepalive > config.keepalive_timeo) {
			if (sockfd >= 0)
				peer_keepalive(sockfd);
		}

		/* Connection timed out, try reconnecting. */
		if (current_ts - last_recv > config.reconnect_timeo) {
reconnect:
			/* Reopen the socket for a different local port. */
			if (sockfd >= 0)
				close(sockfd);
			do {
				if ((sockfd = try_resolve_and_connect(peer_addr_pair, &peer_addr)) < 0) {
					fprintf(stderr, "Unable to connect to '%s', retrying.\n", peer_addr_pair);
					sleep(5);
				}
			} while (sockfd < 0);

			last_keepalive = 0;
			last_recv = current_ts;

			inet_ntop(peer_addr.sa.sa_family, addr_of_sockaddr(&peer_addr), s_peer_addr,
					  sizeof(s_peer_addr));
			printf("Reconnected to %s:%u.\n", s_peer_addr, ntohs(port_of_sockaddr(&peer_addr)));
			continue;
		}

		/* No result from select(), do nothing. */
		if (rc == 0)
			continue;

		if (sockfd >= 0 && FD_ISSET(sockfd, &rset)) {
			rc = network_receiving(tunfd, sockfd);
			if (rc != 0) {
				fprintf(stderr, "Connection went bad. About to reconnect.\n");
				goto reconnect;
			}
		}

		if (FD_ISSET(tunfd, &rset)) {
			rc = tunnel_receiving(tunfd, sockfd);
			assert(rc == 0);
		}
	}

	return 0;
}

