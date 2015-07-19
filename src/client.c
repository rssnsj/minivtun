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
#include <time.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "minivtun.h"
#include "list.h"

static struct timeval last_recv_tv = {0, 0}, last_keepalive_tv = {0, 0}, current_tv = {0, 0};
static struct sockaddr_in peer_addr;

/* Description of delayed transmitted packet. */
struct lfn_task_packet {
	struct list_head list;
	int dir;
	struct timeval recv_tv;
	struct sockaddr_in xmit_addr;
	size_t out_dlen;
	char out_data[1];
};
enum lfn_task_dir {
	LFN_TASK_TO_NETWORK,
	LFN_TASK_TO_TUNNEL,
};

static struct list_head lfn_task_queue;

static void lfn_task_enqueue(int dir, struct sockaddr_in *xmit_addr,
		const void *data1, size_t len1, const void *data2, size_t len2)
{
	struct lfn_task_packet *lt;

	if ((lt = malloc(sizeof(struct lfn_task_packet) + len1 + len2)) == NULL) {
		fprintf(stderr, "*** malloc() error: %s.\n", strerror(errno));
		return;
	}

	lt->list.prev = lt->list.next = NULL;
	lt->dir = dir;
	lt->recv_tv = current_tv;
	if (dir == LFN_TASK_TO_NETWORK) {
		lt->xmit_addr = *xmit_addr;
	} else {
		memset(&lt->xmit_addr, 0x0, sizeof(lt->xmit_addr));
	}
	lt->out_dlen = len1 + len2;
	if (len1)
		memcpy(lt->out_data, data1, len1);
	if (len2)
		memcpy(lt->out_data + len1, data2, len2);

	list_add_tail(&lt->list, &lfn_task_queue);
}
static inline int lfn_task_empty(void)
{
	return list_empty(&lfn_task_queue);
}
static inline struct lfn_task_packet *lfn_task_first(void)
{
	return list_first_entry(&lfn_task_queue, struct lfn_task_packet, list);
}
static inline void lfn_task_del(struct lfn_task_packet *lt)
{
	list_del(&lt->list);
	free(lt);
}

static int network_receiving(int tunfd, int sockfd)
{
	char read_buffer[NM_PI_BUFFER_SIZE], crypt_buffer[NM_PI_BUFFER_SIZE];
	struct minivtun_msg *nmsg;
	struct tun_pi pi;
	void *out_data;
	size_t ip_dlen, out_dlen;
	struct sockaddr_in real_peer;
	socklen_t real_peer_alen;
	//struct iovec iov[2];
	int rc;

	real_peer_alen = sizeof(real_peer);
	rc = recvfrom(sockfd, &read_buffer, NM_PI_BUFFER_SIZE, 0,
			(struct sockaddr *)&real_peer, &real_peer_alen);
	if (rc <= 0)
		return 0;

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

	last_recv_tv = current_tv;

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
		//iov[0].iov_base = &pi;
		//iov[0].iov_len = sizeof(pi);
		//iov[1].iov_base = (char *)nmsg + MINIVTUN_MSG_IPDATA_OFFSET;
		//iov[1].iov_len = ip_dlen;
		//rc = writev(tunfd, iov, 2);
		lfn_task_enqueue(LFN_TASK_TO_TUNNEL, NULL, &pi, sizeof(pi),
			(char *)nmsg + MINIVTUN_MSG_IPDATA_OFFSET, ip_dlen);
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
		return 0;

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

	//rc = sendto(sockfd, out_data, out_dlen, 0,
	//	(struct sockaddr *)&peer_addr, sizeof(peer_addr));
	lfn_task_enqueue(LFN_TASK_TO_NETWORK, &peer_addr,
		out_data, out_dlen, NULL, 0);

	/**
	 * NOTICE: Don't update this on each tunnel packet
	 * transmit. We always need to keep the local virtual IP
	 * (-a local/...) alive.
	 */
	/* last_keepalive_tv = current_tv; */

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

	rc = sendto(sockfd, out_msg, out_len, 0,
		(struct sockaddr *)&peer_addr, sizeof(peer_addr));

	/* Update 'last_keepalive_tv' only when it's really sent out. */
	if (rc > 0) {
		last_keepalive_tv = current_tv;
	}

	return rc;
}

int run_client(int tunfd, const char *peer_addr_pair)
{
	struct timeval timeo, __subres;
	int sockfd, rc;
	fd_set rset;
	char s_peer_addr[44];

	if ((rc = v4pair_to_sockaddr(peer_addr_pair, ':', &peer_addr)) == 0) {
		/* DNS resolve OK, start service normally. */
		gettimeofday(&last_recv_tv, NULL);
		inet_ntop(peer_addr.sin_family, &peer_addr.sin_addr,
			s_peer_addr, sizeof(s_peer_addr));
		printf("Mini virtual tunnelling client to %s:%u, interface: %s.\n",
			s_peer_addr, ntohs(peer_addr.sin_port), config.devname);
	} else if (rc == -EAGAIN && config.wait_dns) {
		/* Resolve later (last_recv = 0). */
		last_recv_tv.tv_sec = last_recv_tv.tv_usec = 0;
		printf("Mini virtual tunnelling client, interface: %s. \n", config.devname);
		printf("WARNING: DNS resolution of '%s' temporarily unavailable, "
			"resolving later.\n", peer_addr_pair);
	} else if (rc == -EINVAL) {
		fprintf(stderr, "*** Invalid address pair '%s'.\n", peer_addr_pair);
		return -1;
	} else {
		fprintf(stderr, "*** Cannot resolve address pair '%s'.\n", peer_addr_pair);
		return -1;
	}


	/* The initial tunnelling connection. */
	if ((sockfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		fprintf(stderr, "*** socket() failed: %s.\n", strerror(errno));
		exit(1);
	}
	set_nonblock(sockfd);

	/* =================================================== */
	/* Initialize the buffering queue. */
	INIT_LIST_HEAD(&lfn_task_queue);
	/* =================================================== */

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
	last_keepalive_tv.tv_sec = last_keepalive_tv.tv_usec = 0;

	for (;;) {
		FD_ZERO(&rset);
		FD_SET(tunfd, &rset);
		FD_SET(sockfd, &rset);

		timeo.tv_sec = 0;
		timeo.tv_usec = 2000;

		rc = select((tunfd > sockfd ? tunfd : sockfd) + 1, &rset, NULL, NULL, &timeo);
		if (rc < 0) {
			fprintf(stderr, "*** select(): %s.\n", strerror(errno));
			return -1;
		}

		gettimeofday(&current_tv, NULL);

		if (timercmp(&last_recv_tv, &current_tv, >))
			last_recv_tv = current_tv;
		if (timercmp(&last_keepalive_tv, &current_tv, >))
			last_keepalive_tv = current_tv;

		/* Packet transmission timed out, send keep-alive packet. */
		timersub(&current_tv, &last_keepalive_tv, &__subres);
		if (__subres.tv_sec >= config.keepalive_timeo) {
			peer_keepalive(sockfd);
		}

		/* Connection timed out, try reconnecting. */
		timersub(&current_tv, &last_recv_tv, &__subres);
		if (__subres.tv_sec >= config.reconnect_timeo) {
			while (v4pair_to_sockaddr(peer_addr_pair, ':', &peer_addr) < 0) {
				fprintf(stderr, "Failed to resolve '%s', retrying.\n",
					peer_addr_pair);
				sleep(5);
			}

			/* Reconnected OK. Reopen the socket for a different local port. */
			close(sockfd);
			if ((sockfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
				fprintf(stderr, "*** socket() failed: %s.\n", strerror(errno));
				exit(1);
			}

			last_keepalive_tv.tv_sec = last_keepalive_tv.tv_usec = 0;
			last_recv_tv = current_tv;

			inet_ntop(peer_addr.sin_family, &peer_addr.sin_addr,
				s_peer_addr, sizeof(s_peer_addr));
			printf("Reconnected to %s:%u.\n", s_peer_addr, ntohs(peer_addr.sin_port));
			continue;
		}

		/* =================================================== */
		/* Send backlog packets. */
		while (!lfn_task_empty()) {
			struct lfn_task_packet *lt = lfn_task_first();

			/* Only handle timed out packets. */
			timersub(&current_tv, &lt->recv_tv, &__subres);
			if (__subres.tv_sec * 1000 + __subres.tv_usec / 1000 <
				config.lfn_latency)
				break;

			switch (lt->dir) {
			case LFN_TASK_TO_NETWORK:
				sendto(sockfd, lt->out_data, lt->out_dlen, 0,
					(struct sockaddr *)&peer_addr, sizeof(peer_addr));
				break;
			case LFN_TASK_TO_TUNNEL:
				write(tunfd, lt->out_data, lt->out_dlen);
				break;
			}

			lfn_task_del(lt);
		}
		/* =================================================== */

		/* No result from select(), do nothing. */
		if (rc == 0)
			continue;

		if (FD_ISSET(sockfd, &rset)) {
			rc = network_receiving(tunfd, sockfd);
		}

		if (FD_ISSET(tunfd, &rset)) {
			rc = tunnel_receiving(tunfd, sockfd);
		}
	}

	return 0;
}

