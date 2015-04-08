/*
 * Copyright (c) 2015 Justin Liu
 * Author: Justin Liu <rssnsj@gmail.com>
 * https://github.com/rssnsj/network-feeds
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <openssl/aes.h>
#include <openssl/md5.h>

#include "minivtun.h"

int run_client(int tunfd, const char *crypto_passwd, const char *peer_addr_pair)
{
	char tun_buffer[NM_PI_BUFFER_SIZE + 64], net_buffer[NM_PI_BUFFER_SIZE + 64];
	struct minivtun_msg *nmsg = (void *)net_buffer;
	struct tun_pi *pi = (void *)tun_buffer;
	AES_KEY encrypt_key, decrypt_key;
	time_t last_recv = 0, last_xmit = 0, current_ts;
	struct timeval timeo;
	size_t ip_dlen, ready_dlen;
	int sockfd, rc;
	struct sockaddr_in peer_addr;
	fd_set rset;
	char s1[20];

	if (v4pair_to_sockaddr(peer_addr_pair, ':', &peer_addr) < 0) {
		fprintf(stderr, "*** Cannot resolve address pair '%s'.\n", peer_addr_pair);
		return -1;
	}

	printf("Mini virtual tunnelling client to %s:%u.\n",
		ipv4_htos(ntohl(peer_addr.sin_addr.s_addr), s1), ntohs(peer_addr.sin_port));

	if (crypto_passwd) {
		gen_encrypt_key(&encrypt_key, crypto_passwd);
		gen_decrypt_key(&decrypt_key, crypto_passwd);
	} else {
		fprintf(stderr, "*** WARNING: Tunnel data will not be encrypted.\n");
	}

	/* The initial tunnelling connection. */
	if ((sockfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		fprintf(stderr, "*** socket() failed: %s.\n", strerror(errno));
		exit(1);
	}
	set_nonblock(sockfd);

	/* For triggering the first keep-alive packet to be sent. */
	last_recv = last_xmit = 0 /*time(NULL)*/;

	for (;;) {
		FD_ZERO(&rset);
		FD_SET(tunfd, &rset);
		FD_SET(sockfd, &rset);

		timeo.tv_sec = 1;
		timeo.tv_usec = 0;

		rc = select((tunfd > sockfd ? tunfd : sockfd) + 1, &rset, NULL, NULL, &timeo);
		if (rc < 0) {
			fprintf(stderr, "*** select(): %s.\n", strerror(errno));
			return -1;
		}

		/* Check connection state on each chance. */
		current_ts = time(NULL);
		if (last_recv > current_ts)
			last_recv = current_ts;
		if (last_xmit > current_ts)
			last_xmit = current_ts;

		/* Connection timed out, try reconnecting. */
		if (current_ts - last_recv > g_reconnect_timeo) {
			if (v4pair_to_sockaddr(peer_addr_pair, ':', &peer_addr) < 0) {
				fprintf(stderr, "*** Failed to resolve '%s'.\n", peer_addr_pair);
				continue;
			}
		}

		/* Packet receive timed out, send keep-alive packet. */
		if (current_ts - last_xmit > g_keepalive_timeo) {
			nmsg->hdr.opcode = MINIVTUN_MSG_NOOP;
			sendto(sockfd, nmsg, MINIVTUN_MSG_BASIC_HLEN, 0,
					(struct sockaddr *)&peer_addr, sizeof(peer_addr));
			last_xmit = current_ts;
		}

		/* No result from select(), do nothing. */
		if (rc == 0)
			continue;

		if (FD_ISSET(sockfd, &rset)) {
			struct sockaddr_in real_peer_addr;
			socklen_t real_peer_alen = sizeof(real_peer_addr);

			rc = recvfrom(sockfd, net_buffer, NM_PI_BUFFER_SIZE, 0,
					(struct sockaddr *)&real_peer_addr, &real_peer_alen);
			if (rc < 0 || rc < MINIVTUN_MSG_BASIC_HLEN)
				goto out1;

			/* FIXME: Verify password. */
			//
			//

			last_recv = current_ts;

			switch (nmsg->hdr.opcode) {
			case MINIVTUN_MSG_IPDATA:
				/* No packet is shorter than a 20-byte IPv4 header. */
				if (rc < MINIVTUN_MSG_IPDATA_OFFSET + 20)
					break;
				ip_dlen = ntohs(nmsg->ipdata.ip_dlen);
				pi->flags = 0;
				pi->proto = nmsg->ipdata.proto;
				ready_dlen = (size_t)rc - MINIVTUN_MSG_IPDATA_OFFSET;
				//if (g_crypto_passwd) {
				//	bytes_decrypt(pi + 1, nmsg->ipdata.data, &ready_dlen);
				//	/* Drop incomplete IP packets. */
				//	if (ready_dlen < ip_dlen)
				//		break;
				//} else {
					/* Drop incomplete IP packets. */
					if (ready_dlen < ip_dlen)
						break;
					memcpy(pi + 1, nmsg->ipdata.data, ip_dlen);
				//}
				rc = write(tunfd, pi, sizeof(struct tun_pi) + ip_dlen);
				break;
			case MINIVTUN_MSG_DISCONNECT:
				/* NOTICE: To instantly know connection closed in next loop. */
				last_recv = last_xmit = 0;
				break;
			}
			out1: ;
		}

		if (FD_ISSET(tunfd, &rset)) {
			rc = read(tunfd, tun_buffer, NM_PI_BUFFER_SIZE);
			if (rc < 0)
				break;

			switch (ntohs(pi->proto)) {
			case ETH_P_IP:
			case ETH_P_IPV6:
				ip_dlen = (size_t)rc - sizeof(struct tun_pi);
				nmsg->hdr.opcode = MINIVTUN_MSG_IPDATA;
				nmsg->ipdata.proto = pi->proto;
				nmsg->ipdata.ip_dlen = htons(ip_dlen);
				//if (g_crypto_passwd) {
				//	ready_dlen = ip_dlen;
				//	bytes_encrypt(nmsg->ipdata.data, pi + 1, &ready_dlen);
				//} else {
					memcpy(nmsg->ipdata.data, pi + 1, ip_dlen);
					ready_dlen = ip_dlen;
				//}
				/* Server sends to peer after it has learned client address. */
				rc = sendto(sockfd, net_buffer, MINIVTUN_MSG_IPDATA_OFFSET + ready_dlen, 0,
						(struct sockaddr *)&peer_addr, sizeof(peer_addr));
				last_xmit = current_ts;
				break;
			}
		}
	}

	return 0;
}

