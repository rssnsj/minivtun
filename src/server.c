/*
 * Copyright (c) 2015 Justin Liu
 * Author: Justin Liu <rssnsj@gmail.com>
 * https://github.com/rssnsj/network-feeds
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
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

#include "list.h"
#include "minivtun.h"

static AES_KEY encrypt_key, decrypt_key;
static time_t current_ts = 0;

struct tun_addr {
	unsigned short af;
	union {
		struct in_addr ip;
		struct in6_addr ip6;
	};
};

struct tun_client {
	struct list_head list;
	struct tun_addr virt_addr;
	struct sockaddr_in real_addr;
	time_t last_recv;
	time_t last_xmit;
};

#define ADDRMAP_HASH_SIZE (1 << 8)
static struct list_head addrmap_hbase[ADDRMAP_HASH_SIZE];
static size_t addrmap_len;

static inline void init_addrmap(void)
{
	int i;
	for (i = 0; i < ADDRMAP_HASH_SIZE; i++)
		INIT_LIST_HEAD(&addrmap_hbase[i]);
	addrmap_len = 0;
}

static inline unsigned int tun_addr_hash(const struct tun_addr *addr)
{
	if (addr->af == AF_INET) {
		return (unsigned int)addr->af + ntohl(addr->ip.s_addr);
	} else if (addr->af == AF_INET6) {
		return (unsigned int)addr->af +
			ntohl(addr->ip6.s6_addr32[0]) + ntohl(addr->ip6.s6_addr32[1]) +
			ntohl(addr->ip6.s6_addr32[2]) + ntohl(addr->ip6.s6_addr32[3]);
	} else {
		abort();
		return 0;
	}
}

static inline int tun_addr_comp(
		const struct tun_addr *a1, const struct tun_addr *a2)
{
	if (a1->af != a2->af)
		return 1;

	if (a1->af == AF_INET) {
		if (a1->ip.s_addr == a2->ip.s_addr) {
			return 0;
		} else {
			return 1;
		}
	} else if (a1->af == AF_INET6) {
		if (a1->ip6.s6_addr32[0] == a2->ip6.s6_addr32[0] &&
			a1->ip6.s6_addr32[1] == a2->ip6.s6_addr32[1] &&
			a1->ip6.s6_addr32[2] == a2->ip6.s6_addr32[2] &&
			a1->ip6.s6_addr32[3] == a2->ip6.s6_addr32[3]) {
			return 0;
		} else {
			return 1;
		}
	} else {
		abort();
		return 0;
	}
}

static struct tun_client *tun_client_try_get(const struct tun_addr *vaddr)
{
	struct list_head *chain = &addrmap_hbase[
		tun_addr_hash(vaddr) & (ADDRMAP_HASH_SIZE - 1)];
	struct tun_client *e;

	list_for_each_entry (e, chain, list) {
		if (tun_addr_comp(&e->virt_addr, vaddr) == 0)
			return e;
	}
	return NULL;
}

static struct tun_client *tun_client_get_or_create(
		const struct tun_addr *vaddr, const struct sockaddr_in *raddr)
{
	struct list_head *chain = &addrmap_hbase[
		tun_addr_hash(vaddr) & (ADDRMAP_HASH_SIZE - 1)];
	struct tun_client *e;

	list_for_each_entry (e, chain, list) {
		if (tun_addr_comp(&e->virt_addr, vaddr) == 0) {
			e->real_addr = *raddr;
			return e;
		}
	}

	/* Not found, always create new entry. */
	if ((e = malloc(sizeof(*e))) == NULL) {
		fprintf(stderr, "*** malloc(): %s.\n", strerror(errno));
		return NULL;
	}

	e->virt_addr = *vaddr;
	e->real_addr = *raddr;
	list_add_tail(&e->list, chain);
	addrmap_len++;

	return e;
}

static inline void tun_client_release(struct tun_client *ce)
{
	list_del(&ce->list);
	addrmap_len--;
}

static inline void source_addr_of_ipdata(
		const void *data, unsigned char af, struct tun_addr *addr)
{
	addr->af = af;
	switch (af) {
	case AF_INET:
		memcpy(&addr->ip, (char *)data + 12, 4);
		break;
	case AF_INET6:
		memcpy(&addr->ip6, (char *)data + 8, 16);
		break;
	default:
		abort();
	}
}

static inline void dest_addr_of_ipdata(
		const void *data, unsigned char af, struct tun_addr *addr)
{
	addr->af = af;
	switch (af) {
	case AF_INET:
		memcpy(&addr->ip, (char *)data + 16, 4);
		break;
	case AF_INET6:
		memcpy(&addr->ip6, (char *)data + 24, 16);
		break;
	default:
		abort();
	}
}


static int network_receiving(int tunfd, int sockfd)
{
	char tun_buffer[NM_PI_BUFFER_SIZE + 64], net_buffer[NM_PI_BUFFER_SIZE + 64];
	struct minivtun_msg *nmsg = (void *)net_buffer;
	struct tun_pi *pi = (void *)tun_buffer;
	size_t ip_dlen, ready_dlen;
	unsigned short af = 0;
	struct tun_addr virt_addr;
	struct tun_client *ce;
	int rc;

	struct sockaddr_in real_peer;
	socklen_t real_peer_alen = sizeof(real_peer);

	rc = recvfrom(sockfd, net_buffer, NM_PI_BUFFER_SIZE, 0,
			(struct sockaddr *)&real_peer, &real_peer_alen);
	if (rc < 0 || rc < MINIVTUN_MSG_BASIC_HLEN)
		return 0;

	/* FIXME: Verify password. */
	//
	//

	switch (nmsg->hdr.opcode) {
	case MINIVTUN_MSG_IPDATA:
		if (nmsg->ipdata.proto == htons(ETH_P_IP)) {
			af = AF_INET;
			/* No packet is shorter than a 20-byte IPv4 header. */
			if (rc < MINIVTUN_MSG_IPDATA_OFFSET + 20)
				return 0;
		} else if (nmsg->ipdata.proto == htons(ETH_P_IPV6)) {
			af = AF_INET6;
			if (rc < MINIVTUN_MSG_IPDATA_OFFSET + 40)
				return 0;
		} else {
			fprintf(stderr, "*** Invalid protocol: 0x%x.\n", ntohs(nmsg->ipdata.proto));
			return 0;
		}

		ip_dlen = ntohs(nmsg->ipdata.ip_dlen);
		ready_dlen = (size_t)rc - MINIVTUN_MSG_IPDATA_OFFSET;
		/* Drop incomplete IP packets. */
		if (ready_dlen < ip_dlen)
			return 0;

		source_addr_of_ipdata(nmsg->ipdata.data, af, &virt_addr);
		if ((ce = tun_client_get_or_create(&virt_addr, &real_peer)) == NULL)
			return 0;
		ce->last_recv = current_ts;

		pi->flags = 0;
		pi->proto = nmsg->ipdata.proto;
		memcpy(pi + 1, nmsg->ipdata.data, ip_dlen);

		rc = write(tunfd, pi, sizeof(struct tun_pi) + ip_dlen);
		break;
	}

	return 0;
}

static int tunnel_receiving(int tunfd, int sockfd)
{
	char tun_buffer[NM_PI_BUFFER_SIZE + 64], net_buffer[NM_PI_BUFFER_SIZE + 64];
	struct minivtun_msg *nmsg = (void *)net_buffer;
	struct tun_pi *pi = (void *)tun_buffer;
	size_t ip_dlen, ready_dlen;
	unsigned short af = 0;
	struct tun_addr virt_addr;
	struct tun_client *ce;
	int rc;

	rc = read(tunfd, tun_buffer, NM_PI_BUFFER_SIZE);
	if (rc < 0)
		return 0;

	switch (ntohs(pi->proto)) {
	case ETH_P_IP:
	case ETH_P_IPV6:
		ip_dlen = (size_t)rc - sizeof(struct tun_pi);
		memcpy(nmsg->ipdata.data, pi + 1, ip_dlen);
		ready_dlen = ip_dlen;

		if (pi->proto == htons(ETH_P_IP)) {
			af = AF_INET;
			if (ip_dlen < 20)
				return 0;
		} else if (pi->proto == htons(ETH_P_IPV6)) {
			af = AF_INET6;
			if (ip_dlen < 40)
				return 0;
		} else {
			fprintf(stderr, "*** Invalid protocol: 0x%x.\n", ntohs(pi->proto));
			return 0;
		}

		dest_addr_of_ipdata(nmsg->ipdata.data, af, &virt_addr);
		if ((ce = tun_client_try_get(&virt_addr)) == NULL)
			return 0;

		nmsg->hdr.opcode = MINIVTUN_MSG_IPDATA;
		nmsg->ipdata.proto = pi->proto;
		nmsg->ipdata.ip_dlen = htons(ip_dlen);
		rc = sendto(sockfd, net_buffer, MINIVTUN_MSG_IPDATA_OFFSET + ready_dlen, 0,
				(struct sockaddr *)&ce->real_addr, sizeof(ce->real_addr));
		ce->last_xmit = current_ts;
		break;
	}

	return 0;
}

int run_server(int tunfd, const char *crypto_passwd, const char *loc_addr_pair)
{
	struct timeval timeo;
	int sockfd, rc;
	struct sockaddr_in loc_addr;
	fd_set rset;
	char s1[20];

	if (v4pair_to_sockaddr(loc_addr_pair, ':', &loc_addr) < 0) {
		fprintf(stderr, "*** Cannot resolve address pair '%s'.\n", loc_addr_pair);
		return -1;
	}

	printf("Mini virtual tunnelling server on %s:%u, interface: %s.\n",
			ipv4_htos(ntohl(loc_addr.sin_addr.s_addr), s1), ntohs(loc_addr.sin_port),
			g_devname);

	if (crypto_passwd) {
		gen_encrypt_key(&encrypt_key, crypto_passwd);
		gen_decrypt_key(&decrypt_key, crypto_passwd);
	} else {
		fprintf(stderr, "*** WARNING: Tunnel data will not be encrypted.\n");
	}

	/* Initialize address map hash table. */
	init_addrmap();

	if ((sockfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		fprintf(stderr, "*** socket() failed: %s.\n", strerror(errno));
		exit(1);
	}
	if (bind(sockfd, (struct sockaddr *)&loc_addr, sizeof(loc_addr)) < 0) {
		fprintf(stderr, "*** bind() failed: %s.\n", strerror(errno));
		exit(1);
	}
	set_nonblock(sockfd);

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
