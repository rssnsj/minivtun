/*
 * Copyright (c) 2015 Justin Liu
 * Author: Justin Liu <rssnsj@gmail.com>
 * https://github.com/rssnsj/minivtun
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "list.h"
#include "jhash.h"
#include "minivtun.h"

static time_t current_ts = 0;
static uint32_t hash_initval = 0;

struct ra_entry {
	struct list_head list;
	struct sockaddr_in real_addr;
	time_t last_recv;
	time_t last_xmit;
	int refs;
};

#define RA_SET_HASH_SIZE  (1 << 3)
#define RA_SET_LIMIT_EACH_WALK  (10)
static struct list_head ra_set_hbase[RA_SET_HASH_SIZE];
static unsigned ra_set_len;

static inline uint32_t real_addr_hash(const struct sockaddr_in *in)
{
	return jhash_2words(in->sin_family, in->sin_addr.s_addr, hash_initval);
}

static struct ra_entry *ra_get_or_create(const struct sockaddr_in *in)
{
	struct list_head *chain = &ra_set_hbase[
		real_addr_hash(in) & (RA_SET_HASH_SIZE - 1)];
	struct ra_entry *re;
	char s_real_addr[44];

	list_for_each_entry (re, chain, list) {
		if (re->real_addr.sin_family == in->sin_family &&
			re->real_addr.sin_addr.s_addr == in->sin_addr.s_addr &&
			re->real_addr.sin_port == in->sin_port) {
			re->refs++;
			return re;
		}
	}

	if ((re = malloc(sizeof(*re))) == NULL) {
		fprintf(stderr, "*** [%s] malloc(): %s.\n", __FUNCTION__,
				strerror(errno));
		return NULL;
	}

	re->real_addr = *in;
	re->refs = 1;
	list_add_tail(&re->list, chain);
	ra_set_len++;

	inet_ntop(re->real_addr.sin_family, &re->real_addr.sin_addr,
		s_real_addr, sizeof(s_real_addr));
	printf("New client [%s:%u]\n", s_real_addr, ntohs(re->real_addr.sin_port));

	return re;
}

static inline void ra_put_no_free(struct ra_entry *re)
{
	assert(re->refs > 0);
	re->refs--;
}

static inline void ra_entry_release(struct ra_entry *re)
{
	char s_real_addr[44];

	assert(re->refs == 0);
	list_del(&re->list);

	inet_ntop(re->real_addr.sin_family, &re->real_addr.sin_addr,
		s_real_addr, sizeof(s_real_addr));
	printf("Recycled client [%s:%u]\n", s_real_addr, ntohs(re->real_addr.sin_port));

	free(re);
}

struct tun_addr {
	unsigned short af;
	union {
		struct in_addr in;
		struct in6_addr in6;
	};
};
struct tun_client {
	struct list_head list;
	struct tun_addr virt_addr;
	//struct sockaddr_in real_addr;
	struct ra_entry *ra;
	time_t last_recv;
	time_t last_xmit;
};

#define VA_MAP_HASH_SIZE  (1 << 4)
#define VA_MAP_LIMIT_EACH_WALK  (10)
static struct list_head va_map_hbase[VA_MAP_HASH_SIZE];
static unsigned va_map_len;

static inline void init_va_ra_maps(void)
{
	int i;

	for (i = 0; i < VA_MAP_HASH_SIZE; i++)
		INIT_LIST_HEAD(&va_map_hbase[i]);
	va_map_len = 0;

	for (i = 0; i < RA_SET_HASH_SIZE; i++)
		INIT_LIST_HEAD(&ra_set_hbase[i]);
	ra_set_len = 0;
}

static inline uint32_t tun_addr_hash(const struct tun_addr *addr)
{
	if (addr->af == AF_INET) {
		return jhash_2words(addr->af, addr->in.s_addr, hash_initval);
	} else if (addr->af == AF_INET6) {
		uint32_t __h = jhash_3words(addr->af, addr->in6.s6_addr32[0],
				addr->in6.s6_addr32[1], hash_initval);
		return jhash_2words(addr->in6.s6_addr32[2],
				addr->in6.s6_addr32[3], __h);
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
		if (a1->in.s_addr == a2->in.s_addr) {
			return 0;
		} else {
			return 1;
		}
	} else if (a1->af == AF_INET6) {
		if (a1->in6.s6_addr32[0] == a2->in6.s6_addr32[0] &&
			a1->in6.s6_addr32[1] == a2->in6.s6_addr32[1] &&
			a1->in6.s6_addr32[2] == a2->in6.s6_addr32[2] &&
			a1->in6.s6_addr32[3] == a2->in6.s6_addr32[3]) {
			return 0;
		} else {
			return 1;
		}
	} else {
		abort();
		return 0;
	}
}

static inline void tun_client_dump(struct tun_client *ce)
{
	char s_virt_addr[44] = "", s_real_addr[44] = "";

	inet_ntop(ce->virt_addr.af, &ce->virt_addr.in,
		s_virt_addr, sizeof(s_virt_addr));
	inet_ntop(ce->ra->real_addr.sin_family, &ce->ra->real_addr.sin_addr,
		s_real_addr, sizeof(s_real_addr));
	printf("[%s] (%s:%u), last_recv: %lu, last_xmit: %lu\n", s_virt_addr,
		s_real_addr, ntohs(ce->ra->real_addr.sin_port),
		(unsigned long)ce->last_recv, (unsigned long)ce->last_xmit);
}

static inline void tun_client_release(struct tun_client *ce)
{
	char s_virt_addr[44], s_real_addr[44];

	inet_ntop(ce->virt_addr.af, &ce->virt_addr.in,
		s_virt_addr, sizeof(s_virt_addr));
	inet_ntop(ce->ra->real_addr.sin_family, &ce->ra->real_addr.sin_addr,
		s_real_addr, sizeof(s_real_addr));
	printf("Recycled virtual address [%s] at [%s:%u].\n", s_virt_addr, s_real_addr,
		ntohs(ce->ra->real_addr.sin_port));

	ra_put_no_free(ce->ra);

	list_del(&ce->list);
	va_map_len--;

	free(ce);
}

static struct tun_client *tun_client_try_get(const struct tun_addr *vaddr)
{
	struct list_head *chain = &va_map_hbase[
		tun_addr_hash(vaddr) & (VA_MAP_HASH_SIZE - 1)];
	struct tun_client *ce;

	list_for_each_entry (ce, chain, list) {
		if (tun_addr_comp(&ce->virt_addr, vaddr) == 0)
			return ce;
	}
	return NULL;
}

static struct tun_client *tun_client_get_or_create(
		const struct tun_addr *vaddr, const struct sockaddr_in *raddr)
{
	struct list_head *chain = &va_map_hbase[
		tun_addr_hash(vaddr) & (VA_MAP_HASH_SIZE - 1)];
	struct tun_client *ce, *__ce;
	char s_virt_addr[44], s_real_addr[44];

	list_for_each_entry_safe (ce, __ce, chain, list) {
		if (tun_addr_comp(&ce->virt_addr, vaddr) == 0) {
			if (ce->ra->real_addr.sin_family != raddr->sin_family ||
				ce->ra->real_addr.sin_addr.s_addr != raddr->sin_addr.s_addr ||
				ce->ra->real_addr.sin_port != raddr->sin_port) {
				/* Real address changed, get a new entry for that. */
				ra_put_no_free(ce->ra);
				if ((ce->ra = ra_get_or_create(raddr)) == NULL) {
					tun_client_release(ce);
					return NULL;
				}
			}
			return ce;
		}
	}

	/* Not found, always create new entry. */
	if ((ce = malloc(sizeof(*ce))) == NULL) {
		fprintf(stderr, "*** [%s] malloc(): %s.\n", __FUNCTION__,
				strerror(errno));
		return NULL;
	}

	ce->virt_addr = *vaddr;

	/* Get real_addr entry before adding to list. */
	if ((ce->ra = ra_get_or_create(raddr)) == NULL) {
		free(ce);
		return NULL;
	}
	list_add_tail(&ce->list, chain);
	va_map_len++;

	inet_ntop(ce->virt_addr.af, &ce->virt_addr.in,
		s_virt_addr, sizeof(s_virt_addr));
	inet_ntop(ce->ra->real_addr.sin_family, &ce->ra->real_addr.sin_addr,
		s_real_addr, sizeof(s_real_addr));
	printf("New virtual address [%s] at [%s:%u].\n", s_virt_addr, s_real_addr,
		ntohs(ce->ra->real_addr.sin_port));

	return ce;
}

static int ra_entry_keepalive(struct ra_entry *re, int sockfd)
{
	char in_data[64], crypt_buffer[64];
	struct minivtun_msg *nmsg = (struct minivtun_msg *)in_data;
	void *out_msg;
	size_t out_len;
	int rc;

	nmsg->hdr.opcode = MINIVTUN_MSG_KEEPALIVE;
	memset(nmsg->hdr.rsv, 0x0, sizeof(nmsg->hdr.rsv));
	memcpy(nmsg->hdr.passwd_md5sum, g_crypto_passwd_md5sum,
		sizeof(nmsg->hdr.passwd_md5sum));
	nmsg->keepalive.loc_tun_in = g_local_tun_in;
	nmsg->keepalive.loc_tun_in6 = g_local_tun_in6;

	out_msg = crypt_buffer;
	out_len = MINIVTUN_MSG_BASIC_HLEN + sizeof(nmsg->keepalive);
	local_to_netmsg(nmsg, &out_msg, &out_len);

	rc = sendto(sockfd, out_msg, out_len, 0,
		(struct sockaddr *)&re->real_addr, sizeof(re->real_addr));

	/* Update 'last_xmit' only when it's really sent out. */
	if (rc > 0) {
		re->last_xmit = current_ts;
	}

	return rc;
}

static void va_ra_walk_continue(int sockfd)
{
	static unsigned va_index = 0, ra_index = 0;
	unsigned va_walk_max = VA_MAP_LIMIT_EACH_WALK, va_count = 0;
	unsigned ra_walk_max = RA_SET_LIMIT_EACH_WALK, ra_count = 0;
	unsigned __va_index = va_index, __ra_index = ra_index;
	struct tun_client *ce, *__ce;
	struct ra_entry *re, *__re;

	if (va_walk_max > va_map_len)
		va_walk_max = va_map_len;
	if (ra_walk_max > ra_set_len)
		ra_walk_max = ra_set_len;

	/* Recycle virtual address entries. */
	if (va_walk_max > 0) {
		do {
			list_for_each_entry_safe (ce, __ce, &va_map_hbase[va_index], list) {
				//tun_client_dump(ce);
				if (current_ts - ce->last_recv > g_reconnect_timeo) {
					tun_client_release(ce);
				}
				va_count++;
			}
			va_index = (va_index + 1) & (VA_MAP_HASH_SIZE - 1);
		} while (va_count < va_walk_max && va_index != __va_index);
	}

	/* Recycle or keep-alive real client addresses. */
	if (ra_walk_max > 0) {
		do {
			list_for_each_entry_safe (re, __re, &ra_set_hbase[ra_index], list) {
				if (current_ts - re->last_recv > g_reconnect_timeo) {
					if (re->refs == 0) {
						ra_entry_release(re);
					}
				} else if (current_ts - re->last_xmit > g_keepalive_timeo) {
					ra_entry_keepalive(re, sockfd);
				}
				ra_count++;
			}
			ra_index = (ra_index + 1) & (RA_SET_HASH_SIZE - 1);
		} while (ra_count < ra_walk_max && ra_index != __ra_index);
	}

	printf("Online clients: %u, addresses: %u\n", ra_set_len, va_map_len);
}

static inline void source_addr_of_ipdata(
		const void *data, unsigned char af, struct tun_addr *addr)
{
	addr->af = af;
	switch (af) {
	case AF_INET:
		memcpy(&addr->in, (char *)data + 12, 4);
		break;
	case AF_INET6:
		memcpy(&addr->in6, (char *)data + 8, 16);
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
		memcpy(&addr->in, (char *)data + 16, 4);
		break;
	case AF_INET6:
		memcpy(&addr->in6, (char *)data + 24, 16);
		break;
	default:
		abort();
	}
}


static int network_receiving(int tunfd, int sockfd)
{
	char read_buffer[NM_PI_BUFFER_SIZE], crypt_buffer[NM_PI_BUFFER_SIZE];
	struct minivtun_msg *nmsg;
	struct tun_pi pi;
	void *out_data;
	size_t ip_dlen, out_dlen;
	unsigned short af = 0;
	struct tun_addr virt_addr;
	struct tun_client *ce;
	struct ra_entry *re;
	struct sockaddr_in real_peer;
	socklen_t real_peer_alen;
	struct iovec iov[2];
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
	if (memcmp(nmsg->hdr.passwd_md5sum, g_crypto_passwd_md5sum, 16) != 0)
		return 0;

	switch (nmsg->hdr.opcode) {
	case MINIVTUN_MSG_KEEPALIVE:
		if ((re = ra_get_or_create(&real_peer))) {
			re->last_recv = current_ts;
			ra_put_no_free(re);
		}
		if (out_dlen < MINIVTUN_MSG_BASIC_HLEN + sizeof(nmsg->keepalive))
			return 0;
		if (is_valid_unicast_in(&nmsg->keepalive.loc_tun_in)) {
			virt_addr.af = AF_INET;
			virt_addr.in = nmsg->keepalive.loc_tun_in;
			if ((ce = tun_client_get_or_create(&virt_addr, &real_peer)))
				ce->last_recv = current_ts;
		}
		if (is_valid_unicast_in6(&nmsg->keepalive.loc_tun_in6)) {
			virt_addr.af = AF_INET6;
			virt_addr.in6 = nmsg->keepalive.loc_tun_in6;
			if ((ce = tun_client_get_or_create(&virt_addr, &real_peer)))
				ce->last_recv = current_ts;
		}
		break;
	case MINIVTUN_MSG_IPDATA:
		if (nmsg->ipdata.proto == htons(ETH_P_IP)) {
			af = AF_INET;
			/* No packet is shorter than a 20-byte IPv4 header. */
			if (out_dlen < MINIVTUN_MSG_IPDATA_OFFSET + 20)
				return 0;
		} else if (nmsg->ipdata.proto == htons(ETH_P_IPV6)) {
			af = AF_INET6;
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

		source_addr_of_ipdata(nmsg->ipdata.data, af, &virt_addr);
		if ((ce = tun_client_get_or_create(&virt_addr, &real_peer)) == NULL)
			return 0;

		ce->last_recv = current_ts;
		ce->ra->last_recv = current_ts;

		pi.flags = 0;
		pi.proto = nmsg->ipdata.proto;
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
	unsigned short af = 0;
	struct tun_addr virt_addr;
	struct tun_client *ce;
	int rc;

	rc = read(tunfd, pi, NM_PI_BUFFER_SIZE);
	if (rc < sizeof(struct tun_pi))
		return 0;

	/* We only accept IPv4 or IPv6 frames. */
	if (pi->proto != htons(ETH_P_IP) && pi->proto != htons(ETH_P_IPV6))
		return 0;

	ip_dlen = (size_t)rc - sizeof(struct tun_pi);

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

	dest_addr_of_ipdata(pi + 1, af, &virt_addr);
	if ((ce = tun_client_try_get(&virt_addr)) == NULL)
		return 0;

	nmsg.hdr.opcode = MINIVTUN_MSG_IPDATA;
	memset(nmsg.hdr.rsv, 0x0, sizeof(nmsg.hdr.rsv));
	memcpy(nmsg.hdr.passwd_md5sum, g_crypto_passwd_md5sum,
		sizeof(nmsg.hdr.passwd_md5sum));
	nmsg.ipdata.proto = pi->proto;
	nmsg.ipdata.ip_dlen = htons(ip_dlen);
	memcpy(nmsg.ipdata.data, pi + 1, ip_dlen);

	/* Do encryption. */
	out_data = crypt_buffer;
	out_dlen = MINIVTUN_MSG_IPDATA_OFFSET + ip_dlen;
	local_to_netmsg(&nmsg, &out_data, &out_dlen);

	rc = sendto(sockfd, out_data, out_dlen, 0,
		(struct sockaddr *)&ce->ra->real_addr, sizeof(ce->ra->real_addr));
	ce->last_xmit = current_ts;
	ce->ra->last_xmit = current_ts;

	return 0;
}

int run_server(int tunfd, const char *loc_addr_pair)
{
	struct timeval timeo;
	int sockfd, rc;
	struct sockaddr_in loc_addr;
	fd_set rset;
	time_t last_walk;
	char s_loc_addr[44];

	if (v4pair_to_sockaddr(loc_addr_pair, ':', &loc_addr) < 0) {
		fprintf(stderr, "*** Cannot resolve address pair '%s'.\n", loc_addr_pair);
		return -1;
	}

	inet_ntop(loc_addr.sin_family, &loc_addr.sin_addr,
		s_loc_addr, sizeof(s_loc_addr));
	printf("Mini virtual tunnelling server on %s:%u, interface: %s.\n",
		s_loc_addr, ntohs(loc_addr.sin_port), g_devname);

	/* Initialize address map hash table. */
	init_va_ra_maps();
	hash_initval = (uint32_t)time(NULL);

	if ((sockfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		fprintf(stderr, "*** socket() failed: %s.\n", strerror(errno));
		exit(1);
	}
	if (bind(sockfd, (struct sockaddr *)&loc_addr, sizeof(loc_addr)) < 0) {
		fprintf(stderr, "*** bind() failed: %s.\n", strerror(errno));
		exit(1);
	}
	set_nonblock(sockfd);

	/* Run in background. */
	if (g_in_background)
		do_daemonize();
	if (g_pid_file) {
		FILE *fp;
		if ((fp = fopen(g_pid_file, "w"))) {
			fprintf(fp, "%d\n", (int)getpid());
			fclose(fp);
		}
	}

	last_walk = time(NULL);

	for (;;) {
		FD_ZERO(&rset);
		FD_SET(tunfd, &rset);
		FD_SET(sockfd, &rset);

		timeo.tv_sec = 2;
		timeo.tv_usec = 0;

		rc = select((tunfd > sockfd ? tunfd : sockfd) + 1, &rset, NULL, NULL, &timeo);
		if (rc < 0) {
			fprintf(stderr, "*** select(): %s.\n", strerror(errno));
			return -1;
		}

		current_ts = time(NULL);

		if (rc > 0) {
			if (FD_ISSET(sockfd, &rset)) {
				rc = network_receiving(tunfd, sockfd);
			}

			if (FD_ISSET(tunfd, &rset)) {
				rc = tunnel_receiving(tunfd, sockfd);
			}
		}

		/* Check connection state at each chance. */
		if (current_ts - last_walk >= 3) {
			va_ra_walk_continue(sockfd);
			last_walk = current_ts;
		}
	}

	return 0;
}
