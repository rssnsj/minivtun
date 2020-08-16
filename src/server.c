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
#include <signal.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#include "list.h"
#include "jhash.h"
#include "minivtun.h"

static __u32 hash_initval = 0;

static void *vt_route_lookup(short af, const void *a)
{
	const union {
		struct in_addr in;
		struct in6_addr in6;
	} *addr = a;
	struct vt_route *rt;

	for (rt = config.vt_routes; rt; rt = rt->next) {
		if (rt->af != af)
			continue;
		if (af == AF_INET) {
			if (rt->prefix == 0) {
				return &rt->gateway.in;
			} else {
				in_addr_t m = rt->prefix ? htonl(~((1 << (32 - rt->prefix)) - 1)) : 0;
				if ((addr->in.s_addr & m) == rt->network.in.s_addr)
					return &rt->gateway.in;
			}
		} else if (af == AF_INET6) {
			if (rt->prefix == 0) {
				return &rt->gateway.in6;
			} else if (rt->prefix < 128) {
				struct in6_addr n = addr->in6;
				int i;
				n.s6_addr[rt->prefix / 8] &= ~((1 << (8 - rt->prefix % 8)) - 1);
				for (i = rt->prefix / 8 + 1; i < 16; i++)
					n.s6_addr[i] &= 0x00;
				if (is_in6_equal(&n, &rt->network.in6))
					return &rt->gateway.in6;
			}

		}
	}

	return NULL;
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

struct ra_entry {
	struct list_head list;
	struct sockaddr_inx real_addr;
	struct timeval last_recv;
	__u16 xmit_seq;
	int refs;
};

/* Hash table for dedicated clients (real addresses). */
#define RA_SET_HASH_SIZE  (1 << 3)
#define RA_SET_LIMIT_EACH_WALK  (10)
static struct list_head ra_set_hbase[RA_SET_HASH_SIZE];
static unsigned ra_set_len;

static inline __u32 real_addr_hash(const struct sockaddr_inx *sa)
{
	if (sa->sa.sa_family == AF_INET6) {
		return jhash_2words(sa->sa.sa_family, sa->in6.sin6_port,
			jhash2((__u32 *)&sa->in6.sin6_addr, 4, hash_initval));
	} else {
		return jhash_3words(sa->sa.sa_family, sa->in.sin_port,
			sa->in.sin_addr.s_addr, hash_initval);
	}
}

static struct ra_entry *ra_get_or_create(const struct sockaddr_inx *sa)
{
	struct list_head *chain = &ra_set_hbase[
		real_addr_hash(sa) & (RA_SET_HASH_SIZE - 1)];
	struct ra_entry *re;
	char s_real_addr[50];

	list_for_each_entry (re, chain, list) {
		if (is_sockaddr_equal(&re->real_addr, sa)) {
			re->refs++;
			return re;
		}
	}

	if ((re = malloc(sizeof(*re))) == NULL) {
		syslog(LOG_ERR, "*** [%s] malloc(): %s.", __FUNCTION__, strerror(errno));
		return NULL;
	}

	re->real_addr = *sa;
	re->xmit_seq = (__u16)rand();
	re->refs = 1;
	list_add_tail(&re->list, chain);
	ra_set_len++;

	inet_ntop(re->real_addr.sa.sa_family, addr_of_sockaddr(&re->real_addr),
			s_real_addr, sizeof(s_real_addr));
	syslog(LOG_INFO, "New client [%s:%u]", s_real_addr,
			port_of_sockaddr(&re->real_addr));

	return re;
}

static inline void ra_put_no_free(struct ra_entry *re)
{
	assert(re->refs > 0);
	re->refs--;
}

static inline void ra_entry_release(struct ra_entry *re)
{
	char s_real_addr[50];

	assert(re->refs == 0);
	list_del(&re->list);
	ra_set_len--;

	inet_ntop(re->real_addr.sa.sa_family, addr_of_sockaddr(&re->real_addr),
			s_real_addr, sizeof(s_real_addr));
	syslog(LOG_INFO, "Recycled client [%s:%u]", s_real_addr,
			ntohs(port_of_sockaddr(&re->real_addr)));

	free(re);
}

struct tun_addr {
	unsigned short af;
	union {
		struct in_addr in;
		struct in6_addr in6;
		struct mac_addr mac;
	};
};
struct tun_client {
	struct list_head list;
	struct tun_addr virt_addr;
	struct ra_entry *ra;
	struct timeval last_recv;
};

/* Hash table of virtual address in tunnel. */
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

static inline __u32 tun_addr_hash(const struct tun_addr *addr)
{
	if (addr->af == AF_INET) {
		return jhash_2words(addr->af, addr->in.s_addr, hash_initval);
	} else if (addr->af == AF_INET6) {
		const __be32 *a = (void *)&addr->in6;
		return jhash_2words(a[2], a[3],
			jhash_3words(addr->af, a[0], a[1], hash_initval));
	} else if (addr->af == AF_MACADDR) {
		const __be32 *a = (void *)&addr->mac;
		const __be16 *b = (void *)(a + 1);
		return jhash_3words(addr->af, *a, *b, hash_initval);
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
		if (is_in6_equal(&a1->in6, &a2->in6)) {
			return 0;
		} else {
			return 1;
		}
	} else if (a1->af == AF_MACADDR) {
		if (is_mac_equal(&a1->mac, &a2->mac)) {
			return 0;
		} else {
			return 1;
		}
	} else {
		abort();
		return 0;
	}
}

static void tun_addr_ntop(const struct tun_addr *a, char *buf, socklen_t bufsz)
{
	const __u8 *b;

	switch (a->af) {
	case AF_INET:
	case AF_INET6:
		inet_ntop(a->af, &a->in, buf, bufsz);
		break;
	default:
		b = a->mac.addr;
		sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
				b[0], b[1], b[2], b[3], b[4], b[5]);
	}
}

#ifdef DUMP_TUN_CLIENTS_ON_WALK
static inline void tun_client_dump(struct tun_client *ce)
{
	char s_virt_addr[50] = "", s_real_addr[50] = "";

	tun_addr_ntop(&ce->virt_addr, s_virt_addr, sizeof(s_virt_addr));
	inet_ntop(ce->ra->real_addr.sa.sa_family, addr_of_sockaddr(&ce->ra->real_addr),
			  s_real_addr, sizeof(s_real_addr));
	printf("[%s] (%s:%u), last_recv: %lu\n", s_virt_addr,
			s_real_addr, ntohs(port_of_sockaddr(&ce->ra->real_addr)),
			(unsigned long)ce->last_recv.tv_sec);
}
#endif

static inline void tun_client_release(struct tun_client *ce)
{
	char s_virt_addr[50], s_real_addr[50];

	tun_addr_ntop(&ce->virt_addr, s_virt_addr, sizeof(s_virt_addr));
	inet_ntop(ce->ra->real_addr.sa.sa_family, addr_of_sockaddr(&ce->ra->real_addr),
			s_real_addr, sizeof(s_real_addr));
	syslog(LOG_INFO, "Recycled virtual address [%s] at [%s:%u].", s_virt_addr,
			s_real_addr, ntohs(port_of_sockaddr(&ce->ra->real_addr)));

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
		const struct tun_addr *vaddr, const struct sockaddr_inx *raddr)
{
	struct list_head *chain = &va_map_hbase[
		tun_addr_hash(vaddr) & (VA_MAP_HASH_SIZE - 1)];
	struct tun_client *ce, *__ce;
	char s_virt_addr[50], s_real_addr[50];

	list_for_each_entry_safe (ce, __ce, chain, list) {
		if (tun_addr_comp(&ce->virt_addr, vaddr) == 0) {
			if (!is_sockaddr_equal(&ce->ra->real_addr, raddr)) {
				/* Real address changed, reassign a new entry for it. */
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
		syslog(LOG_ERR, "*** [%s] malloc(): %s.", __FUNCTION__, strerror(errno));
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

	tun_addr_ntop(&ce->virt_addr, s_virt_addr, sizeof(s_virt_addr));
	inet_ntop(ce->ra->real_addr.sa.sa_family, addr_of_sockaddr(&ce->ra->real_addr),
			  s_real_addr, sizeof(s_real_addr));
	syslog(LOG_INFO, "New virtual address [%s] at [%s:%u].", s_virt_addr,
			s_real_addr, ntohs(port_of_sockaddr(&ce->ra->real_addr)));

	return ce;
}

/* Send echo reply back to a client */
static void reply_an_echo_ack(struct minivtun_msg *req, struct ra_entry *re)
{
	char in_data[64], crypt_buffer[64];
	struct minivtun_msg *nmsg = (struct minivtun_msg *)in_data;
	void *out_msg;
	size_t out_len;

	memset(&nmsg->hdr, 0x0, sizeof(nmsg->hdr));
	nmsg->hdr.opcode = MINIVTUN_MSG_ECHO_ACK;
	nmsg->hdr.seq = htons(re->xmit_seq++);
	memcpy(nmsg->hdr.auth_key, config.crypto_key, sizeof(nmsg->hdr.auth_key));
	nmsg->echo = req->echo;

	out_msg = crypt_buffer;
	out_len = MINIVTUN_MSG_BASIC_HLEN + sizeof(nmsg->echo);
	local_to_netmsg(nmsg, &out_msg, &out_len);

	(void)sendto(state.sockfd, out_msg, out_len, 0,
			(const struct sockaddr *)&re->real_addr,
			sizeof_sockaddr(&re->real_addr));
}

static void va_ra_walk_continue(void)
{
	static unsigned va_index = 0, ra_index = 0;
	struct timeval __current;
	unsigned va_walk_max = VA_MAP_LIMIT_EACH_WALK, va_count = 0;
	unsigned ra_walk_max = RA_SET_LIMIT_EACH_WALK, ra_count = 0;
	unsigned __va_index = va_index, __ra_index = ra_index;
	struct tun_client *ce, *__ce;
	struct ra_entry *re, *__re;

	gettimeofday(&__current, NULL);

	if (va_walk_max > va_map_len)
		va_walk_max = va_map_len;
	if (ra_walk_max > ra_set_len)
		ra_walk_max = ra_set_len;

	/* Recycle timeout virtual address entries. */
	if (va_walk_max > 0) {
		do {
			list_for_each_entry_safe (ce, __ce, &va_map_hbase[va_index], list) {
#ifdef DUMP_TUN_CLIENTS_ON_WALK
				tun_client_dump(ce);
#endif
				if (__sub_timeval_ms(&__current, &ce->last_recv) >
					config.reconnect_timeo * 1000) {
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
				if (__sub_timeval_ms(&__current, &re->last_recv) >
					config.reconnect_timeo * 1000) {
					if (re->refs == 0) {
						ra_entry_release(re);
					}
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
	case AF_MACADDR:
		memcpy(&addr->mac, (char *)data + 6, 6);
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
	case AF_MACADDR:
		memcpy(&addr->mac, (char *)data + 0, 6);
		break;
	default:
		abort();
	}
}


static int network_receiving(void)
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
	struct sockaddr_inx real_peer;
	socklen_t real_peer_alen;
	struct iovec iov[2];
	struct timeval __current;
	int rc;

	gettimeofday(&__current, NULL);

	real_peer_alen = sizeof(real_peer);
	rc = recvfrom(state.sockfd, &read_buffer, NM_PI_BUFFER_SIZE, 0,
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

	switch (nmsg->hdr.opcode) {
	case MINIVTUN_MSG_ECHO_REQ:
		/* Keep the real address alive */
		if ((re = ra_get_or_create(&real_peer))) {
			re->last_recv = __current;
			/* Send echo reply */
			reply_an_echo_ack(nmsg, re);
			ra_put_no_free(re);
		}
		if (out_dlen < MINIVTUN_MSG_BASIC_HLEN + sizeof(nmsg->echo))
			return 0;
		/* Keep virtual addresses alive */
		if (config.tap_mode) {
			/* TAP mode, handle as MAC address */
			if (is_valid_unicast_mac(&nmsg->echo.loc_tun_mac)) {
				virt_addr.af = AF_MACADDR;
				virt_addr.mac = nmsg->echo.loc_tun_mac;
				if ((ce = tun_client_get_or_create(&virt_addr, &real_peer)))
					ce->last_recv = __current;
			}
		} else {
			/* TUN mode, handle as IP/IPv6 addresses */
			if (is_valid_unicast_in(&nmsg->echo.loc_tun_in)) {
				virt_addr.af = AF_INET;
				virt_addr.in = nmsg->echo.loc_tun_in;
				if ((ce = tun_client_get_or_create(&virt_addr, &real_peer)))
					ce->last_recv = __current;
			}
			if (is_valid_unicast_in6(&nmsg->echo.loc_tun_in6)) {
				virt_addr.af = AF_INET6;
				virt_addr.in6 = nmsg->echo.loc_tun_in6;
				if ((ce = tun_client_get_or_create(&virt_addr, &real_peer)))
					ce->last_recv = __current;
			}
		}
		break;
	case MINIVTUN_MSG_IPDATA:
		if (config.tap_mode) {
			af = AF_MACADDR;
			/* No ethernet packet is shorter than 14 bytes. */
			if (out_dlen < MINIVTUN_MSG_IPDATA_OFFSET + 14)
				return 0;
			nmsg->ipdata.proto = 0;
			ip_dlen = out_dlen - MINIVTUN_MSG_IPDATA_OFFSET;
		} else {
			if (nmsg->ipdata.proto == htons(ETH_P_IP)) {
				af = AF_INET;
				/* No valid IP packet is shorter than 20 bytes. */
				if (out_dlen < MINIVTUN_MSG_IPDATA_OFFSET + 20)
					return 0;
			} else if (nmsg->ipdata.proto == htons(ETH_P_IPV6)) {
				af = AF_INET6;
				if (out_dlen < MINIVTUN_MSG_IPDATA_OFFSET + 40)
					return 0;
			} else {
				syslog(LOG_WARNING, "*** Invalid protocol: 0x%x.", ntohs(nmsg->ipdata.proto));
				return 0;
			}
			ip_dlen = ntohs(nmsg->ipdata.ip_dlen);
			/* Drop incomplete IP packets. */
			if (out_dlen - MINIVTUN_MSG_IPDATA_OFFSET < ip_dlen)
				return 0;
		}

		source_addr_of_ipdata(nmsg->ipdata.data, af, &virt_addr);
		if ((ce = tun_client_get_or_create(&virt_addr, &real_peer)) == NULL)
			return 0;

		ce->last_recv = __current;
		ce->ra->last_recv = __current;

		pi.flags = 0;
		pi.proto = nmsg->ipdata.proto;
		osx_ether_to_af(&pi.proto);
		iov[0].iov_base = &pi;
		iov[0].iov_len = sizeof(pi);
		iov[1].iov_base = (char *)nmsg + MINIVTUN_MSG_IPDATA_OFFSET;
		iov[1].iov_len = ip_dlen;
		rc = writev(state.tunfd, iov, 2);
		break;
	}

	return 0;
}

static int tunnel_receiving(void)
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

	rc = read(state.tunfd, pi, NM_PI_BUFFER_SIZE);
	if (rc < sizeof(struct tun_pi))
		return -1;

	osx_af_to_ether(&pi->proto);

	ip_dlen = (size_t)rc - sizeof(struct tun_pi);

	if (config.tap_mode) {
		/* Ethernet frame */
		af = AF_MACADDR;
		if (ip_dlen < 14)
			return 0;
	} else {
		/* We only accept IPv4 or IPv6 frames. */
		if (pi->proto == htons(ETH_P_IP)) {
			af = AF_INET;
			if (ip_dlen < 20)
				return 0;
		} else if (pi->proto == htons(ETH_P_IPV6)) {
			af = AF_INET6;
			if (ip_dlen < 40)
				return 0;
		} else {
			syslog(LOG_WARNING, "*** Invalid protocol: 0x%x.", ntohs(pi->proto));
			return 0;
		}
	}

	dest_addr_of_ipdata(pi + 1, af, &virt_addr);

	if ((ce = tun_client_try_get(&virt_addr)) == NULL) {
		/**
		 * Not an existing client address, lookup the pseudo
		 * route table for a destination to send.
		 */
		void *gw;

		/* Lookup the gateway address first */
		if ((gw = vt_route_lookup(virt_addr.af, &virt_addr.in))) {
			/* Then find the gateway client entry */
			struct tun_addr __va;
			memset(&__va, 0x0, sizeof(__va));
			__va.af = virt_addr.af;
			if (virt_addr.af == AF_INET) {
				__va.in = *(struct in_addr *)gw;
			} else if (virt_addr.af == AF_INET6) {
				__va.in6 = *(struct in6_addr *)gw;
			} else {
				__va.mac = *(struct mac_addr *)gw;
			}
			if ((ce = tun_client_try_get(&__va)) == NULL)
				return 0;

			/* Finally, create a client entry with this address */
			if ((ce = tun_client_get_or_create(&virt_addr,
				&ce->ra->real_addr)) == NULL)
				return 0;
		} else if (config.tap_mode) {
			/* In TAP mode, fall through to broadcast to all clients */
		} else {
			return 0;
		}
	}

	memset(&nmsg.hdr, 0x0, sizeof(nmsg.hdr));
	nmsg.hdr.opcode = MINIVTUN_MSG_IPDATA;
	memcpy(nmsg.hdr.auth_key, config.crypto_key, sizeof(nmsg.hdr.auth_key));
	nmsg.ipdata.proto = pi->proto;
	nmsg.ipdata.ip_dlen = htons(ip_dlen);
	memcpy(nmsg.ipdata.data, pi + 1, ip_dlen);

	/* Do encryption. */
	out_data = crypt_buffer;
	out_dlen = MINIVTUN_MSG_IPDATA_OFFSET + ip_dlen;
	local_to_netmsg(&nmsg, &out_data, &out_dlen);

	if (ce) {
		nmsg.hdr.seq = htons(ce->ra->xmit_seq++);
		(void)sendto(state.sockfd, out_data, out_dlen, 0,
				(struct sockaddr *)&ce->ra->real_addr,
				sizeof_sockaddr(&ce->ra->real_addr));
	} else {
		/* Traverse all online clients and send */
		unsigned i;
		for (i = 0; i < RA_SET_HASH_SIZE; i++) {
			struct ra_entry *re;
			list_for_each_entry (re, &ra_set_hbase[i], list) {
				nmsg.hdr.seq = htons(re->xmit_seq++);
				(void)sendto(state.sockfd, out_data, out_dlen, 0,
						(struct sockaddr *)&re->real_addr,
						sizeof_sockaddr(&re->real_addr));
			}
		}
	}

	return 0;
}

int run_server(const char *loc_addr_pair)
{
	char s_loc_addr[50];
	bool is_random_port = false;

	if (get_sockaddr_inx_pair(loc_addr_pair, &state.local_addr, &is_random_port) < 0) {
		fprintf(stderr, "*** Cannot resolve address pair '%s'.\n", loc_addr_pair);
		return -1;
	}
	if (is_random_port) {
		fprintf(stderr, "*** Port range is not allowed for server.\n");
		return -1;
	}

	inet_ntop(state.local_addr.sa.sa_family, addr_of_sockaddr(&state.local_addr),
			s_loc_addr, sizeof(s_loc_addr));
	printf("Mini virtual tunneling server on %s:%u, interface: %s.\n",
			s_loc_addr, ntohs(port_of_sockaddr(&state.local_addr)), config.ifname);

	/* Initialize address map hash table. */
	init_va_ra_maps();
	hash_initval = rand();

	if ((state.sockfd = socket(state.local_addr.sa.sa_family, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		fprintf(stderr, "*** socket() failed: %s.\n", strerror(errno));
		exit(1);
	}
	if (bind(state.sockfd, (struct sockaddr *)&state.local_addr,
		sizeof_sockaddr(&state.local_addr)) < 0) {
		fprintf(stderr, "*** bind() failed: %s.\n", strerror(errno));
		exit(1);
	}
	set_nonblock(state.sockfd);

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

	gettimeofday(&state.last_walk, NULL);

	for (;;) {
		fd_set rset;
		struct timeval __current, timeo;
		int rc;

		FD_ZERO(&rset);
		FD_SET(state.tunfd, &rset);
		FD_SET(state.sockfd, &rset);

		timeo = (struct timeval) { 2, 0 };
		rc = select((state.tunfd > state.sockfd ? state.tunfd : state.sockfd) + 1,
				&rset, NULL, NULL, &timeo);
		if (rc < 0) {
			fprintf(stderr, "*** select(): %s.\n", strerror(errno));
			return -1;
		}

		if (FD_ISSET(state.sockfd, &rset)) {
			rc = network_receiving();
		}

		if (FD_ISSET(state.tunfd, &rset)) {
			rc = tunnel_receiving();
		}

		/* Check connection state at each chance. */
		gettimeofday(&__current, NULL);
		if (__sub_timeval_ms(&__current, &state.last_walk) >= 3 * 1000) {
			va_ra_walk_continue();
			state.last_walk = __current;
		}
	}

	return 0;
}
