/*
 * Copyright (c) 2015 Justin Liu
 * Author: Justin Liu <rssnsj@gmail.com>
 * https://github.com/rssnsj/minivtun
 */

#ifndef __LIBRARY_H
#define __LIBRARY_H

#include <sys/types.h>
#include <sys/time.h>
#include <stddef.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

typedef uint32_t __be32;
typedef uint16_t __be16;
typedef uint32_t __u32;
typedef uint16_t __u16;
typedef uint8_t __u8;

typedef char bool;
#define true 1
#define false 0

#define countof(arr) (sizeof(arr) / sizeof((arr)[0]))

#define container_of(ptr, type, member) ({			\
	const typeof(((type *)0)->member) * __mptr = (ptr);	\
	(type *)((char *)__mptr - offsetof(type, member)); })

#ifndef ETH_P_IP
	#define ETH_P_IP 0x0800 /* Internet Protocol packet */
#endif
#ifndef ETH_P_IPV6
	#define ETH_P_IPV6 0x86dd /* IPv6 over bluebook */
#endif

/* Dummy types for ethernet mode */
struct mac_addr { __u8 addr[6]; };
#ifdef __linux__
#define AF_MACADDR AF_PACKET
#endif

/* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= */

static inline bool is_in6_equal(const struct in6_addr *a1, const struct in6_addr *a2)
{
	const __be32 *b1 = (__be32 *)a1, *b2 = (__be32 *)a2;
	if (b1[0] == b2[0] && b1[1] == b2[1] &&
		b1[2] == b2[2] && b1[3] == b2[3]) {
		return true;
	} else {
		return false;
	}
}

static inline bool is_mac_equal(const struct mac_addr *a1, const struct mac_addr *a2)
{
	const __be32 *b1 = (__be32 *)a1, *b2 = (__be32 *)a2;
	const __be16 *c1 = (__be16 *)(b1 + 1), *c2 = (__be16 *)(b2 + 1);
	if (*b1 == *b2 && *c1 == *c2) {
		return true;
	} else {
		return false;
	}
}

struct sockaddr_inx {
	union {
		struct sockaddr sa;
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
	};
};

#define port_of_sockaddr(s) ((s)->sa.sa_family == AF_INET6 ? (s)->in6.sin6_port : (s)->in.sin_port)
#define addr_of_sockaddr(s) ((s)->sa.sa_family == AF_INET6 ? (void *)&(s)->in6.sin6_addr : (void *)&(s)->in.sin_addr)
#define sizeof_sockaddr(s)  ((s)->sa.sa_family == AF_INET6 ? sizeof((s)->in6) : sizeof((s)->in))

static inline bool is_sockaddr_equal(const struct sockaddr_inx *a1,
		const struct  sockaddr_inx *a2)
{
	if (a1->sa.sa_family != a2->sa.sa_family)
		return false;

	if (a1->sa.sa_family == AF_INET6) {
		if (is_in6_equal(&a1->in6.sin6_addr, &a2->in6.sin6_addr) &&
			a1->in6.sin6_port == a2->in6.sin6_port) {
			return true;
		}
	} else {
		if (a1->in.sin_addr.s_addr == a2->in.sin_addr.s_addr &&
			a1->in.sin_port == a2->in.sin_port) {
			return true;
		}
	}

	return false;
}

int get_sockaddr_inx_pair(const char *pair, struct sockaddr_inx *sa);
int resolve_and_connect(const char *peer_addr_pair, struct sockaddr_inx *peer_addr);
int tun_alloc(char *dev, bool tap_mode);

void ip_addr_add_ipv4(const char *ifname, struct in_addr *local,
		struct in_addr *peer, int prefix);
void ip_addr_add_ipv6(const char *ifname, struct in6_addr *local, int prefix);
void ip_link_set_mtu(const char *ifname, unsigned mtu);
void ip_link_set_updown(const char *ifname, bool up);
void ip_route_add_ipvx(const char *ifname, int af, void *network, int prefix,
		int metric, const char *table);

static inline bool is_valid_unicast_in(struct in_addr *in)
{
	__u32 a = ntohl(in->s_addr);
	return  ((a & 0xff000000) != 0x00000000) &&
			((a & 0xf0000000) != 0xe0000000);
}

static inline bool is_valid_unicast_in6(struct in6_addr *in6)
{
	__u32 a0 = ntohl(((__be32 *)in6)[0]);
	return  ((a0 & 0xff000000) != 0x00000000) &&
			((a0 & 0xff000000) != 0xff000000);
}

static inline bool is_valid_unicast_mac(struct mac_addr *mac)
{
	if ((mac->addr[0] & 0x01)) {
		return false;
	} else {
		__be16 *a = (__be16 *)mac;
		if (a[0] == 0 && a[1] == 0 && a[2] == 0) {
			return false;
		} else {
			return true;
		}
	}
}

/* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= */

#if defined(__APPLE__) || defined(__FreeBSD__)
	#include <net/if.h>

	/* Protocol info prepended to the packets */
	struct tun_pi {
		__u16  flags;
		__be16 proto;
	};
	#define TUNSIFHEAD  _IOW('t', 96, int)
	#define TUNGIFHEAD  _IOR('t', 97, int)

	/* Conversion between address family & ethernet type. */
	static inline void osx_af_to_ether(__be16 *proto)
	{
		switch (ntohs(*proto)) {
		case AF_INET:
			*proto = htons(ETH_P_IP);
			break;
		case AF_INET6:
			*proto = htons(ETH_P_IPV6);
			break;
		}
	}
	static inline void osx_ether_to_af(__be16 *proto)
	{
		switch (ntohs(*proto)) {
		case ETH_P_IP:
			*proto = htons(AF_INET);
			break;
		case ETH_P_IPV6:
			*proto = htons(AF_INET6);
			break;
		}
	}
#else
	#include <linux/if.h>
	#include <linux/if_tun.h>

	#define osx_af_to_ether(x)
	#define osx_ether_to_af(x)
#endif

/* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= */

#define CRYPTO_DEFAULT_ALGORITHM  "aes-128"
#define CRYPTO_MAX_KEY_SIZE  32
#define CRYPTO_MAX_BLOCK_SIZE  32

struct name_cipher_pair {
	const char *name;
	const void *cipher;
};

extern struct name_cipher_pair cipher_pairs[];
const void *get_crypto_type(const char *name);
void datagram_encrypt(const void *key, const void *cptype, void *in,
		void *out, size_t *dlen);
void datagram_decrypt(const void *key, const void *cptype, void *in,
		void *out, size_t *dlen);
void fill_with_string_md5sum(const char *in, void *out, size_t outlen);

/* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= */

static inline long __sub_timeval_ms(const struct timeval *a,
		const struct timeval *b)
{
	long secs = a->tv_sec - b->tv_sec;
	if (secs > 1000000)
		return 1000000000;
	if (secs < -1000000)
		return -1000000000;
	return secs * 1000 + (a->tv_usec - b->tv_usec) / 1000;
}

static inline int set_nonblock(int sockfd)
{
	if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFD, 0)|O_NONBLOCK) == -1)
		return -1;
	return 0;
}

static inline void hexdump(void *d, size_t len)
{
	unsigned char *s;
	for (s = d; len; len--, s++)
		printf("%02x ", (unsigned int)*s);
	printf("\n");
}

void do_daemonize(void);

#endif /* __LIBRARY_H */

