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
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <net/route.h>

#include "library.h"

struct name_cipher_pair cipher_pairs[] = {
	{ "aes-128", EVP_aes_128_cbc, },
	{ "aes-256", EVP_aes_256_cbc, },
	{ "des", EVP_des_cbc, },
	{ "desx", EVP_desx_cbc, },
	{ "rc4", EVP_rc4, },
	{ NULL, NULL, },
};

const void *get_crypto_type(const char *name)
{
	const EVP_CIPHER *cipher = NULL;
	int i;

	for (i = 0; cipher_pairs[i].name; i++) {
		if (strcasecmp(cipher_pairs[i].name, name) == 0) {
			cipher = ((const EVP_CIPHER *(*)(void))cipher_pairs[i].cipher)();
			break;
		}
	}

	if (cipher) {
		assert(EVP_CIPHER_key_length(cipher) <= CRYPTO_MAX_KEY_SIZE);
		assert(EVP_CIPHER_iv_length(cipher) <= CRYPTO_MAX_BLOCK_SIZE);
		return cipher;
	} else {
		return NULL;
	}
}

static const char crypto_ivec_initdata[CRYPTO_MAX_BLOCK_SIZE] = {
	0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
	0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
	0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
	0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
};

#define CRYPTO_DATA_PADDING(data, dlen, bs) \
	do { \
		size_t last_len = *(dlen) % (bs); \
		if (last_len) { \
			size_t padding_len = bs - last_len; \
			memset((char *)data + *(dlen), 0x0, padding_len); \
			*(dlen) += padding_len; \
		} \
	} while(0)

void datagram_encrypt(const void *key, const void *cptype, void *in,
		void *out, size_t *dlen)
{
	size_t iv_len = EVP_CIPHER_iv_length((const EVP_CIPHER *)cptype);
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	unsigned char iv[CRYPTO_MAX_KEY_SIZE];
	int outl = 0, outl2 = 0;

	if (iv_len == 0)
		iv_len = 16;

	memcpy(iv, crypto_ivec_initdata, iv_len);
	CRYPTO_DATA_PADDING(in, dlen, iv_len);
	EVP_CIPHER_CTX_init(ctx);
	assert(EVP_EncryptInit_ex(ctx, cptype, NULL, key, iv));
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	assert(EVP_EncryptUpdate(ctx, out, &outl, in, *dlen));
	assert(EVP_EncryptFinal_ex(ctx, (unsigned char *)out + outl, &outl2));
	EVP_CIPHER_CTX_cleanup(ctx);
	EVP_CIPHER_CTX_free(ctx);

	*dlen = (size_t)(outl + outl2);
}

void datagram_decrypt(const void *key, const void *cptype, void *in,
		void *out, size_t *dlen)
{
	size_t iv_len = EVP_CIPHER_iv_length((const EVP_CIPHER *)cptype);
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	unsigned char iv[CRYPTO_MAX_KEY_SIZE];
	int outl = 0, outl2 = 0;

	if (iv_len == 0)
		iv_len = 16;

	memcpy(iv, crypto_ivec_initdata, iv_len);
	CRYPTO_DATA_PADDING(in, dlen, iv_len);
	EVP_CIPHER_CTX_init(ctx);
	assert(EVP_DecryptInit_ex(ctx, cptype, NULL, key, iv));
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	assert(EVP_DecryptUpdate(ctx, out, &outl, in, *dlen));
	assert(EVP_DecryptFinal_ex(ctx, (unsigned char *)out + outl, &outl2));
	EVP_CIPHER_CTX_cleanup(ctx);
	EVP_CIPHER_CTX_free(ctx);

	*dlen = (size_t)(outl + outl2);
}

void fill_with_string_md5sum(const char *in, void *out, size_t outlen)
{
	char *outp = out, *oute = outp + outlen;
	MD5_CTX ctx;

	MD5_Init(&ctx);
	MD5_Update(&ctx, in, strlen(in));
	MD5_Final(out, &ctx);

	/* Fill in remaining buffer with repeated data. */
	for (outp += 16; outp < oute; outp += 16) {
		size_t bs = (oute - outp >= 16) ? 16 : (oute - outp);
		memcpy(outp, out, bs);
	}
}

/* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= */

int get_sockaddr_inx_pair(const char *pair, struct sockaddr_inx *sa,
		bool *is_random_port)
{
	struct addrinfo hints, *result;
	char host[51] = "", s_port[21] = "";
	unsigned port = 0;
	int rc;

	*is_random_port = false;

	/* Only getting an INADDR_ANY address. */
	if (pair == NULL) {
		struct sockaddr_in *sa4 = (struct sockaddr_in *)sa;
		sa4->sin_family = AF_INET;
		sa4->sin_addr.s_addr = 0;
		sa4->sin_port = 0;
		return 0;
	}

	if (sscanf(pair, "[%50[^]]]:%20s", host, s_port) == 2 ||
		sscanf(pair, "%50[^:]:%20s", host, s_port) == 2) {
		unsigned end_port = 0;
		if (sscanf(s_port, "%u-%u", &port, &end_port) == 2) {
			/* Port range */
			if (!(port > 0 && end_port >= port && end_port <= 65535))
				return -EINVAL;
			port += rand() % (end_port - port + 1);
			*is_random_port = true;
		} else {
			/* Single port */
			port = strtoul(s_port, NULL, 10);
			if (port > 65535)
				return -EINVAL;
		}
	} else  {
		/**
		 * Address with a single port number, usually for
		 * local IPv4 listen address.
		 * e.g., "10000" is considered as "0.0.0.0:10000"
		 */
		strcpy(host, "0.0.0.0");
		port = strtoul(pair, NULL, 10);
		if (port > 65535)
			return -EINVAL;
	}

	sprintf(s_port, "%u", port);

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;  /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;  /* For wildcard IP address */
	hints.ai_protocol = 0;        /* Any protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	if ((rc = getaddrinfo(host, s_port, &hints, &result)))
		return -EAGAIN;

	/* Get the first resolution. */
	memcpy(sa, result->ai_addr, result->ai_addrlen);

	freeaddrinfo(result);
	return 0;
}

int resolve_and_connect(const char *peer_addr_pair, struct sockaddr_inx *peer_addr)
{
	int sockfd, rc;
	bool is_random_port = false;

	if ((rc = get_sockaddr_inx_pair(peer_addr_pair, peer_addr, &is_random_port)) < 0)
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

int tun_alloc(char *dev, bool tap_mode)
{
	int fd = -1, err;
#if defined(__APPLE__) || defined(__FreeBSD__)
	int b_enable = 1, i;

	for (i = 0; i < 8; i++) {
		char dev_path[20];
		sprintf(dev_path, "/dev/tun%d", i);
		if ((fd = open(dev_path, O_RDWR)) >= 0) {
			sprintf(dev, "tun%d", i);
			break;
		}
	}
	if (fd < 0)
		return -EINVAL;
	if ((err = ioctl(fd, TUNSIFHEAD, &b_enable)) < 0) {
		close(fd);
		return err;
	}
#else
	struct ifreq ifr;

	if ((fd = open("/dev/net/tun", O_RDWR)) >= 0) {
	} else if ((fd = open("/dev/tun", O_RDWR)) >= 0) {
	} else {
		return -EINVAL;
	}

	memset(&ifr, 0, sizeof(ifr));
	if (tap_mode) {
		ifr.ifr_flags = IFF_TAP;
	} else {
		ifr.ifr_flags = IFF_TUN;
	}
	if (dev[0])
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
		close(fd);
		return err;
	}
	strcpy(dev, ifr.ifr_name);
#endif

	return fd;
}

/* Like strncpy but make sure the resulting string is always 0 terminated. */
static char *safe_strncpy(char *dst, const char *src, size_t size)
{
	dst[size - 1] = '\0';
	return strncpy(dst, src, size - 1);
}

/* Set a certain interface flag. */
static int __set_flag(int sockfd, const char *ifname, short flag)
{
	struct ifreq ifr;

	safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
		fprintf(stderr, "*** SIOCGIFFLAGS: %s.\n", strerror(errno));
		return -1;
	}
	safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_flags |= flag;
	if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
		fprintf(stderr, "*** SIOCSIFFLAGS: %s.\n", strerror(errno));
		return -1;
	}
	return 0;
}
/* Clear a certain interface flag. */
static int __clr_flag(int sockfd, const char *ifname, short flag)
{
	struct ifreq ifr;

	safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
		fprintf(stderr, "*** SIOCGIFFLAGS: %s.\n", strerror(errno));
		return -1;
	}
	safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_flags &= ~flag;
	if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
		fprintf(stderr, "*** SIOCSIFFLAGS: %s.\n", strerror(errno));
		return -1;
	}
	return 0;
}

static int __set_ip_using(int sockfd, const char *name, int c,
		const struct in_addr *addr)
{
	struct sockaddr_in sin;
	struct ifreq ifr;

	safe_strncpy(ifr.ifr_name, name, IFNAMSIZ);
	memset(&sin, 0, sizeof(struct sockaddr));
	sin.sin_family = AF_INET;
	sin.sin_addr = *addr;
	memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));
	if (ioctl(sockfd, c, &ifr) < 0)
		return -1;
	return 0;
}

static int __get_ifindex(const char *ifname)
{
	struct ifreq ifr;
	int sockfd;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return -1;
	memset(&ifr, 0x0, sizeof(ifr));
	safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(sockfd, SIOGIFINDEX, &ifr) < 0) {
		close(sockfd);
		return -1;
	}
	close(sockfd);
	return ifr.ifr_ifindex;
}

void ip_addr_add_ipv4(const char *ifname, struct in_addr *local,
		struct in_addr *peer, int prefix)
{
	int sockfd;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return;
	if (is_valid_unicast_in(local) && is_valid_unicast_in(peer)) {
		__set_ip_using(sockfd, ifname, SIOCSIFADDR, local);
		__set_ip_using(sockfd, ifname, SIOCSIFDSTADDR, peer);
		__set_flag(sockfd, ifname, IFF_POINTOPOINT | IFF_UP | IFF_RUNNING); /* same as ifconfig */
	} else if (is_valid_unicast_in(local) && prefix > 0) {
		struct in_addr mask;
		mask.s_addr = htonl(~((1 << (32 - prefix)) - 1));
		__set_ip_using(sockfd, ifname, SIOCSIFADDR, local);
		__set_ip_using(sockfd, ifname, SIOCSIFNETMASK, &mask);
		__set_flag(sockfd, ifname, IFF_UP | IFF_RUNNING); /* same as ifconfig */
	}
	close(sockfd);
}

void ip_addr_add_ipv6(const char *ifname, struct in6_addr *local, int prefix)
{
#ifndef _LINUX_IN6_H
	/* This is in linux/include/net/ipv6.h */
	struct in6_ifreq {
		struct in6_addr ifr6_addr;
		__u32 ifr6_prefixlen;
		unsigned int ifr6_ifindex;
	};
#endif
	struct in6_ifreq ifr6;
	int sockfd, ifindex;

	if ((ifindex = __get_ifindex(ifname)) < 0) {
		fprintf(stderr, "*** SIOGIFINDEX: %s.\n", strerror(errno));
		return;
	}
	if ((sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
		return;
	if (is_valid_unicast_in6(local) && prefix > 0) {
		memcpy(&ifr6.ifr6_addr, local, sizeof(*local));
		ifr6.ifr6_ifindex = ifindex;
		ifr6.ifr6_prefixlen = prefix;
		if (ioctl(sockfd, SIOCSIFADDR, &ifr6) < 0)
			fprintf(stderr, "*** SIOCSIFADDR: %s.\n", strerror(errno));
	}
	close(sockfd);
}

void ip_link_set_mtu(const char *ifname, unsigned mtu)
{
	struct ifreq ifr;
	int sockfd;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return;
	safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_mtu = mtu;
	if (ioctl(sockfd, SIOCSIFMTU, &ifr) < 0)
		fprintf(stderr, "*** SIOCSIFMTU, %u: %s.\n", mtu, strerror(errno));
	close(sockfd);
}

void ip_link_set_txqueue_len(const char *ifname, unsigned qlen)
{
	struct ifreq ifr;
	int sockfd;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return;
	safe_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_qlen = qlen;
	if (ioctl(sockfd, SIOCSIFTXQLEN, &ifr) < 0)
		fprintf(stderr, "*** SIOCSIFTXQLEN: %s\n", strerror(errno));
	close(sockfd);
}

void ip_link_set_updown(const char *ifname, bool up)
{
	int sockfd;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return;
	if (up) {
		__set_flag(sockfd, ifname, IFF_UP | IFF_RUNNING);
	} else {
		__clr_flag(sockfd, ifname, IFF_UP);
	}
	close(sockfd);
}

#if defined(__APPLE__) || defined(__FreeBSD__)
void ip_route_add_ipvx(const char *ifname, int af, void *network,
		int prefix, int metric, const char *table)
{
	char cmd[256], __net[64] = "";
	inet_ntop(af, network, __net, sizeof(__net));
	sprintf(cmd, "route %s add -net %s/%d %s metric %d",
		af == AF_INET6 ? "-A inet6" : "", __net, prefix, ifname, metric);
	(void)system(cmd);
}
#else
void ip_route_add_ipvx(const char *ifname, int af, void *network,
		int prefix, int metric, const char *table)
{
	/* Fallback to 'ip route ...' if adding to another table */
	if (table) {
		char cmd[256], __net[64] = "";
		inet_ntop(af, network, __net, sizeof(__net));
		sprintf(cmd, "ip %s route add %s/%d dev %s metric %d table %s",
			af == AF_INET6 ? "-6" : "", __net, prefix, ifname, metric, table);
		(void)system(cmd);
	} else 	if (af == AF_INET) {
		/* IPv4 */
		struct rtentry rt;
		int sockfd;

		memset(&rt, 0x0, sizeof(rt));
		rt.rt_flags = RTF_UP;
		if (prefix == 32)
			rt.rt_flags |= RTF_HOST;
		((struct sockaddr_in *)&rt.rt_dst)->sin_family = AF_INET;
		((struct sockaddr_in *)&rt.rt_dst)->sin_addr = *(struct in_addr *)network;
		((struct sockaddr_in *)&rt.rt_genmask)->sin_family = AF_INET;
		((struct sockaddr_in *)&rt.rt_genmask)->sin_addr.s_addr =
				prefix ? htonl(~((1 << (32 - prefix)) - 1)) : 0;
		rt.rt_metric = metric + 1; /* +1 for binary compatibility! */
		rt.rt_dev = (char *)ifname;
		if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
			fprintf(stderr, "*** socket(): %s\n", strerror(errno));
			return;
		}
		ioctl(sockfd, SIOCADDRT, &rt);
		close(sockfd);
	} else if (af == AF_INET6) {
		/* IPv6 */
		struct in6_rtmsg rt6;
		int sockfd, ifindex;

		if ((ifindex = __get_ifindex(ifname)) < 0) {
			fprintf(stderr, "*** SIOGIFINDEX: %s.\n", strerror(errno));
			return;
		}

		memset(&rt6, 0x0, sizeof(rt6));
		memcpy(&rt6.rtmsg_dst, network, sizeof(struct in6_addr));
		rt6.rtmsg_flags = RTF_UP;
		if (prefix == 128)
			rt6.rtmsg_flags |= RTF_HOST;
		rt6.rtmsg_metric = metric;
		rt6.rtmsg_dst_len = prefix;
		rt6.rtmsg_ifindex = ifindex;

		if ((sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
			fprintf(stderr, "*** socket(): %s\n", strerror(errno));
			return;
		}
		ioctl(sockfd, SIOCADDRT, &rt6);
		close(sockfd);
	}
}
#endif

void do_daemonize(void)
{
	pid_t pid;
	int fd;

	/* Fork off the parent process */
	if ((pid = fork()) < 0) {
		/* Error */
		fprintf(stderr, "*** fork() error: %s.\n", strerror(errno));
		exit(1);
	} else if (pid > 0) {
		/* Let the parent process terminate */
		exit(0);
	}

	/* Do this before child process quits to prevent duplicate printf output */
	if ((fd = open("/dev/null", O_RDWR)) >= 0) {
		dup2(fd, 0);
		dup2(fd, 1);
		dup2(fd, 2);
		if (fd > 2)
			close(fd);
	}

	/* Let the child process become session leader */
	if (setsid() < 0)
		exit(1);

	if ((pid = fork()) < 0) {
		/* Error */
		exit(1);
	} else if (pid > 0) {
		/* Let the parent process terminate */
		exit(0);
	}

	/* OK, set up the grandchild process */
	chdir("/tmp");
}

