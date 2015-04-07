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

#include "list.h"
#include "minivtun.h"

#define NM_PI_BUFFER_SIZE  (2048)

static char g_devname[20];
static const char *g_log_file = NULL;
static const char *g_pid_file = NULL;
static const char *s_loc_addr = NULL;
static const char *s_peer_addr = NULL;
static unsigned g_tun_mtu = 1408;
static unsigned g_keepalive_timeo = 7;
static unsigned g_renegotiate_timeo = 26;
static bool g_is_daemon = false;
static const char *g_crypto_passwd = "";

static AES_KEY g_aes_encrypt_key;
static AES_KEY g_aes_decrypt_key;

static inline void gen_encrypt_key(const char *passwd)
{
	unsigned char md[16];
	MD5_CTX ctx;

	MD5_Init(&ctx);
	MD5_Update(&ctx, passwd, strlen(passwd));
	MD5_Final(md, &ctx);

	AES_set_encrypt_key((void *)md, 128, &g_aes_encrypt_key);
}
static inline void gen_decrypt_key(const char *passwd)
{
	unsigned char md[16];
	MD5_CTX ctx;

	MD5_Init(&ctx);
	MD5_Update(&ctx, passwd, strlen(passwd));
	MD5_Final(md, &ctx);

	AES_set_decrypt_key((void *)&md, 128, &g_aes_decrypt_key);
}

#define AES_IVEC_INITVAL  { 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, \
		0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, }

static inline void bytes_encrypt(void *out, void *in, size_t *dlen)
{
	unsigned char ivec[AES_BLOCK_SIZE] = AES_IVEC_INITVAL;
	size_t remain = *dlen % AES_BLOCK_SIZE;
	if (remain) {
		size_t padding = AES_BLOCK_SIZE - remain;
		memset((char *)in + *dlen, 0x0, padding);
		*dlen += padding;
	}
	AES_cbc_encrypt(in, out, *dlen, &g_aes_encrypt_key, (void *)ivec, AES_ENCRYPT);
}
static inline void bytes_decrypt(void *out, void *in, size_t *dlen)
{
	unsigned char ivec[AES_BLOCK_SIZE] = AES_IVEC_INITVAL;
	size_t remain = *dlen % AES_BLOCK_SIZE;
	if (remain) {
		size_t padding = AES_BLOCK_SIZE - remain;
		memset((char *)in + *dlen, 0x0, padding);
		*dlen += padding;
	}
	AES_cbc_encrypt(in, out, *dlen, &g_aes_decrypt_key, (void *)ivec, AES_DECRYPT);
}

static int do_daemonize(void)
{
	int rc;
	
	if ((rc = fork()) < 0) {
		fprintf(stderr, "*** fork() error: %s.\n", strerror(errno));
		return rc;
	} else if (rc > 0) {
		/* In parent process */
		exit(0);
	} else {
		/* In child process */
		int infd, outfd;
		setsid();
		chdir("/tmp");
		if ((infd = open("/dev/null", O_RDWR)) >= 0) {
			dup2(infd, STDIN_FILENO);
			if (infd > 2)
				close(infd);
		}
		if (g_log_file) {
			if ((outfd = open(g_log_file, O_WRONLY | O_CREAT | O_TRUNC)) < 0)
				outfd = open("/dev/null", O_RDWR);
		} else {
			outfd = open("/dev/null", O_RDWR);
		}
		dup2(outfd, STDOUT_FILENO);
		dup2(outfd, STDERR_FILENO);
		if (outfd > 2)
			close(outfd);
	}
	return 0;
}

static int tun_alloc(char *dev)
{
	struct ifreq ifr;
	int fd, err;

	if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
		if ((fd = open("/dev/tun", O_RDWR)) < 0)
			return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	/* Flags: IFF_TUN   - TUN device (no Ethernet headers)
	 *        IFF_TAP   - TAP device
	 *
	 *        IFF_NO_PI - Do not provide packet information
	 */
	ifr.ifr_flags = IFF_TUN;
	if (*dev)
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0){
		close(fd);
		return err;
	}
	strcpy(dev, ifr.ifr_name);
	return fd;
}

static void print_help(int argc, char *argv[])
{
	printf("P2P-based virtual tunneller.\n");
	printf("Usage:\n");
	printf("  %s [options]\n", argv[0]);
	printf("Options:\n");
	printf("  -u <uuid>             specify my UUID string\n");
	printf("  -U <expected_uuid>    specify peer UUID to connect (P2P negotiation mode)\n");
	printf("  -s <ip:port>          P2P negotiation server address (P2P negotiation mode)\n");
	printf("  -l <ip:port>          IP:port of local binding\n");
	printf("  -r <ip:port>          IP:port of peer device\n");
	printf("  -a <tun_lip/tun_rip>  tunnel IP pair\n");
	printf("  -A <tun_ip6/pfx_len>  tunnel IPv6 address/prefix length pair\n");
	printf("  -m <mtu>              set MTU size, default: %u.\n", g_tun_mtu);
	printf("  -t <g_keepalive_timeo>  seconds between sending keep-alive packets, default: %u\n", g_keepalive_timeo);
	printf("  -n <ifname>           tunnel interface name\n");
	printf("  -o <log_file>         log file path, only used with '-d'\n");
	printf("  -p <pid_file>         PID file of the daemon\n");
	printf("  -S <status_file>      file to store the latest negotiation status (P2P negotiation mode)\n");
	printf("  -e <encrypt_key>      shared password for data encryption\n");
	printf("  -N                    turn off encryption for tunnelling data\n");
	printf("  -v                    verbose print (P2P negotiation mode)\n");
	printf("  -d                    run as daemon process\n");
	printf("  -h                    print this help\n");
}

static int g_tunfd = -1, g_sockfd = -1;
static struct sockaddr_in g_loc_addr, g_peer_addr;

static void cleanup_on_exit(int sig)
{
	if (g_sockfd >= 0 && is_valid_host_sin(&g_peer_addr)) {
		struct minivtun_msg nmsg;
		int i;

		memset(&nmsg, 0x0, sizeof(nmsg));
		nmsg.hdr.opcode = MINIVTUN_MSG_DISCONNECT;
		for (i = 0; i < 2; i++) {
			sendto(g_sockfd, &nmsg, MINIVTUN_MSG_BASIC_HLEN, 0,
				(struct sockaddr *)&g_peer_addr, sizeof(g_peer_addr));
		}
		fprintf(stderr, "Notification sent to peer.\n");
	}
	if (g_pid_file)
		unlink(g_pid_file);
	exit(sig);
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static int minivtun_client(void)
{
	char tun_buffer[NM_PI_BUFFER_SIZE + 64], net_buffer[NM_PI_BUFFER_SIZE + 64];
	struct minivtun_msg *nmsg = (void *)net_buffer;
	struct tun_pi *pi = (void *)tun_buffer;
	time_t last_recv_ts = 0, last_xmit_ts = 0;
	char s1[20];
	int rc;

	printf("Mini virtual tunnelling (Client) to %s:%u, interface: %s.\n",
			ipv4_htos(ntohl(g_peer_addr.sin_addr.s_addr), s1), ntohs(g_peer_addr.sin_port),
			g_devname);

	/* NOTICE: Setting 'last_recv_ts' to 0 ensures a NOOP packet is sent 1s after startup. */
	last_recv_ts = last_xmit_ts = 0 /*time(NULL)*/;

	for (;;) {
		fd_set rset;
		struct timeval timeo;
		size_t ip_dlen, ready_dlen;
		time_t current_ts;

		FD_ZERO(&rset);
		FD_SET(g_tunfd, &rset);
		FD_SET(g_sockfd, &rset);

		timeo.tv_sec = 1;
		timeo.tv_usec = 0;

		rc = select((g_tunfd > g_sockfd ? g_tunfd : g_sockfd) + 1, &rset, NULL, NULL, &timeo);
		if (rc < 0) {
			fprintf(stderr, "*** select(): %s.\n", strerror(errno));
			exit(1);
		}

		/* Check connection state on each chance. */
		current_ts = time(NULL);
		if (last_recv_ts > current_ts)
			last_recv_ts = current_ts;
		if (last_xmit_ts > current_ts)
			last_xmit_ts = current_ts;

		/* Connection timed out, try reconnecting. */
		if (current_ts - last_recv_ts > g_renegotiate_timeo) {
			if (v4pair_to_sockaddr(s_peer_addr, ':', &g_peer_addr) < 0) {
				fprintf(stderr, "*** Failed to resolve '%s'.\n", s_peer_addr);
				continue;
			}
		}

		/* Packet receive timed out, send keep-alive packet. */
		if (current_ts - last_xmit_ts > g_keepalive_timeo) {
			nmsg->hdr.opcode = MINIVTUN_MSG_NOOP;
			sendto(g_sockfd, nmsg, MINIVTUN_MSG_BASIC_HLEN, 0,
					(struct sockaddr *)&g_peer_addr, sizeof(g_peer_addr));
			last_xmit_ts = current_ts;
		}

		/* No result from select(), do nothing. */
		if (rc == 0)
			continue;

		if (FD_ISSET(g_sockfd, &rset)) {
			struct sockaddr_in real_peer_addr;
			socklen_t real_peer_alen = sizeof(real_peer_addr);

			rc = recvfrom(g_sockfd, net_buffer, NM_PI_BUFFER_SIZE, 0,
					(struct sockaddr *)&real_peer_addr, &real_peer_alen);
			if (rc < 0 || rc < MINIVTUN_MSG_BASIC_HLEN)
				goto out1;

			/* FIXME: Verify password. */
			//
			//

			last_recv_ts = current_ts;

			switch (nmsg->hdr.opcode) {
			case MINIVTUN_MSG_IPDATA:
				/* No packet is shorter than a 20-byte IPv4 header. */
				if (rc < MINIVTUN_MSG_IPDATA_OFFSET + 20)
					break;
				ip_dlen = ntohs(nmsg->ipdata.ip_dlen);
				pi->flags = 0;
				pi->proto = nmsg->ipdata.proto;
				ready_dlen = (size_t)rc - MINIVTUN_MSG_IPDATA_OFFSET;
				if (g_crypto_passwd) {
					bytes_decrypt(pi + 1, nmsg->ipdata.data, &ready_dlen);
					/* Drop incomplete IP packets. */
					if (ready_dlen < ip_dlen)
						break;
				} else {
					/* Drop incomplete IP packets. */
					if (ready_dlen < ip_dlen)
						break;
					memcpy(pi + 1, nmsg->ipdata.data, ip_dlen);
				}
				rc = write(g_tunfd, pi, sizeof(struct tun_pi) + ip_dlen);
				break;
			case MINIVTUN_MSG_DISCONNECT:
				/* NOTICE: To instantly know connection closed in next loop. */
				last_recv_ts = last_xmit_ts = 0;
				break;
			}
			out1: ;
		}

		if (FD_ISSET(g_tunfd, &rset)) {
			rc = read(g_tunfd, tun_buffer, NM_PI_BUFFER_SIZE);
			if (rc < 0)
				break;

			switch (ntohs(pi->proto)) {
			case ETH_P_IP:
			case ETH_P_IPV6:
				ip_dlen = (size_t)rc - sizeof(struct tun_pi);
				nmsg->hdr.opcode = MINIVTUN_MSG_IPDATA;
				nmsg->ipdata.proto = pi->proto;
				nmsg->ipdata.ip_dlen = htons(ip_dlen);
				if (g_crypto_passwd) {
					ready_dlen = ip_dlen;
					bytes_encrypt(nmsg->ipdata.data, pi + 1, &ready_dlen);
				} else {
					memcpy(nmsg->ipdata.data, pi + 1, ip_dlen);
					ready_dlen = ip_dlen;
				}
				/* Server sends to peer after it has learned client address. */
				rc = sendto(g_sockfd, net_buffer, MINIVTUN_MSG_IPDATA_OFFSET + ready_dlen, 0,
						(struct sockaddr *)&g_peer_addr, sizeof(g_peer_addr));
				last_xmit_ts = current_ts;
				break;
			}
		}
	}

	return 0;
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */


















#define VIRTUAL_ADDR_HASH_SIZE (1 << 8)
static struct list_head virt_addr_hbase[VIRTUAL_ADDR_HASH_SIZE];
static size_t virt_addr_hlen = 0;

struct l3_addr {
	unsigned char af;
	union {
		struct in_addr ip;
		struct in6_addr ip6;
	};
};

struct tun_client {
	struct list_head list;
	struct l3_addr virt_addr;
	struct sockaddr_in real_addr;
	time_t last_recv;
	time_t last_xmit;
};

static inline unsigned int l3_addr_hash(const struct l3_addr *addr)
{
	if (addr->af == AF_INET) {
		return (unsigned int)addr->af + ntohl(addr->ip.s_addr);
	} else {
		return (unsigned int)addr->af +
			ntohl(addr->ip6.s6_addr32[0]) + ntohl(addr->ip6.s6_addr32[1]) +
			ntohl(addr->ip6.s6_addr32[2]) + ntohl(addr->ip6.s6_addr32[3]);
	}
}

static inline int l3_addr_comp(
		const struct l3_addr *a1, const struct l3_addr *a2)
{
	if (a1->af != a2->af)
		return 1;

	if (a1->af == AF_INET) {
		if (a1->ip.s_addr == a2->ip.s_addr) {
			return 0;
		} else {
			return 1;
		}
	} else {
		if (a1->ip6.s6_addr32[0] == a2->ip6.s6_addr32[0] &&
			a1->ip6.s6_addr32[1] == a2->ip6.s6_addr32[1] &&
			a1->ip6.s6_addr32[2] == a2->ip6.s6_addr32[2] &&
			a1->ip6.s6_addr32[3] == a2->ip6.s6_addr32[3]) {
			return 0;
		} else {
			return 1;
		}
	}
}

static struct tun_client *tun_client_try_get(const struct l3_addr *vaddr)
{
	struct list_head *chain = &virt_addr_hbase[
		l3_addr_hash(vaddr) & (VIRTUAL_ADDR_HASH_SIZE - 1)];
	struct tun_client *e;

	list_for_each_entry (e, chain, list) {
		if (l3_addr_comp(&e->virt_addr, vaddr) == 0)
			return e;
	}
	return NULL;
}

static struct tun_client *tun_client_get_or_create(
		const struct l3_addr *vaddr, const struct sockaddr_in *raddr)
{
	struct list_head *chain = &virt_addr_hbase[
		l3_addr_hash(vaddr) & (VIRTUAL_ADDR_HASH_SIZE - 1)];
	struct tun_client *e;

	list_for_each_entry (e, chain, list) {
		if (l3_addr_comp(&e->virt_addr, vaddr) == 0)
			return e;
	}

	/* Not found, always create new entry. */
	if ((e = malloc(sizeof(*e))) == NULL) {
		fprintf(stderr, "*** malloc(): %s.\n", strerror(errno));
		return NULL;
	}

	e->virt_addr = *vaddr;
	e->real_addr = *raddr;
	list_add_tail(&e->list, chain);
	return e;
}

static inline void source_addr_of_ipdata(
		const void *data, unsigned char af, struct l3_addr *addr)
{
	addr->af = af;
	switch (af) {
	case AF_INET:
		memcpy(&addr->ip, (char *)data + 12, 4);
		break;
	case AF_INET6:
		memcpy(&addr->ip6, (char *)data + 8, 16);
		break;
	}
}

static inline void dest_addr_of_ipdata(
		const void *data, unsigned char af, struct l3_addr *addr)
{
	addr->af = af;
	switch (af) {
	case AF_INET:
		memcpy(&addr->ip, (char *)data + 16, 4);
		break;
	case AF_INET6:
		memcpy(&addr->ip6, (char *)data + 24, 16);
		break;
	}
}


static int minivtun_server(void)
{
	char tun_buffer[NM_PI_BUFFER_SIZE + 64], net_buffer[NM_PI_BUFFER_SIZE + 64];
	struct minivtun_msg *nmsg = (void *)net_buffer;
	struct tun_pi *pi = (void *)tun_buffer;
	char s1[20];
	int rc;

	printf("Mini virtual tunnelling (Server) on %s:%u, interface: %s.\n",
			ipv4_htos(ntohl(g_loc_addr.sin_addr.s_addr), s1), ntohs(g_loc_addr.sin_port),
			g_devname);

	for (;;) {
		fd_set rset;
		struct timeval timeo;
		size_t ip_dlen, ready_dlen;
		time_t current_ts;

		FD_ZERO(&rset);
		FD_SET(g_tunfd, &rset);
		FD_SET(g_sockfd, &rset);

		timeo.tv_sec = 1;
		timeo.tv_usec = 0;

		rc = select((g_tunfd > g_sockfd ? g_tunfd : g_sockfd) + 1, &rset, NULL, NULL, &timeo);
		if (rc < 0) {
			fprintf(stderr, "*** select(): %s.\n", strerror(errno));
			exit(1);
		}

		/* Check connection state on each chance. */
		current_ts = time(NULL);

		/* No result from select(), do nothing. */
		if (rc == 0)
			continue;

		if (FD_ISSET(g_sockfd, &rset)) {
			struct sockaddr_in real_peer_addr;
			socklen_t real_peer_alen = sizeof(real_peer_addr);
			unsigned char af = 0;
			struct l3_addr virt_addr;
			struct tun_client *ce;

			rc = recvfrom(g_sockfd, net_buffer, NM_PI_BUFFER_SIZE, 0,
					(struct sockaddr *)&real_peer_addr, &real_peer_alen);
			if (rc < 0 || rc < MINIVTUN_MSG_BASIC_HLEN)
				goto out1;

			/* FIXME: Verify password. */
			//
			//

			switch (nmsg->hdr.opcode) {
			case MINIVTUN_MSG_IPDATA:
				if (nmsg->ipdata.proto == htons(ETH_P_IP)) {
					af = AF_INET;
					/* No packet is shorter than a 20-byte IPv4 header. */
					if (rc < MINIVTUN_MSG_IPDATA_OFFSET + 20)
						break;
				} else if (nmsg->ipdata.proto == htons(ETH_P_IPV6)) {
					af = AF_INET6;
					if (rc < MINIVTUN_MSG_IPDATA_OFFSET + 40)
						break;
				} else {
					fprintf(stderr, "*** Invalid protocol: 0x%x.\n", ntohs(nmsg->ipdata.proto));
					break;
				}

				ip_dlen = ntohs(nmsg->ipdata.ip_dlen);
				ready_dlen = (size_t)rc - MINIVTUN_MSG_IPDATA_OFFSET;
				/* Drop incomplete IP packets. */
				if (ready_dlen < ip_dlen)
					break;

				source_addr_of_ipdata(nmsg->ipdata.data, af, &virt_addr);
				if ((ce = tun_client_get_or_create(&virt_addr, &real_peer_addr)) == NULL)
					break;
				ce->last_recv = current_ts;
				pi->flags = 0;
				pi->proto = nmsg->ipdata.proto;
				memcpy(pi + 1, nmsg->ipdata.data, ip_dlen);

				rc = write(g_tunfd, pi, sizeof(struct tun_pi) + ip_dlen);
				break;
			}
			out1: ;
		}

		if (FD_ISSET(g_tunfd, &rset)) {
			unsigned char af = 0;
			struct l3_addr virt_addr;
			struct tun_client *ce;

			rc = read(g_tunfd, tun_buffer, NM_PI_BUFFER_SIZE);
			if (rc < 0)
				break;

			switch (ntohs(pi->proto)) {
			case ETH_P_IP:
			case ETH_P_IPV6:
				ip_dlen = (size_t)rc - sizeof(struct tun_pi);
				memcpy(nmsg->ipdata.data, pi + 1, ip_dlen);
				ready_dlen = ip_dlen;

				if (pi->proto == htons(ETH_P_IP)) {
					af = AF_INET;
					if (ip_dlen < 20)
						break;
				} else if (pi->proto == htons(ETH_P_IPV6)) {
					af = AF_INET6;
					if (ip_dlen < 40)
						break;
				} else {
					fprintf(stderr, "*** Invalid protocol: 0x%x.\n", ntohs(pi->proto));
					break;
				}

				dest_addr_of_ipdata(nmsg->ipdata.data, af, &virt_addr);
				if ((ce = tun_client_try_get(&virt_addr)) == NULL)
					break;

				nmsg->hdr.opcode = MINIVTUN_MSG_IPDATA;
				nmsg->ipdata.proto = pi->proto;
				nmsg->ipdata.ip_dlen = htons(ip_dlen);
				rc = sendto(g_sockfd, net_buffer, MINIVTUN_MSG_IPDATA_OFFSET + ready_dlen, 0,
						(struct sockaddr *)&ce->real_addr, sizeof(ce->real_addr));
				ce->last_xmit = current_ts;
				break;
			}
		}
	}

	return 0;
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

int main(int argc, char *argv[])
{
	const char *tun_ip_set = NULL, *tun_ip6_set = NULL;
	char cmd[100];
	int opt;

	while ((opt = getopt(argc, argv, "s:r:l:a:A:m:t:n:o:p:S:e:Nvdh")) != -1) {
		switch (opt) {
		case 'l':
			s_loc_addr = optarg;
			break;
		case 'r':
			s_peer_addr = optarg;
			break;
		case 'a':
			tun_ip_set = optarg;
			break;
		case 'A':
			tun_ip6_set = optarg;
			break;
		case 'm':
			g_tun_mtu = (unsigned)strtoul(optarg, NULL, 10);
			break;
		case 't':
			g_keepalive_timeo = (unsigned)strtoul(optarg, NULL, 10);
			break;
		case 'n':
			strncpy(g_devname, optarg, sizeof(g_devname) - 1);
			g_devname[sizeof(g_devname) - 1] = '\0';
			break;
		case 'o':
			g_log_file = optarg;
			break;
		case 'p':
			g_pid_file = optarg;
			break;
		case 'e':
			g_crypto_passwd = optarg;
			break;
		case 'N':
			g_crypto_passwd = NULL;
			break;
		case 'd':
			g_is_daemon = true;
			break;
		case 'h':
			print_help(argc, argv);
			exit(0);
			break;
		case '?':
			exit(1);
		}
	}

	memset(&g_loc_addr, 0x0, sizeof(g_loc_addr));
	memset(&g_peer_addr, 0x0, sizeof(g_peer_addr));

	if (g_crypto_passwd) {
		gen_encrypt_key(g_crypto_passwd);
		gen_decrypt_key(g_crypto_passwd);
	} else {
		fprintf(stderr, "*** WARNING: Tunnel data will be transmitted without encryption.\n");
	}

	if (strlen(g_devname) == 0)
		strcpy(g_devname, "p2p%d");
	if ((g_tunfd = tun_alloc(g_devname)) < 0) {
		fprintf(stderr, "*** open_tun() failed: %s.\n", strerror(errno));
		exit(1);
	}

	/* Configure IPv4 address for the interface. */
	if (tun_ip_set) {
		char s_lip[20], *s_rip;

		if (!(s_rip = strchr(tun_ip_set, '/'))) {
			fprintf(stderr, "*** Invalid P-t-P IP pair: %s.\n", tun_ip_set);
			exit(1);
		}
		strncpy(s_lip, tun_ip_set, s_rip - tun_ip_set);
		s_lip[s_rip - tun_ip_set] = '\0';
		s_rip++;

		sprintf(cmd, "ifconfig %s %s pointopoint %s", g_devname, s_lip, s_rip);
		(void)system(cmd);
	}

	/* Configure IPv6 address if set. */
	if (tun_ip6_set) {
		sprintf(cmd, "ifconfig %s add %s", g_devname, tun_ip6_set);
		(void)system(cmd);
	}

	/* Always bring it up with proper MTU size. */
	sprintf(cmd, "ifconfig %s mtu %u; ifconfig %s up", g_devname, g_tun_mtu, g_devname);
	(void)system(cmd);

	/* Mode 2: Regular server or client mode. */
	if (s_loc_addr && v4pair_to_sockaddr(s_loc_addr, ':', &g_loc_addr) < 0) {
		fprintf(stderr, "*** Unable to resolve address pair: %s.\n", s_loc_addr);
		exit(1);
	}
	if (s_peer_addr && v4pair_to_sockaddr(s_peer_addr, ':', &g_peer_addr) < 0) {
		fprintf(stderr, "*** Unable to resolve address pair: %s.\n", s_peer_addr);
		exit(1);
	}

	/* The initial tunnelling connection. */
	if ((g_sockfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		fprintf(stderr, "*** socket() failed: %s.\n", strerror(errno));
		exit(1);
	}
	if (bind(g_sockfd, (struct sockaddr *)&g_loc_addr, sizeof(g_loc_addr)) < 0) {
		fprintf(stderr, "*** bind() failed: %s.\n", strerror(errno));
		exit(1);
	}
	set_nonblock(g_sockfd);

	/* Run in background. */
	if (g_is_daemon)
		do_daemonize();

	if (g_pid_file) {
		FILE *fp;
		if ((fp = fopen(g_pid_file, "w"))) {
			fprintf(fp, "%d\n", (int)getpid());
			fclose(fp);
		}
	}

	if (is_valid_bind_sin(&g_loc_addr)) {
		minivtun_server();
	} else if (is_valid_host_sin(&g_peer_addr)) {
		minivtun_client();
	} else {
		fprintf(stderr, "*** No valid local or peer address can be used.\n");
		exit(1);
	}


	return 0;
}

