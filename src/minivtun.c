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

static const char *g_uuid = NULL;
static const char *g_expected_uuid = NULL;
static const char *g_log_file = NULL;
static const char *g_pid_file = NULL;
static const char *g_status_file = NULL;
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

static inline void minivtun_msg_set_uuids(struct minivtun_msg *nm,
		const char *src_uuid, const char *dst_uuid)
{
	memset(nm->hdr.src_uuid, 0x0, MINIVTUN_UUID_SIZE);
	memset(nm->hdr.dst_uuid, 0x0, MINIVTUN_UUID_SIZE);
	if (src_uuid)
		strncpy(nm->hdr.src_uuid, src_uuid, MINIVTUN_UUID_SIZE);
	if (dst_uuid)
		strncpy(nm->hdr.dst_uuid, dst_uuid, MINIVTUN_UUID_SIZE);
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

static void __cleanup_and_exit(int sig)
{
	if (g_sockfd >= 0 && is_valid_host_sin(&g_peer_addr)) {
		struct minivtun_msg nm;
		int i;

		memset(&nm, 0x0, sizeof(nm));
		nm.hdr.ver = 0;
		nm.hdr.opcode = MINIVTUN_MSG_DISCONNECT;
		minivtun_msg_set_uuids(&nm, g_uuid, g_expected_uuid);
		nm.disconnect.rsv = 0;
		for (i = 0; i < 2; i++) {
			sendto(g_sockfd, &nm, MINIVTUN_MSG_BASIC_HLEN + sizeof(nm.disconnect), 0,
					(struct sockaddr *)&g_peer_addr, sizeof(g_peer_addr));
		}
		fprintf(stderr, "Notification sent to peer.\n");
	}
	if (g_pid_file)
		unlink(g_pid_file);
	if (g_status_file)
		unlink(g_status_file);
	exit(sig);
}

int main(int argc, char *argv[])
{
	const char *s_loc_addr = NULL, *s_peer_addr = NULL,
		*tun_ip_set = NULL, *tun_ip6_set = NULL;
#define NM_PI_BUFFER_SIZE  (2048)
	char devname[20] = "", pi_buf[NM_PI_BUFFER_SIZE + 64],
		nm_buf[NM_PI_BUFFER_SIZE + 64], s1[20], s2[20], *cmd = pi_buf;
	struct tun_pi *pi = (void *)pi_buf;
	struct minivtun_msg *nm = (void *)nm_buf;
	time_t last_recv_ts = 0, last_xmit_ts = 0;
	int opt, rc;

	while ((opt = getopt(argc, argv, "u:U:s:r:l:a:A:m:t:n:o:p:S:e:Nvdh")) != -1) {
		switch (opt) {
		case 'u':
			g_uuid = optarg;
			break;
		case 'U':
			g_expected_uuid = optarg;
			break;
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
			strncpy(devname, optarg, sizeof(devname) - 1);
			devname[sizeof(devname) - 1] = '\0';
			break;
		case 'o':
			g_log_file = optarg;
			break;
		case 'p':
			g_pid_file = optarg;
			break;
		case 'S':
			g_status_file = optarg;
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

	if (strlen(devname) == 0)
		strcpy(devname, "p2p%d");
	if ((g_tunfd = tun_alloc(devname)) < 0) {
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

		sprintf(cmd, "ifconfig %s %s pointopoint %s", devname, s_lip, s_rip);
		(void)system(cmd);
	}

	/* Configure IPv6 address if set. */
	if (tun_ip6_set) {
		sprintf(cmd, "ifconfig %s add %s", devname, tun_ip6_set);
		(void)system(cmd);
	}

	/* Always bring it up with proper MTU size. */
	sprintf(cmd, "ifconfig %s mtu %u; ifconfig %s up", devname, g_tun_mtu, devname);
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

	if (is_valid_bind_sin(&g_loc_addr) && is_valid_host_sin(&g_peer_addr)) {
		printf("P2P-based virtual tunneller (P2P) on %s:%u <-> %s:%u, interface: %s.\n",
				ipv4_htos(ntohl(g_loc_addr.sin_addr.s_addr), s1), ntohs(g_loc_addr.sin_port),
				ipv4_htos(ntohl(g_peer_addr.sin_addr.s_addr), s2), ntohs(g_peer_addr.sin_port),
				devname);
	} else if (is_valid_bind_sin(&g_loc_addr)) {
		printf("P2P-based virtual tunneller (Server) on %s:%u, interface: %s.\n",
				ipv4_htos(ntohl(g_loc_addr.sin_addr.s_addr), s1), ntohs(g_loc_addr.sin_port),
				devname);
	} else if (is_valid_host_sin(&g_peer_addr)) {
		printf("P2P-based virtual tunneller (Client) to %s:%u, interface: %s.\n",
				ipv4_htos(ntohl(g_peer_addr.sin_addr.s_addr), s1), ntohs(g_peer_addr.sin_port),
				devname);
	} else {
		fprintf(stderr, "*** No valid local or peer address can be used.\n");
		exit(1);
	}

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

	/* NOTICE: Setting 'last_recv_ts' to 0 ensures a NOOP packet is sent 1s after startup. */
	last_recv_ts = last_xmit_ts = 0 /*time(NULL)*/;

	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, __cleanup_and_exit);
	signal(SIGTERM, __cleanup_and_exit);

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

		/* Check connection state at each chance. */
		current_ts = time(NULL);
		if (last_recv_ts > current_ts)
			last_recv_ts = current_ts;
		if (last_xmit_ts > current_ts)
			last_xmit_ts = current_ts;

		/* No packets received from peer for long time, connection is dead. */
		if (current_ts - last_recv_ts > g_renegotiate_timeo) {
			if (s_peer_addr) {
				/* Client mode: Update server's DNS resolution in case it changes. */
				if (v4pair_to_sockaddr(s_peer_addr, ':', &g_peer_addr) < 0) {
					fprintf(stderr, "*** Unable to resolve address pair: %s.\n", s_peer_addr);
					continue;
				}
			}
		}

		/* No packets sent to peer for more than 'last_xmit_ts', send a 'NOOP'. */
		if (current_ts - last_xmit_ts > g_keepalive_timeo) {
			/* Timed out, send a keep-alive packet. */
			nm->hdr.ver = 0;
			nm->hdr.opcode = MINIVTUN_MSG_NOOP;
			minivtun_msg_set_uuids(nm, g_uuid, g_expected_uuid);
			nm->noop.rsv = 0;
			if (g_peer_addr.sin_addr.s_addr && g_peer_addr.sin_port) {
				sendto(g_sockfd, nm, MINIVTUN_MSG_BASIC_HLEN + sizeof(nm->noop), 0,
						(struct sockaddr *)&g_peer_addr, sizeof(g_peer_addr));
				last_xmit_ts = current_ts;
			}
		}

		/* Nothing more to do on timeout. */
		if (rc == 0)
			continue;

		if (FD_ISSET(g_sockfd, &rset)) {
			struct sockaddr_in real_peer_addr;
			socklen_t real_peer_alen = sizeof(real_peer_addr);

			rc = recvfrom(g_sockfd, nm_buf, NM_PI_BUFFER_SIZE, 0,
					(struct sockaddr *)&real_peer_addr, &real_peer_alen);
			if (rc < 0)
				goto out1;
			if (rc < MINIVTUN_MSG_BASIC_HLEN)
				goto out1;

			/* Check identities of this packet. */
			if ((g_uuid && strncmp(nm->hdr.dst_uuid, g_uuid, MINIVTUN_UUID_SIZE) != 0) ||
				(g_expected_uuid && strncmp(nm->hdr.src_uuid, g_expected_uuid, MINIVTUN_UUID_SIZE) != 0)) {
				fprintf(stderr, "*** Untrusted UDP message from %s:%u.\n",
						ipv4_htos(ntohl(real_peer_addr.sin_addr.s_addr), s1),
						ntohs(real_peer_addr.sin_port));
				goto out1;
			}

			/* Update the time each time it receives from peer. */
			last_recv_ts = current_ts;

			/* Learn peer address on each incoming packet if it was not specified (server mode). */
			if (s_peer_addr == NULL)
				g_peer_addr = real_peer_addr;

			switch (nm->hdr.opcode) {
			case MINIVTUN_MSG_IPDATA:
				/* No packet is shorter than a 20-byte IPv4 header. */
				if (rc < MINIVTUN_MSG_IPDATA_OFFSET + 20)
					goto out1;
				ip_dlen = ntohs(nm->ipdata.ip_dlen);
				pi->flags = 0;
				pi->proto = nm->ipdata.proto;
				ready_dlen = (size_t)rc - MINIVTUN_MSG_IPDATA_OFFSET;
				if (g_crypto_passwd) {
					bytes_decrypt(pi + 1, nm->ipdata.data, &ready_dlen);
					/* Drop truncated packets. */
					if (ready_dlen < ip_dlen)
						goto out1;
				} else {
					/* Drop truncated packets. */
					if (ready_dlen < ip_dlen)
						goto out1;
					memcpy(pi + 1, nm->ipdata.data, ip_dlen);
				}
				rc = write(g_tunfd, pi, sizeof(struct tun_pi) + ip_dlen);
				break;
			case MINIVTUN_MSG_DISCONNECT:
				/* NOTICE: To let next loop instantly know the connection is dead. */
				last_recv_ts = last_xmit_ts = 0;
				break;
			}
out1:		;
		}

		if (FD_ISSET(g_tunfd, &rset)) {
			rc = read(g_tunfd, pi_buf, NM_PI_BUFFER_SIZE);
			if (rc < 0)
				break;

			switch (ntohs(pi->proto)) {
			case ETH_P_IP:
			case ETH_P_IPV6:
				ip_dlen = (size_t)rc - sizeof(struct tun_pi);
				nm->hdr.opcode = MINIVTUN_MSG_IPDATA;
				minivtun_msg_set_uuids(nm, g_uuid, g_expected_uuid);
				nm->ipdata.proto = pi->proto;
				nm->ipdata.ip_dlen = htons(ip_dlen);
				if (g_crypto_passwd) {
					ready_dlen = ip_dlen;
					bytes_encrypt(nm->ipdata.data, pi + 1, &ready_dlen);
				} else {
					memcpy(nm->ipdata.data, pi + 1, ip_dlen);
					ready_dlen = ip_dlen;
				}
				/* Server sends to peer after it has learned client address. */
				if (g_peer_addr.sin_addr.s_addr && g_peer_addr.sin_port) {
					rc = sendto(g_sockfd, nm_buf, MINIVTUN_MSG_IPDATA_OFFSET + ready_dlen, 0,
							(struct sockaddr *)&g_peer_addr, sizeof(g_peer_addr));
					last_xmit_ts = current_ts;
				}
				break;
			}
		}
	}

	return 0;
}

