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

#include "minivtun.h"

unsigned g_keepalive_timeo = 7;
unsigned g_reconnect_timeo = 26;
const char *g_pid_file = NULL;
const char *g_crypto_passwd = "";
char g_crypto_passwd_md5sum[16];
AES_KEY g_encrypt_key;
AES_KEY g_decrypt_key;

char g_devname[20];
static unsigned g_tun_mtu = 1408;

static void print_help(int argc, char *argv[])
{
	printf("P2P-based virtual tunneller.\n");
	printf("Usage:\n");
	printf("  %s [options]\n", argv[0]);
	printf("Options:\n");
	printf("  -l <ip:port>          IP:port of local binding\n");
	printf("  -r <ip:port>          IP:port of peer device\n");
	printf("  -a <tun_lip/tun_rip>  tunnel IP pair\n");
	printf("  -A <tun_ip6/pfx_len>  tunnel IPv6 address/prefix length pair\n");
	printf("  -m <mtu>              set MTU size, default: %u.\n", g_tun_mtu);
	printf("  -t <g_keepalive_timeo>  seconds between sending keep-alive packets, default: %u\n", g_keepalive_timeo);
	printf("  -n <ifname>           tunnel interface name\n");
	printf("  -o <log_file>         log file path, only used with '-d'\n");
	printf("  -p <pid_file>         PID file of the daemon\n");
	printf("  -e <g_encrypt_key>      shared password for data encryption\n");
	printf("  -N                    turn off encryption for tunnelling data\n");
	printf("  -v                    verbose print (P2P negotiation mode)\n");
	printf("  -d                    run as daemon process\n");
	printf("  -h                    print this help\n");
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


//static void cleanup_on_exit(int sig)
//{
//	if (g_sockfd >= 0 && is_valid_host_sin(&g_peer_addr)) {
//		struct minivtun_msg nmsg;
//		int i;
//
//		memset(&nmsg, 0x0, sizeof(nmsg));
//		nmsg.hdr.opcode = MINIVTUN_MSG_DISCONNECT;
//		for (i = 0; i < 2; i++) {
//			sendto(g_sockfd, &nmsg, MINIVTUN_MSG_BASIC_HLEN, 0,
//				(struct sockaddr *)&g_peer_addr, sizeof(g_peer_addr));
//		}
//		fprintf(stderr, "Notification sent to peer.\n");
//	}
//	if (g_pid_file)
//		unlink(g_pid_file);
//	exit(sig);
//}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

int main(int argc, char *argv[])
{
	const char *tun_ip_set = NULL, *tun_ip6_set = NULL;
	const char *loc_addr_pair = NULL;
	const char *peer_addr_pair = NULL;
	bool in_background = false;
	char cmd[100];
	int tunfd, opt;

	while ((opt = getopt(argc, argv, "s:r:l:a:A:m:t:n:o:p:S:e:Nvdh")) != -1) {
		switch (opt) {
		case 'l':
			loc_addr_pair = optarg;
			break;
		case 'r':
			peer_addr_pair = optarg;
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
			in_background = true;
			break;
		case 'h':
			print_help(argc, argv);
			exit(0);
			break;
		case '?':
			exit(1);
		}
	}

	if (strlen(g_devname) == 0)
		strcpy(g_devname, "p2p%d");
	if ((tunfd = tun_alloc(g_devname)) < 0) {
		fprintf(stderr, "*** open_tun() failed: %s.\n", strerror(errno));
		exit(1);
	}

	/* Configure IPv4 address for the interface. */
	if (tun_ip_set) {
		char s_lip[20], s_rip[20], *sp;
		struct in_addr raddr;
		int na = 0;

		if (!(sp = strchr(tun_ip_set, '/'))) {
			fprintf(stderr, "*** Invalid P-t-P IP pair: %s.\n", tun_ip_set);
			exit(1);
		}
		strncpy(s_lip, tun_ip_set, sp - tun_ip_set);
		s_lip[sp - tun_ip_set] = '\0';
		sp++;
		strncpy(s_rip, sp, sizeof(s_rip));
		s_rip[sizeof(s_rip) - 1] = '\0';

		if (!inet_pton(AF_INET, s_lip, &raddr)) {
			fprintf(stderr, "*** Invalid local IPv4 address: %s.\n", s_lip);
			exit(1);
		}
		if (inet_pton(AF_INET, s_rip, &raddr)) {
			sprintf(cmd, "ifconfig %s %s pointopoint %s", g_devname, s_lip, s_rip);
		} else if (sscanf(s_rip, "%d", &na) == 1 && na > 0 && na < 31 ) {
			uint32_t mask = ~((1 << (32 - na)) - 1);
			sprintf(s_rip, "%u.%u.%u.%u", mask >> 24, (mask >> 16) & 0xff,
					(mask >> 8) & 0xff, mask & 0xff);
			sprintf(cmd, "ifconfig %s %s netmask %s", g_devname, s_lip, s_rip);
		} else {
			fprintf(stderr, "*** Not a legal netmask or prefix length: %s.\n",
					s_rip);
			exit(1);
		}
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

	if (g_crypto_passwd) {
		gen_encrypt_key(&g_encrypt_key, g_crypto_passwd);
		gen_decrypt_key(&g_decrypt_key, g_crypto_passwd);
	} else {
		fprintf(stderr, "*** WARNING: Transmission will not be encrypted.\n");
	}

	/* Run in background. */
	if (in_background)
		do_daemonize();

	if (g_pid_file) {
		FILE *fp;
		if ((fp = fopen(g_pid_file, "w"))) {
			fprintf(fp, "%d\n", (int)getpid());
			fclose(fp);
		}
	}

	if (loc_addr_pair) {
		run_server(tunfd, loc_addr_pair);
	} else if (peer_addr_pair) {
		run_client(tunfd, peer_addr_pair);
	} else {
		fprintf(stderr, "*** No valid local or peer address specified.\n");
		exit(1);
	}

	return 0;
}

