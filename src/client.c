/*
 * Copyright (c) 2015 Justin Liu
 * Author: Justin Liu <rssnsj@gmail.com>
 * https://github.com/rssnsj/minivtun
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#include "minivtun.h"

static void handle_link_up(void)
{
	struct vt_route *rt;

	syslog(LOG_INFO, "Link is up.");

	ip_link_set_updown(config.ifname, true);

	/* Add IPv4 address if possible */
	ip_addr_add_ipv4(config.ifname, &config.tun_in_local,
			&config.tun_in_peer, config.tun_in_prefix);

	/* Add IPv6 address if possible */
	ip_addr_add_ipv6(config.ifname, &config.tun_in6_local,
			config.tun_in6_prefix);

	if (!config.tap_mode) {
		/* Attach the dynamic routes */
		for (rt = config.vt_routes; rt; rt = rt->next) {
			ip_route_add_ipvx(config.ifname, rt->af, &rt->network, rt->prefix,
				config.vt_metric, config.vt_table[0] ? config.vt_table : NULL);
		}
	}
}

static void handle_link_down(void)
{
	syslog(LOG_INFO, "Link is down.");

	ip_link_set_updown(config.ifname, false);
}

static int network_receiving(void)
{
	char read_buffer[NM_PI_BUFFER_SIZE], crypt_buffer[NM_PI_BUFFER_SIZE];
	struct minivtun_msg *nmsg;
	struct tun_pi pi;
	void *out_data;
	size_t ip_dlen, out_dlen;
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

	state.last_recv = __current;

	/* Call link-up scripts */
	if (!state.is_link_ok) {
		if (config.dynamic_link)
			handle_link_up();
		state.is_link_ok = true;
	}

	switch (nmsg->hdr.opcode) {
	case MINIVTUN_MSG_IPDATA:
		if (config.tap_mode) {
			/* No ethernet packet is shorter than 12 bytes. */
			if (out_dlen < MINIVTUN_MSG_IPDATA_OFFSET + 12)
				return 0;
			ip_dlen = out_dlen - MINIVTUN_MSG_IPDATA_OFFSET;
			nmsg->ipdata.proto = 0;
		} else {
			if (nmsg->ipdata.proto == htons(ETH_P_IP)) {
				/* No valid IP packet is shorter than 20 bytes. */
				if (out_dlen < MINIVTUN_MSG_IPDATA_OFFSET + 20)
					return 0;
			} else if (nmsg->ipdata.proto == htons(ETH_P_IPV6)) {
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

		pi.flags = 0;
		pi.proto = nmsg->ipdata.proto;
		osx_ether_to_af(&pi.proto);
		iov[0].iov_base = &pi;
		iov[0].iov_len = sizeof(pi);
		iov[1].iov_base = (char *)nmsg + MINIVTUN_MSG_IPDATA_OFFSET;
		iov[1].iov_len = ip_dlen;
		rc = writev(state.tunfd, iov, 2);
		break;
	case MINIVTUN_MSG_ECHO_ACK:
		if (state.has_pending_echo && nmsg->echo.id == state.pending_echo_id) {
			state.last_echo_recv = __current;
			state.total_echo_rcvd++;
			state.total_rtt_ms += __sub_timeval_ms(&__current, &state.last_echo_sent);
			state.has_pending_echo = false;
		}
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
	int rc;

	rc = read(state.tunfd, pi, NM_PI_BUFFER_SIZE);
	if (rc < sizeof(struct tun_pi))
		return -1;

	osx_af_to_ether(&pi->proto);

	ip_dlen = (size_t)rc - sizeof(struct tun_pi);

	if (config.tap_mode) {
		if (ip_dlen < 12)
			return 0;
	} else {
		/* We only accept IPv4 or IPv6 frames. */
		if (pi->proto == htons(ETH_P_IP)) {
			if (ip_dlen < 20)
				return 0;
		} else if (pi->proto == htons(ETH_P_IPV6)) {
			if (ip_dlen < 40)
				return 0;
		} else {
			syslog(LOG_WARNING, "*** Invalid protocol: 0x%x.", ntohs(pi->proto));
			return 0;
		}
	}

	memset(&nmsg.hdr, 0x0, sizeof(nmsg.hdr));
	nmsg.hdr.opcode = MINIVTUN_MSG_IPDATA;
	nmsg.hdr.seq = htons(state.xmit_seq++);
	memcpy(nmsg.hdr.auth_key, config.crypto_key, sizeof(nmsg.hdr.auth_key));
	nmsg.ipdata.proto = pi->proto;
	nmsg.ipdata.ip_dlen = htons(ip_dlen);
	memcpy(nmsg.ipdata.data, pi + 1, ip_dlen);

	/* Do encryption. */
	out_data = crypt_buffer;
	out_dlen = MINIVTUN_MSG_IPDATA_OFFSET + ip_dlen;
	local_to_netmsg(&nmsg, &out_data, &out_dlen);

	(void)send(state.sockfd, out_data, out_dlen, 0);

	return 0;
}

static void do_an_echo_request(void)
{
	char in_data[64], crypt_buffer[64];
	struct minivtun_msg *nmsg = (struct minivtun_msg *)in_data;
	void *out_msg;
	size_t out_len;
	__be32 r = rand();

	memset(nmsg, 0x0, sizeof(nmsg->hdr) + sizeof(nmsg->echo));
	nmsg->hdr.opcode = MINIVTUN_MSG_ECHO_REQ;
	nmsg->hdr.seq = htons(state.xmit_seq++);
	memcpy(nmsg->hdr.auth_key, config.crypto_key, sizeof(nmsg->hdr.auth_key));
	if (!config.tap_mode) {
		nmsg->echo.loc_tun_in = config.tun_in_local;
		nmsg->echo.loc_tun_in6 = config.tun_in6_local;
	}
	nmsg->echo.id = r;

	out_msg = crypt_buffer;
	out_len = MINIVTUN_MSG_BASIC_HLEN + sizeof(nmsg->echo);
	local_to_netmsg(nmsg, &out_msg, &out_len);

	(void)send(state.sockfd, out_msg, out_len, 0);

	state.has_pending_echo = true;
	state.pending_echo_id = r; /* must be checked on ECHO_ACK */
	state.total_echo_sent++;
}

static void reset_health_assess_data(void)
{
	state.has_pending_echo = false;
	state.pending_echo_id = 0;

	state.total_echo_sent = 0;
	state.total_echo_rcvd = 0;
	state.total_rtt_ms = 0;
}

static void reset_state_on_reconnect(void)
{
	struct timeval __current;
	gettimeofday(&__current, NULL);
	state.xmit_seq = (__u16)rand();
	state.last_recv = __current;
	state.last_echo_recv = __current;
	state.last_echo_sent = (struct timeval) { 0, 0 }; /* trigger the first echo */
	state.last_health_assess = __current;
	reset_health_assess_data();
}

static bool do_link_health_assess(void)
{
	unsigned loss = state.total_echo_sent > 0 ?
		((state.total_echo_sent - state.total_echo_rcvd) * 100 / state.total_echo_sent) : 0;
	unsigned rtt = state.total_echo_rcvd > 0 ?
		(unsigned)(state.total_rtt_ms / state.total_echo_rcvd) : 0;

	/* Write into file */
	if (config.health_file) {
		FILE *fp;
		remove(config.health_file);
		if ((fp = fopen(config.health_file, "w"))) {
			fprintf(fp, "%u,%u,%u,%u\n", state.total_echo_sent, state.total_echo_rcvd,
					loss, rtt);
			fclose(fp);
		}
	} else {
		syslog(LOG_INFO, "Sent: %u, received: %u, loss: %u%%, average RTT: %u",
				state.total_echo_sent, state.total_echo_rcvd, loss, rtt);
	}

	reset_health_assess_data();

	/* FIXME: return an effective health state */
	return true;
}

int run_client(const char *peer_addr_pair)
{
	char s_peer_addr[50];
	struct timeval startup_time;

	/* Remember the startup time for checking with 'config.exit_after' */
	gettimeofday(&startup_time, NULL);

	/* Dynamic link mode */
	state.is_link_ok = false;
	if (config.dynamic_link)
		ip_link_set_updown(config.ifname, false);

	if ((state.sockfd = resolve_and_connect(peer_addr_pair, &state.peer_addr)) >= 0) {
		/* DNS resolve OK, start service normally */
		reset_state_on_reconnect();
		inet_ntop(state.peer_addr.sa.sa_family, addr_of_sockaddr(&state.peer_addr),
				s_peer_addr, sizeof(s_peer_addr));
		printf("Mini virtual tunneling client to %s:%u, interface: %s.\n",
				s_peer_addr, ntohs(port_of_sockaddr(&state.peer_addr)), config.ifname);
	} else if (state.sockfd == -EAGAIN && config.wait_dns) {
		/* Connect later (state.sockfd < 0) */
		gettimeofday(&state.last_health_assess, NULL);
		printf("Mini virtual tunneling client, interface: %s. \n", config.ifname);
		printf("WARNING: Connection to '%s' temporarily unavailable, "
				"to be retried later.\n", peer_addr_pair);
	} else if (state.sockfd == -EINVAL) {
		fprintf(stderr, "*** Invalid address pair '%s'.\n", peer_addr_pair);
		return -1;
	} else {
		fprintf(stderr, "*** Unable to connect to '%s'.\n", peer_addr_pair);
		return -1;
	}

	if (config.exit_after)
		printf("NOTICE: This client will exit autonomously in %u seconds.\n", config.exit_after);

	/* Run in background */
	if (config.in_background)
		do_daemonize();

	if (config.pid_file) {
		FILE *fp;
		if ((fp = fopen(config.pid_file, "w"))) {
			fprintf(fp, "%d\n", (int)getpid());
			fclose(fp);
		}
	}

	for (;;) {
		fd_set rset;
		struct timeval __current, timeo;
		int rc;

		FD_ZERO(&rset);
		FD_SET(state.tunfd, &rset);
		if (state.sockfd >= 0)
			FD_SET(state.sockfd, &rset);

		timeo = (struct timeval) { 1, 0 };
		rc = select((state.tunfd > state.sockfd ? state.tunfd : state.sockfd) + 1,
				&rset, NULL, NULL, &timeo);
		if (rc < 0) {
			fprintf(stderr, "*** select(): %s.\n", strerror(errno));
			return -1;
		}

		gettimeofday(&__current, NULL);

		/* Date corruption check */
		if (timercmp(&state.last_recv, &__current, >))
			state.last_recv = __current;
		if (timercmp(&state.last_echo_sent, &__current, >))
			state.last_echo_sent = __current;
		if (timercmp(&state.last_echo_recv, &__current, >))
			state.last_echo_recv = __current;

		/* Command line requires an "exit after N seconds" */
		if (config.exit_after && __sub_timeval_ms(&__current, &startup_time)
				>= config.exit_after * 1000) {
			syslog(LOG_INFO, "User sets a force-to-exit after %u seconds. Exited.",
					config.exit_after);
			exit(0);
		}

		/* Calculate packet loss and RTT for a link health assess */
		if (__sub_timeval_ms(&__current, &state.last_health_assess)
				>= config.health_assess_timeo * 1000) {
			state.last_health_assess = __current;
			if (!do_link_health_assess())
				goto reconnect;
		}

		/* Start an echo test */
		if (state.sockfd >= 0 && __sub_timeval_ms(&__current, &state.last_echo_sent)
				>= config.keepalive_timeo * 1000) {
			do_an_echo_request();
			state.last_echo_sent = __current;
		}

		/* Connection timed out, try to reconnect */
		if (state.sockfd < 0 || __sub_timeval_ms(&__current, &state.last_echo_recv)
				>= config.reconnect_timeo * 1000) {
reconnect:
			/* Call link-down scripts */
			if (state.is_link_ok) {
				if (config.dynamic_link)
					handle_link_down();
				state.is_link_ok = false;
			}
			/* Reopen socket for a different local port */
			if (state.sockfd >= 0)
				close(state.sockfd);
			if ((state.sockfd = resolve_and_connect(peer_addr_pair, &state.peer_addr)) < 0) {
				fprintf(stderr, "Unable to connect to '%s', retrying.\n", peer_addr_pair);
				sleep(5);
				goto reconnect;
			}
			reset_state_on_reconnect();
			inet_ntop(state.peer_addr.sa.sa_family, addr_of_sockaddr(&state.peer_addr),
					s_peer_addr, sizeof(s_peer_addr));
			syslog(LOG_INFO, "Reconnected to %s:%u.", s_peer_addr,
					ntohs(port_of_sockaddr(&state.peer_addr)));
			continue;
		}

		if (state.sockfd >= 0 && FD_ISSET(state.sockfd, &rset)) {
			rc = network_receiving();
		}

		if (FD_ISSET(state.tunfd, &rset)) {
			rc = tunnel_receiving();
			assert(rc == 0);
		}
	}

	return 0;
}
