# minivtun
A fast secure and reliable VPN service in non-standard protocol for rapidly deploying VPN servers/clients or getting through firewalls

### Key features
* Fast: direct UDP-encapsulated without complex authentication handshakes.
* Secure: both header and tunnel data are encrypted, which is impossible to be tracked by protocol characteristics and blocked, unless all UDP ports are blocked by your firewall; spoofed packets from unauthorized peer are dropped immediately.
* Reliable: communication recovers immediately from next received packet from client after the previous session was dead, which makes the connection extremely reliable.
* Rapid to deploy: a standalone program to run; all configuration are specified in command line with very few options.


### Installation for Linux

Install required development components

    sudo apt-get install build-essential libssl-dev   # for Ubuntu / Debian
    sudo yum install make gcc openssl-devel   # for CentOS / Fedora / RedHat
  
Compile and install

    git clone https://github.com/rssnsj/minivtun.git minivtun
    cd minivtun/src
    make
    sudo make install

### Installation for Mac OS X

Install TUNTAP driver for Mac OS X: http://tuntaposx.sourceforge.net/

Compile and install

    git clone https://github.com/rssnsj/minivtun.git minivtun
    cd minivtun/src
    make
    sudo make install

### Usage

	Mini virtual tunneller in non-standard protocol.
	Usage:
	  minivtun [options]
	Options:
	  -l, --local <ip:port>               IP:port for server to listen
	  -r, --remote <ip:port>              IP:port of server to connect
	  -a, --ipv4-addr <tun_lip/tun_rip>   pointopoint IPv4 pair of the virtual interface
					  <tun_lip/pfx_len>   IPv4 address/prefix length pair
	  -A, --ipv6-addr <tun_ip6/pfx_len>   IPv6 address/prefix length pair
	  -m, --mtu <mtu>                     set MTU size, default: 1416.
	  -t, --keepalive <keepalive_timeo>   interval of keep-alive packets, default: 13
	  -n, --ifname <ifname>               virtual interface name
	  -p, --pidfile <pid_file>            PID file of the daemon
	  -e, --key <encryption_key>          shared password for data encryption
	  -v, --route <network/prefix=gateway>
	                                      route a network to a client address, can be multiple
	  -w, --wait-dns                      wait for DNS resolve ready after service started.
	  -d, --daemon                        run as daemon process
	  -h, --help                          print this help

### Examples

Server: Run a VPN server on port 1414, with local virtual address 10.7.0.1, client address space 10.7.0.0/24, encryption password 'Hello':

    /usr/sbin/minivtun -l 0.0.0.0:1414 -a 10.7.0.1/24 -e Hello -d

Client: Connect VPN to the above server (assuming address vpn.abc.com), with local virtual address 10.7.0.33:

    /usr/sbin/minivtun -r vpn.abc.com:1414 -a 10.7.0.33/24 -e Hello -d

Multiple clients on different devices can be connected to the same server:

    /usr/sbin/minivtun -r vpn.abc.com:1414 -a 10.7.0.34/24 -e Hello -d
    /usr/sbin/minivtun -r vpn.abc.com:1414 -a 10.7.0.35/24 -e Hello -d
    /usr/sbin/minivtun -r vpn.abc.com:1414 -a 10.7.0.36/24 -e Hello -d
    ...

### Diagnoses

None.