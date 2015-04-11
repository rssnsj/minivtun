# minivtun
A fast secure VPN service in non-standard protocol for rapidly deploying VPN servers/clients or getting through firewalls

### Installation

    # Install required development components
    sudo apt-get install build-essential libssl-dev  # for Ubuntu
      
    # Compile and install
    git clone https://github.com/rssnsj/minivtun.git minivtun
    cd minivtun/src
    make
    make install

### Usage

    Mini virtual tunneller in non-standard protocol.
    Usage:
      minivtun [options]
    Options:
      -l <ip:port>          IP:port of local binding
      -r <ip:port>          IP:port of peer device
      -a <tun_lip/tun_rip>  tunnel IP pair
      -A <tun_ip6/pfx_len>  tunnel IPv6 address/prefix length pair
      -m <mtu>              set MTU size, default: 1408.
      -t <g_keepalive_timeo>  seconds between sending keep-alive packets, default: 13
      -n <ifname>           tunnel interface name
      -p <pid_file>         PID file of the daemon
      -e <g_encrypt_key>    shared password for data encryption
      -N                    turn off encryption for tunnelling data
      -d                    run as daemon process
      -h                    print this help

### Examples

Server: Run a VPN server on port 1414, with local virtual address 10.7.0.1, client address space 10.7.0.0/24, encryption password 'Hello':

    /usr/sbin/minivtun -l 0.0.0.0:1414 -a 10.7.0.1/24 -e Hello -d

Client: Connect VPN to the above server (assuming address vpn.abc.com), with local virtual address 10.7.0.33:

    /usr/sbin/minivtun -r vpn.abc.com:1414 -a 10.7.0.33/24 -e Hello -d


