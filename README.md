# minivtun
A fast secure and reliable VPN service in non-standard protocol for rapidly deploying VPN servers/clients or getting through firewalls

### Key features
* Fast: direct UDP-encapsulated without complex authentication handshakes.
* Secure: both header and tunnel data are encrypted, which is impossible to be tracked by protocol characteristics and blocked, unless all UDP ports are blocked by your firewall; spoofed packets from unauthorized peer are dropped immediately.
* Reliable: communication recovers immediately from next received packet from client after the previous session was dead, which makes the connection extremely reliable.
* Rapid to deploy: a standalone program to run; all configuration are specified in command line with very few options.


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
      -t <keepalive_timeo>  seconds between sending keep-alive packets, default: 13
      -n <ifname>           tunnel interface name
      -p <pid_file>         PID file of the daemon
      -e <encrypt_key>      shared password for data encryption
      -N                    turn off encryption for tunnelling data
      -d                    run as daemon process
      -h                    print this help

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

If you run 'minivtun' server on a VPS (openvz, kvm, docker, ...), I recommend you to enlarge the server side MTU, e.g., 4000. This is because the physical host might enables segmentation offloadings which let your VPS receive large TCP packets (up to 3000 bytes). Since the feature is opened on the physical host, you cannot disable it. So the best way is to change your MTU by `-m 4000`.

    /usr/sbin/minivtun -l 0.0.0.0:1414 -a 10.7.0.1/24 -e Hello -d -m 4000
