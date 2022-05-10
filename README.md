<!--
Copyright (c) 2022 Vít Labuda. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
following conditions are met:
 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
    disclaimer.
 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
    following disclaimer in the documentation and/or other materials provided with the distribution.
 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
    products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-->

# Tundra-NAT64
**Tundra-NAT64** is an open-source **stateless NAT64 and CLAT implementation for Linux** which operates entirely in user-space, 
can run in **multiple threads** (and thus make use of today's modern multicore CPUs) and uses either the TUN driver or 
inherited file descriptors to receive and send packets. It is written in pure C and translates packets from IPv6 to 
IPv4 and vice versa according to [RFC 7915](https://datatracker.ietf.org/doc/html/rfc7915) *(SIIT – Stateless IP/ICMP 
Translation Algorithm)*.

The stateless NAT64/CLAT translator offered by Tundra focuses on being minimal – features which are not necessary for 
SOHO-grade NAT64/CLAT service are often omitted, and so are features which can be substituted by something else. One of the
consequences of this design approach is that the program does not allocate any extra memory after it initializes.

Probably the most significant trait of this program, which makes it different from other NAT64/CLAT implementations, is 
that Tundra itself cannot act as a NAT64/CLAT translator for more than one host, as it lacks an internal dynamic address 
pool from which it would assign IP addresses to hosts needing its service (or something similar) – it uses a fixed 
single IP address specified in a configuration file instead (see the [example config file](tundra-nat64.conf.example) 
for details). However, it can be used in cooperation with **Linux's in-kernel NAT66/NAT44** translator and therefore 
translate traffic from any number of hosts/networks, as is described in the 
[example config file](tundra-nat64.conf.example) and shown (for NAT64) in the [deployment example](#deployment-example) 
below.

Tundra is similar to [TAYGA](http://www.litech.org/tayga/) (another stateless out-of-kernel NAT64 implementation, which 
can act as a CLAT translator in cooperation with [clatd](https://github.com/toreanderson/clatd)), but there are some 
differences. Tundra is multi-threaded, it can receive and send packets from inherited file descriptors and lacks the 
aforementioned dynamic address pool. TAYGA also inspired this program's name - both "taiga" and "tundra" are subarctic 
biomes and the word "tundra" starts with "tun", the name of the driver which Tundra uses to exchange packets.



## Build
Since Tundra has no dependencies other than Linux's standard C library and `libpthread`, it can be compiled by a single 
command and without the use of a build system: 
```shell
gcc -Wall -pthread -std=c11 -O3 -flto -o tundra-nat64 src/t64_*.c
```
Both `gcc` and `clang` may be used to compile the program.



## Configuration & usage

### Configuration file
Tundra loads its settings from a configuration file. This repository contains a sample configuration file with 
**detailed comments**: [tundra-nat64.conf.example](tundra-nat64.conf.example).

### Command-line parameters
The output of `./tundra-nat64 --help` is as follows:
```
Usage: ./tundra-nat64 [OPTION]... [MODE_OF_OPERATION]

Options:
  -h, --help
    Prints help and exits.
  -v, --version
    Prints version information and exits.
  -l, --license
    Prints license and exits.
  -c, --config-file=CONFIG_FILE_PATH
    Specifies the file from which the program's configuration will be loaded.
    DEFAULT: /etc/tundra-nat64/tundra-nat64.conf
    NOTE: To load the configuration from standard input, specify '/dev/stdin' as the config file path.
  -f, --inherited-fds=THREAD1_IN,THREAD1_OUT[;THREAD2_IN,THREAD2_OUT]...
    Specifies the file descriptors to be used in the 'inherited-fds' I/O mode. Ignored otherwise.

Modes of operation:
  translate
    The program will act as a stateless NAT64 translator.
    This is the default mode of operation.
  mktun
    Creates a persistent TUN device according to the configuration file, then exits.
    Applicable only in the 'tun' I/O mode.
  rmtun
    Destroys a previously created persistent TUN device according to the configuration file, then exits.
    Applicable only in the 'tun' I/O mode.
  validate-config
    Tries to configure the program and prints an informational message if it succeeds, then exits.
  print-config
    Prints the program's configuration in a human-readable format, then exits.
```

### Deployment example
The following example shows how Tundra could be deployed as **NAT64 translator** for an IPv6-only network with the use 
of the [example configuration file](tundra-nat64.conf.example) on a router which has access to both IPv4 and IPv6:
```shell
TUNDRA_CONFIG_FILE="./tundra-nat64.conf.example"
WAN_INTERFACE_NAME="eth0"  # Remember to adjust this!

# Create a new TUN network interface
./tundra-nat64 --config-file=$TUNDRA_CONFIG_FILE mktun

# Set up the TUN interface
ip link set dev tundra up
ip addr add 192.168.64.254/24 dev tundra  # The IP address should be different from 'translator.ipv4' and 'router.ipv4'!
ip -6 addr add fd00:6464::fffe/64 dev tundra  # The IP address should be different from 'translator.ipv6' and 'router.ipv6'!
ip -6 route add 64:ff9b::/96 dev tundra
ip6tables -t nat -A POSTROUTING -d 64:ff9b::/96 -o tundra -j SNAT --to-source=fd00:6464::2  # On some kernels, the support for NAT66 may need to be installed as a module
iptables -t nat -A POSTROUTING -o $WAN_INTERFACE_NAME -j MASQUERADE  # Perform NAT44 on all packets going to the internet, including the ones generated by Tundra

# Start the NAT64 translator (to terminate it, send SIGTERM, SIGINT or SIGHUP to the process)
./tundra-nat64 --config-file=$TUNDRA_CONFIG_FILE translate

# After the translator has terminated, remove the previously added NAT rules...
ip6tables -t nat -D POSTROUTING -d 64:ff9b::/96 -o tundra -j SNAT --to-source=fd00:6464::2
iptables -t nat -D POSTROUTING -o $WAN_INTERFACE_NAME -j MASQUERADE

# ... and remove the TUN interface
./tundra-nat64 --config-file=$TUNDRA_CONFIG_FILE rmtun
```

#### DNS64
To make hosts on IPv6-only networks use the NAT64 translator to access IPv4-only services, you will need to provide them
with a **DNS64** recursive resolver. You can either deploy your own one (all major recursive DNS servers, such as 
[Unbound](https://github.com/NLnetLabs/unbound/blob/master/doc/README.DNS64) or 
[Knot Resolver](https://knot-resolver.readthedocs.io/en/stable/modules-dns64.html), nowadays support DNS64 natively),
or, if your NAT64 deployment uses the well-known prefix of `64:ff9b::/96`, use a **public DNS64 resolver**, such as the 
one provided by [Google](https://developers.google.com/speed/public-dns/docs/dns64) or 
[Cloudflare](https://developers.cloudflare.com/1.1.1.1/infrastructure/ipv6-networks/).



## Licensing
This project is licensed under the **3-clause BSD license** – see the [LICENSE](LICENSE) file.

Programmed by **[Vít Labuda](https://vitlabuda.cz/)**.
