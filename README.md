<!--
Copyright (c) 2024 Vít Labuda. All rights reserved.

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

**Tundra-NAT64** is an open-source **IPv6-to-IPv4 & IPv4-to-IPv6 translator for Linux** which operates 
entirely in user-space, can run in multiple threads (and thus make use of today's modern multicore CPUs) and uses 
either the TUN driver or inherited file descriptors to receive and send packets. It is written in pure C and translates 
packets according to the rules of **SIIT** (_Stateless IP/ICMP Translation Algorithm_; 
[RFC 7915](https://datatracker.ietf.org/doc/html/rfc7915)), while offering the following **configurable address 
translation modes**:

- **Stateless NAT64** – In this mode, Tundra is making it possible for a single host, or, in cooperation with Linux's 
  in-kernel NAT66 translator (as described below), for any number of hosts on an IPv6-only network to access IPv4-only 
  hosts.

- **Stateless CLAT** – In this mode, Tundra is making it possible for programs using IPv4-only sockets (`AF_INET`) to
  access IPv4-only hosts when running on a computer connected to an IPv6-only network with a NAT64 service. In addition,
  when running on a router which is connected to the outside world over an IPv6-only network with a NAT64 service,
  Tundra may be used to create a dual-stack internal network in cooperation with Linux's in-kernel NAT44 translator.

- **SIIT** – In this mode, Tundra is translating IPv6 packets whose addresses are composed of an IPv4 address wrapped
  inside a translation prefix into IPv4 packets with the same IPv4 addresses (extracted from the aforementioned prefix),
  and vice versa.

- **External** – In this mode, Tundra delegates address translation to another program–server, with which it
  communicates via inherited file descriptors, Unix stream sockets or TCP. Tundra will translate packets from IPv4 to 
  IPv6 and vice versa as per the rules of SIIT while querying an external address translator for IP addresses to be 
  put in the translated packets. The specification of the protocol which Tundra uses to communicate with the external 
  translator can be found in 
  [external_addr_xlat/EXTERNAL-ADDR-XLAT-PROTOCOL.md](external_addr_xlat/EXTERNAL-ADDR-XLAT-PROTOCOL.md).

More information about the aforementioned address translation modes (including how to configure them) can be found in 
relevant sections of the [example configuration file](tundra-nat64.example.conf).

The SIIT/NAT64/CLAT translator offered by Tundra focuses on being minimal – features which are not necessary for 
SOHO-grade SIIT/NAT64/CLAT service are often omitted, and so are features which can be substituted by something else. 
One of the consequences of this design approach is that the program does not allocate any extra memory after it 
initializes.

Probably the most significant trait of this program, which makes it different from other NAT64/CLAT implementations, is 
that Tundra itself cannot act as a NAT64/CLAT translator for more than one host, as it lacks an internal dynamic address 
pool (or something similar) from which it would assign IP addresses to hosts needing its service – it uses a fixed 
single IP address specified in a configuration file instead (see the [example config file](tundra-nat64.example.conf) 
for details). However, it can be used in cooperation with **Linux's in-kernel NAT66/NAT44** translator and therefore 
translate traffic from any number of hosts/networks.

Tundra is, in certain aspects, similar to [TAYGA](http://www.litech.org/tayga/) (another stateless out-of-kernel NAT64 
implementation, which can act as a CLAT translator in cooperation with [clatd](https://github.com/toreanderson/clatd)), 
but there are some differences. Tundra is multi-threaded, has configurable address translation modes (including the 
non-traditional `external` mode), can receive and send packets from inherited file descriptors, and lacks the 
aforementioned dynamic address pool. TAYGA also inspired this program's name - both "taiga" and "tundra" are subarctic 
biomes and the word "tundra" starts with "tun", the name of the driver which Tundra uses to exchange packets.

The reason why this program is named _Tundra-NAT64_ despite it offering other address translation modes than just NAT64
is that originally, it was meant to be only a stateless NAT64 translator and the other modes were added later. Since
rebranding it would be quite difficult and could cause certain problems (due to, for example, permalinks pointing to 
this Git repository whose name/URL contains the `nat64`), I decided not to do it.

Tundra was the subject of a Czech-language talk I held at the 
[Seminář IPv6: deset let poté](https://www.cesnet.cz/akce/seminar-ipv6-deset-let-pote/) conference on the 6th June 2022 
in Prague – [presentation](https://www.cesnet.cz/wp-content/uploads/2022/06/Bezstavovy-NAT64_Vit-Labuda.pdf),
[video](https://www.youtube.com/watch?v=wnsD_W5ITbE). In addition, if you happen to be interested, you may have a look
at [this post](https://blog.vitlabuda.cz/2022/12/30/improving-tundras-speed-and-code-quality.html) on my 
English-language blog, in which the changes to this program made between the versions _4.1.6_ and _5.0.1_ are summed
up.





## Build
Tundra only depends on Linux's standard C library and `libpthread` - no other libraries are needed. The project uses 
**CMake** as its build system and **GCC** as its compiler. To build the program, run the following commands in the
repository's root directory:
```shell
CC=gcc cmake -S. -Bbuild
make -Cbuild
```
The resulting binary will be located at `./build/tundra-nat64`.





## Configuration & usage

### Configuration file
Tundra loads its settings from a configuration file. This repository contains a sample configuration file with 
**detailed comments**: [tundra-nat64.example.conf](tundra-nat64.example.conf).

### Command-line parameters
The output of `./tundra-nat64 --help` is as follows:
```text
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
    NOTE: To load the configuration from standard input, specify '-' as the config file path.
  -f, --io-inherited-fds=THREAD1_IN,THREAD1_OUT[;THREAD2_IN,THREAD2_OUT]...
    Specifies the file descriptors to be used in the 'inherited-fds' I/O mode. Ignored otherwise.
  -F, --addressing-external-inherited-fds=THREAD1_IN,THREAD1_OUT[;THREAD2_IN,THREAD2_OUT]...
    Specifies the file descriptors to be used for the 'inherited-fds' transport of the 'external' addressing mode. Ignored otherwise.

Modes of operation:
  translate
    The program will act as a stateless NAT64/CLAT translator.
    This is the default mode of operation.
  mktun
    Creates a persistent TUN device according to the configuration file, then exits.
    Applicable only in the 'tun' I/O mode.
  rmtun
    Destroys a previously created persistent TUN device according to the configuration file, then exits.
    Applicable only in the 'tun' I/O mode.
  validate-config
    Tries to configure the program and prints an informational message if it succeeds, then exits.
```

### Generic NAT64 configuration example
The following example shows how Tundra could be deployed as **NAT64 translator** for an IPv6-only network with the use 
of the [example configuration file](tundra-nat64.example.conf) on a router which has access to both IPv4 and IPv6:
```shell
TUNDRA_CONFIG_FILE="./tundra-nat64.example.conf"
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

### Specific configuration examples
This repository contains the following configuration examples for specific platforms and translation modes:
- **[OpenWRT + NAT64](config_examples/openwrt_nat64)** ([README with a step-by-step guide](config_examples/openwrt_nat64/README.md))
- **[Debian + CLAT](config_examples/debian_clat)** ([README with a step-by-step guide](config_examples/debian_clat/README.md))





## Licensing
This project is licensed under the **3-clause BSD license** – see the [LICENSE](LICENSE) file.

Programmed by **[Vít Labuda](https://vitlabuda.cz/)**.
