# Tundra-NAT64
**Tundra** is an open-source SIIT (Stateless IP/ICMP Translation Algorithm – 
[RFC 7915](https://datatracker.ietf.org/doc/html/rfc7915)) implementation for Linux which can function as a NAT64 
translator in cooperation with Linux's in-kernel NAT44 and NAT66 translators. It runs entirely in user-space and
uses the TUN driver to receive and send packets.

Tundra is similar to [TAYGA](http://www.litech.org/tayga/) (another stateless out-of-kernel NAT64 implementation), but
it can, for example, make use of multiple CPU threads, and it uses Linux's NAT66 translator instead of mapping IPv6 
addresses to IPv4 addresses internally.



## Documentation
**TBD** (in the next few days – the program was finished on 2022-04-18)

Build:
```
clang -Wall -pthread -o tundra-nat64 src/*.c
```

Usage:
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
    Default: /etc/tundra-nat64/tundra-nat64.conf
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

Example configuration file: [tundra-nat64.conf](tundra-nat64.conf)



## Licensing
This project is licensed under the **3-clause BSD license** – see the [LICENSE](LICENSE) file.

Programmed by **[Vít Labuda](https://vitlabuda.cz/)**.
