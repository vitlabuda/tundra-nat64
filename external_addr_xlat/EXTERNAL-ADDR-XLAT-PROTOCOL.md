# Tundra-NAT64 external address translation protocol specification 





## 1 Introduction
[Tundra-NAT64](https://github.com/vitlabuda/tundra-nat64) offers the ability to delegate address translation to
another program–server, with which it communicates via inherited file descriptors, Unix stream sockets or TCP.
After setting the `addressing.mode` option in Tundra's configuration file to `external` and configuring other necessary
options as documented in the [example configuration file](../tundra-nat64.example.conf), the program will translate
packets from IPv4 to IPv6 and vice versa as per the rules of SIIT (Stateless IP/ICMP Translation Algorithm, see 
[RFC 7915](https://datatracker.ietf.org/doc/html/rfc7915)) while querying the external address translator for IP 
addresses to be put in the translated packets. This querying is done using the protocol described in this document.





## 2 Message structure specification
When Tundra translates a packet, it sends exactly one _request_ message, to which the external translator MUST reply
by sending exactly one _response_ message back to Tundra. Both of these messages are exactly **40 bytes** (= 40 octets 
= 320 bits) in size and have the same structure:

```text
+---------+------+---------------+---------------+---------------+---------------+
| OFFSETS | Byte |       0       |       1       |       2       |       3       |
+---------+------+---------------+---------------+---------------+---------------+
|  Byte   | Bit  |0|1|2|3|4|5|6|7|0|1|2|3|4|5|6|7|0|1|2|3|4|5|6|7|0|1|2|3|4|5|6|7|
+---------+------+---------------+---------------+---------------+---------------+
|    0    |  0   |   Magic byte  | Proto version |R|E|I| Msg type| Cache lifetime|
+---------+------+---------------+---------------+---------------+---------------+
|    4    |  32  |                       Message identifier                      |
+---------+------+---------------+---------------+---------------+---------------+
|    8    |  64  |                                                               |
|    12   |  96  |                       Source IP address                       |
|    16   |  128 |                                                               |
|    20   |  160 |                                                               |
+---------+------+---------------+---------------+---------------+---------------+
|    24   |  192 |                                                               |
|    28   |  224 |                     Destination IP address                    |
|    32   |  256 |                                                               |
|    36   |  288 |                                                               |
+---------+------+---------------+---------------+---------------+---------------+

(R = Response bit; E = Error bit; I = ICMP bit)
```


- **Magic byte** (1 byte)  
  Must be of the value `84` = `0x54` = ASCII `'T'`.


- **Protocol version** (1 byte)  
  Specifies the version of this protocol. As of now, it must be of the value `1`.


- **Response bit** (1 bit)  
  `1` means that the message is a response, `0` means that it is a request. Therefore, messages sent from Tundra to
  an external address translator do not have this bit set, whereas messages going the other way MUST have it set.


- **Error bit** (1 bit)  
  May be set only in _response_ messages, i.e. when the _response bit_ is set. `1` means that the external address
  translator failed to translate the IP address pair submitted in the corresponding _request_ message, to which 
  Tundra reacts by dropping the packet, if the _ICMP bit_ is not set (see below). `0` means that the translation
  was successful.


- **ICMP bit** (1 bit)  
  May be set only in erroneous _response_ messages of type **4TO6_MAIN_PACKET** or **6TO4_MAIN_PACKET**, i.e. when both 
  the _response bit_ and the _error bit_ are set and the _message type_ is either `1` or `3`.
  `1` means that Tundra will react to the address translation failure by sending an ICMPv4 `Destination Host
  Unreachable` or ICMPv6 `Address Unreachable` to the inbound packet's source host, whereas `0` means that the packet
  will simply be dropped.


- **Message type** (5 bits)  
  The following values are defined:
  - `1` = **4TO6_MAIN_PACKET**
  - `2` = **4TO6_ICMP_ERROR_PACKET** (ICMP error packet = packet "in error" carried inside an ICMP error message's body)
  - `3` = **6TO4_MAIN_PACKET**
  - `4` = **6TO4_ICMP_ERROR_PACKET** (ICMP error packet = packet "in error" carried inside an ICMP error message's body)

  The value must be the same for a _request_ message and the corresponding _response_ message.


- **Cache lifetime** (1 byte)  
  Specifies for how many seconds at maximum _may_ Tundra cache the IP address pair from a successful _response_ message.
  `0` means that the response will not be cached. Since the lifetime is represented by a 1-byte unsigned integer, the 
  maximum value is `255` seconds = 4 minutes 15 seconds.


- **Message identifier** (4 bytes)  
  A pseudo-random identifier which must be the same for a _request_ message and the corresponding _response_ message.


- **Source IP address** (16 bytes) & **Destination IP address** (16 bytes)  
  In case the _message type_ is either **4TO6_MAIN_PACKET** or **4TO6_ICMP_ERROR_PACKET**, a _request_ message 
  contains the source & destination IPv4 address to be translated by the external address translator in the first 4 
  bytes, and the corresponding successful _response_ message MUST contain the translated source & destination IPv6 
  address to be put in the translated (outbound) packet.

  In case the _message type_ is either **6TO4_MAIN_PACKET** or **6TO4_ICMP_ERROR_PACKET**, a _request_ message 
  contains the source & destination IPv6 address to be translated by the external address translator, and the 
  corresponding successful _response_ message MUST contain the translated source & destination IPv4 address in the 
  first 4 bytes to be put in the translated (outbound) packet.

  Due to both the fields being 16 bytes in size, when a 4-byte IPv4 address is placed inside them, it MUST be placed 
  in the first 4 bytes of the field, and the remaining 12 bytes MUST be zeroed out.


NOTE: If a value of a field in certain types of messages is not explicitly defined in the above text (e.g. what value 
should _cache lifetime_ be of in case of a _request_ message, or what addresses should the IP address fields contain
in case of an erroneous _response_ message), the field MUST be zeroed out.





## 3 Tundra-NAT64's implementation details


### 3.1 Connection establishment
Each translator thread holds and manages its own connection to an external address translator. If the transport is set 
to `unix` or `tcp`, each thread establishes the connection when it receives its first packet for translation. This
means that translator threads which are completely "inactive" will not hold unnecessary connections. However, it also
means that the connections are always established after the program initializes, i.e. after it changes its working 
directory to `/` and drops its privileges, if it is configured to do so.

If the `inherited-fds` transport is configured to be used, the file descriptors are extracted from the 
`addressing-external-inherited-fds` command-line argument and checked whether they are valid during initialization, 
i.e. before translator threads are started.


### 3.2 Sending & receiving data
When Tundra sends/receives messages to/from the sockets/inherited file descriptors, it uses the `write()` and `read()`
functions in a loop, i.e. a single call to these functions need not send or receive a whole message. As a result,
when using the `inherited-fds` transport, the file descriptors should be referring to a "stream" communication channel, 
for example a `pipe()` or a `SOCK_STREAM` socket.


### 3.3 Protocol & transmission error handling
When a protocol (e.g. a _response_ message with invalid contents is received) or transmission (e.g. the connection 
to an external address translator times out, or it cannot be established) error occurs, Tundra closes the connection's 
file descriptor(s) and drops the translated packet.

When a next packet requiring translation comes to Tundra, the connection to the external address translator is attempted
to be re-established if the `addressing.external.transport` option is set to `unix` or `tcp`; in case the transport is
set to `inherited-fds`, the program will crash, as it has no way of obtaining a new set of inherited file descriptors.





## 4 Implementations


### 4.1 Libraries
- **[tundra-xaxlib-python](https://github.com/vitlabuda/tundra-xaxlib-python)** (Python) – Enables one to easily parse 
  and construct wireformat messages used by this protocol in Python programs.


### 4.2 Programs
- **[Get4For6](https://github.com/vitlabuda/get4for6)** (Python, uses _tundra-xaxlib-python_) – An open-source 
  user-space NAT46 and DNS46 translator for Linux, whose main purpose is to enable internal IPv4-only hosts to 
  communicate with IPv6-only Internet hosts by providing a DNS forwarder/resolver which manipulates DNS queries and 
  answers from the internal IPv4-only hosts.


### 4.3 Examples
- **[tundra-xaxlib-python/examples/001_nat64.py](https://github.com/vitlabuda/tundra-xaxlib-python/blob/main/examples/001_nat64.py)**
  (Python, uses _tundra-xaxlib-python_) – An example external address translation server which works almost exactly the 
  same as Tundra-NAT64's built-in `nat64` addressing mode, i.e. it is able to, without the help of a NAT66, statelessly 
  translate packets from one source IPv6 to one source IPv4 and do the inverse process for packets going the other way.





## 5 Licensing & author
This project is licensed under the **3-clause BSD license** – see the [LICENSE](../LICENSE) file.

Created by **[Vít Labuda](https://vitlabuda.cz/)**.
