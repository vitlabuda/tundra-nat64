/*
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
*/

#include"t64_tundra.h"
#include"t64_utils_ip.h"

#include"t64_utils.h"


// Unusable IPv4 address blocks:
// - 0.0.0.0/8 (Current network)
// - 127.0.0.0/8 (Loopback)
// - 224.0.0.0/4 (Multicast)
// - 255.255.255.255/32 (Limited broadcast)
bool t64f_utils_ip__is_ipv4_address_unusable(const uint8_t *ipv4_address) {
    return (bool) (
        (*ipv4_address == 0) || // 0.0.0.0/8 (Current network)
        (*ipv4_address == 127) || // 127.0.0.0/8 (Loopback)
        (*ipv4_address >= 224 && *ipv4_address <= 239) || // 224.0.0.0/4 (Multicast)
        (T64M_UTILS__MEMORY_EQUAL(ipv4_address, "\xff\xff\xff\xff", 4)) // 255.255.255.255/32 (Limited broadcast)
    );
}

// Unusable IPv6 address blocks:
// - ::/128 (Unspecified address)
// - ::1/128 (Loopback)
// - ff00::/8 (Multicast)
bool t64f_utils_ip__is_ipv6_address_unusable(const uint8_t *ipv6_address) {
    return (bool) (
        (*ipv6_address == 255) || // ff00::/8 (Multicast)
        (T64M_UTILS__MEMORY_EQUAL(ipv6_address, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16)) || // ::/128 (Unspecified address)
        (T64M_UTILS__MEMORY_EQUAL(ipv6_address, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 16)) // ::1/128 (Loopback)
    );
}

bool t64f_utils_ip__is_ipv4_address_private(const uint8_t *ipv4_address) {
    return (bool) (
        (*ipv4_address == 0) || // 0.0.0.0/8
        (*ipv4_address == 10) || // 10.0.0.0/8
        (*ipv4_address == 100 && (ipv4_address[1] >= 64 && ipv4_address[1] <= 127)) || // 100.64.0.0/10
        (*ipv4_address == 127) || // 127.0.0.0/8
        (*ipv4_address == 169 && ipv4_address[1] == 254) || // 169.254.0.0/16
        (*ipv4_address == 172 && (ipv4_address[1] >= 16 && ipv4_address[1] <= 31)) || // 172.16.0.0/12
        (T64M_UTILS__MEMORY_EQUAL(ipv4_address, "\xc0\x00\x00", 3)) || // 192.0.0.0/24
        (T64M_UTILS__MEMORY_EQUAL(ipv4_address, "\xc0\x00\x02", 3)) || // 192.0.2.0/24
        (T64M_UTILS__MEMORY_EQUAL(ipv4_address, "\xc0\x58\x63", 3)) || // 192.88.99.0/24
        (*ipv4_address == 192 && ipv4_address[1] == 168) || // 192.168.0.0/16
        (*ipv4_address == 198 && (ipv4_address[1] == 18 || ipv4_address[1] == 19)) || // 198.18.0.0/15
        (T64M_UTILS__MEMORY_EQUAL(ipv4_address, "\xc6\x33\x64", 3)) || // 198.51.100.0/24
        (T64M_UTILS__MEMORY_EQUAL(ipv4_address, "\xcb\x00\x71", 3)) || // 203.0.113.0/24
        (*ipv4_address >= 224) // 224.0.0.0/4 & 240.0.0.0/4 (including 255.255.255.255/32)
    );
}

bool t64f_utils_ip__is_ipv4_embedded_ipv6_address_translatable(const t64ts_tundra__xlat_thread_context *context, const uint8_t *embedded_ipv4_address) {
    if(T64M_UTILS_IP__IPV4_ADDRESSES_EQUAL(embedded_ipv4_address, context->configuration->router_ipv4))
        return false; // Packets from/to the router are not translated

    if(T64M_UTILS_IP__IPV4_ADDRESSES_EQUAL(embedded_ipv4_address, context->configuration->translator_ipv4))
        return false; // Translator IPv4 address cannot be mapped inside prefix

    if(context->configuration->translator_allow_translation_of_private_ips) {
        if(t64f_utils_ip__is_ipv4_address_unusable(embedded_ipv4_address))
            return false;
    } else {
        if(t64f_utils_ip__is_ipv4_address_private(embedded_ipv4_address))
            return false;
    }

    return true;
}

bool t64f_utils_ip__is_ip_protocol_number_forbidden(const uint8_t ip_protocol_number) {
    // https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    return (bool) (
        (ip_protocol_number == 0) || // IPv6 Hop-by-Hop Option
        (ip_protocol_number == 2) || // IGMP (Internet Group Management Protocol)
        (ip_protocol_number == 43) || // Routing Header for IPv6
        (ip_protocol_number == 44) || // Fragment Header for IPv6
        (ip_protocol_number == 51) || // Authentication Header
        (ip_protocol_number == 60) || // Destination Options for IPv6
        (ip_protocol_number == 135) || // Mobility Header
        (ip_protocol_number == 139) || // Host Identity Protocol
        (ip_protocol_number == 140) // Shim6 Protocol
    );

    // ESP (50) is allowed
    //  (ip_protocol_number == 50) || // Encapsulating Security Payload
}

/*
 * The input IPv4 header must be fully complete and valid. This function does not perform boundary (or any other) checks!
 */
uint16_t t64f_utils_ip__calculate_ipv4_header_checksum(const struct iphdr *ipv4_header) {
    const uint16_t *header_16bit_words = (const uint16_t *) ipv4_header;
    const size_t header_16bit_word_count = (ipv4_header->ihl * 2);

    uint64_t header_checksum = 0;
    for(size_t i = 0; i < header_16bit_word_count; i++)
        header_checksum += ntohs(header_16bit_words[i]);

    while(header_checksum > 0xffff)
        header_checksum = ((header_checksum & 0xffff) + (header_checksum >> 16));

    return htons(~((uint16_t) header_checksum));
}

/*
 * The header of the input IPv4/IPv6 packet must be fully complete and valid, 'payload_raw' must point to the beginning
 *  of the packet's payload and 'payload_size' must contain the size of the payload in bytes (it CAN be set to zero, if
 *  the packet does not carry any payload).
 */
uint16_t t64f_utils_ip__calculate_rfc1071_checksum(const t64ts_tundra__packet *packet, const bool include_pseudo_header, const bool return_0xffff_checksum_if_it_is_zero) {
    uint64_t checksum = 0;

    // Checksum calculation pseudo-header
    if(include_pseudo_header) {
        if(packet->packet_ipv6hdr->version == 6) { // IPv6:
            // If the 'volatile' modifier is not present there and the program is compiled using gcc with optimization turned on, the checksum computation does not work!
            volatile struct __attribute__((__packed__, aligned(2))) {
                uint8_t source_address[16];
                uint8_t destination_address[16];
                uint32_t length;
                uint8_t zeroes[3];
                uint8_t protocol;
            } ipv6_pseudo_header;
            T64M_UTILS__MEMORY_CLEAR((void *) &ipv6_pseudo_header, 1, sizeof(ipv6_pseudo_header));

            memcpy((void *) ipv6_pseudo_header.source_address, packet->packet_ipv6hdr->saddr.s6_addr, 16);
            memcpy((void *) ipv6_pseudo_header.destination_address, packet->packet_ipv6hdr->daddr.s6_addr, 16);
            ipv6_pseudo_header.length = htonl((uint32_t) packet->payload_size);
            memset((void *) ipv6_pseudo_header.zeroes, 0, 3);
            ipv6_pseudo_header.protocol = *(packet->ipv6_carried_protocol_field);

            uint16_t *ipv6_pseudo_header_16bit_words = (uint16_t *) &ipv6_pseudo_header;
            for(size_t i = 0; i < 20; i++) // The pseudo-header contains 20 16-bit words
                checksum += ntohs(ipv6_pseudo_header_16bit_words[i]);
        } else { // IPv4:
            // If the 'volatile' modifier is not present there and the program is compiled using gcc with optimization turned on, the checksum computation does not work!
            volatile struct __attribute__((__packed__, aligned(2))) {
                uint32_t source_address;
                uint32_t destination_address;
                uint8_t zeroes;
                uint8_t protocol;
                uint16_t length;
            } ipv4_pseudo_header;
            T64M_UTILS__MEMORY_CLEAR((void *) &ipv4_pseudo_header, 1, sizeof(ipv4_pseudo_header));

            ipv4_pseudo_header.source_address = packet->packet_ipv4hdr->saddr;
            ipv4_pseudo_header.destination_address = packet->packet_ipv4hdr->daddr;
            ipv4_pseudo_header.zeroes = 0;
            ipv4_pseudo_header.protocol = packet->packet_ipv4hdr->protocol;
            ipv4_pseudo_header.length = htons((uint16_t) packet->payload_size);

            uint16_t *ipv4_pseudo_header_16bit_words = (uint16_t *) &ipv4_pseudo_header;
            for(size_t i = 0; i < 6; i++) // The pseudo-header contains 6 16-bit words
                checksum += ntohs(ipv4_pseudo_header_16bit_words[i]);
        }
    }

    // Packet header & payload
    {
        const uint8_t *current_byte = packet->payload_raw;
        size_t remaining_bytes = packet->payload_size;

        while(remaining_bytes > 1) { // At least 2 bytes are left
            // This is a hack which overcomes the 2-byte alignment requirement for 16-bit values.
            uint16_t temp;
            memcpy(&temp, current_byte, 2);

            checksum += ntohs(temp);
            current_byte += 2;
            remaining_bytes -= 2;
        }

        if(remaining_bytes > 0) { // In case 'remaining_bytes' is an odd number, there will be one unprocessed byte left at the end
            const uint16_t temp = (uint16_t) (*current_byte);
            checksum += ((uint16_t) (temp << 8));
        }
    }

    while(checksum > 0xffff)
        checksum = ((checksum & 0xffff) + (checksum >> 16));

    const uint16_t final_checksum = htons(~((uint16_t) checksum));
    return ((return_0xffff_checksum_if_it_is_zero && final_checksum == 0) ? 0xffff : final_checksum);
}

/*
 * Puts the supplied 'icmp_type' to the first byte and 'icmp_code' to the second byte of out_packet's payload and zeroes
 *  out the remaining 6 bytes. After that, it increments 'out_packet.packet_size' by 8 and sets 'out_packet.payload_size'
 *  to 8. This function does not perform any boundary checks - it is assumed that there are at least 8 bytes free in the
 *  packet buffer!
 * Keep in mind that you need to compute the checksum yourself after you generate the final form of the ICMPv4/v6 message!
 */
void t64f_utils_ip__generate_basic_icmpv4_or_icmpv6_header_to_empty_out_packet_payload(t64ts_tundra__xlat_thread_context *context, const uint8_t icmp_type, const uint8_t icmp_code) {
    context->out_packet.payload_raw[0] = icmp_type;
    context->out_packet.payload_raw[1] = icmp_code;
    memset(context->out_packet.payload_raw + 2, 0, 6);

    context->out_packet.packet_size += 8;
    context->out_packet.payload_size = 8;
}
