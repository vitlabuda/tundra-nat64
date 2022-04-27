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
#include"t64_checksum.h"

#include"t64_utils.h"


static uint32_t _t64f_checksum__sum_16bit_words(const uint8_t *bytes, size_t length);
static uint32_t _t64f_checksum__sum_pseudo_header(const t64ts_tundra__packet *packet);
static uint32_t _t64f_checksum__sum_ipv4_pseudo_header(const t64ts_tundra__packet *ipv4_packet);
static uint32_t _t64f_checksum__sum_ipv6_pseudo_header(const t64ts_tundra__packet *ipv6_packet);
static uint16_t _t64f_checksum__pack_into_16bits(uint32_t packed_32bit_number);


uint16_t t64f_checksum__calculate_ipv4_header_checksum(const struct iphdr *ipv4_header) {
    return ~_t64f_checksum__pack_into_16bits(_t64f_checksum__sum_16bit_words((const uint8_t *) ipv4_header, ipv4_header->ihl * 4));
}

uint16_t t64f_checksum__calculate_rfc1071_checksum_of_packet(const t64ts_tundra__packet *packet, const bool include_pseudo_header) {
    uint32_t sum = 0;

    if(include_pseudo_header)
        sum += _t64f_checksum__sum_pseudo_header(packet);

    sum += _t64f_checksum__sum_16bit_words(packet->payload_raw, packet->payload_size);

    return ~_t64f_checksum__pack_into_16bits(sum);
}

uint16_t t64f_checksum__quickly_recalculate_rfc1071_checksum(const uint16_t old_checksum, const t64ts_tundra__packet *packet_with_old_pseudo_header, const t64ts_tundra__packet *packet_with_new_pseudo_header) {
    const uint16_t old_pseudo_header_sum = _t64f_checksum__pack_into_16bits(_t64f_checksum__sum_pseudo_header(packet_with_old_pseudo_header));
    const uint16_t new_pseudo_header_sum = _t64f_checksum__pack_into_16bits(_t64f_checksum__sum_pseudo_header(packet_with_new_pseudo_header));

    // new_checksum = ~(~old_checksum - old_pseudo_header + new_pseudo_header)
    return ~_t64f_checksum__pack_into_16bits(_t64f_checksum__pack_into_16bits(~old_checksum - old_pseudo_header_sum) + new_pseudo_header_sum);
}

static uint32_t _t64f_checksum__sum_16bit_words(const uint8_t *bytes, size_t length_in_bytes) {
    uint32_t sum = 0;

    while(length_in_bytes > 1) { // At least 2 bytes are left
        sum += *((uint16_t *) bytes);
        bytes += 2;
        length_in_bytes -= 2;
    }

    if(length_in_bytes > 0) { // In case 'length_in_bytes' is an odd number, there will be one unprocessed byte left at the end
        const uint16_t temp = (uint16_t) (*bytes);
        sum += htons((uint16_t) (temp << 8)); // The checksum is calculated with all bytes being in network order (= big endian)
    }

    return sum;
}

static uint32_t _t64f_checksum__sum_pseudo_header(const t64ts_tundra__packet *packet) {
    if(packet->packet_ipv4hdr->version == 4)
        return _t64f_checksum__sum_ipv4_pseudo_header(packet);

    if(packet->packet_ipv4hdr->version == 6)
        return _t64f_checksum__sum_ipv6_pseudo_header(packet);

    return 0; // This should never happen!
}

static uint32_t _t64f_checksum__sum_ipv4_pseudo_header(const t64ts_tundra__packet *ipv4_packet) {
    // If the 'volatile' modifier is not present there and the program is compiled using gcc with optimization turned on, the checksum computation does not work!
    volatile struct __attribute__((__packed__)) {
        uint32_t source_address;
        uint32_t destination_address;
        uint8_t zeroes;
        uint8_t protocol;
        uint16_t length;
    } ipv4_pseudo_header;
    T64M_UTILS__MEMORY_CLEAR((void *) &ipv4_pseudo_header, 1, sizeof(ipv4_pseudo_header));

    ipv4_pseudo_header.source_address = ipv4_packet->packet_ipv4hdr->saddr;
    ipv4_pseudo_header.destination_address = ipv4_packet->packet_ipv4hdr->daddr;
    ipv4_pseudo_header.zeroes = 0;
    ipv4_pseudo_header.protocol = ipv4_packet->packet_ipv4hdr->protocol;
    ipv4_pseudo_header.length = htons((uint16_t) ipv4_packet->payload_size);

    return _t64f_checksum__sum_16bit_words((uint8_t *) &ipv4_pseudo_header, sizeof(ipv4_pseudo_header));
}

static uint32_t _t64f_checksum__sum_ipv6_pseudo_header(const t64ts_tundra__packet *ipv6_packet) {
    // If the 'volatile' modifier is not present there and the program is compiled using gcc with optimization turned on, the checksum computation does not work!
    volatile struct __attribute__((__packed__)) {
        uint8_t source_address[16];
        uint8_t destination_address[16];
        uint32_t length;
        uint8_t zeroes[3];
        uint8_t protocol;
    } ipv6_pseudo_header;
    T64M_UTILS__MEMORY_CLEAR((void *) &ipv6_pseudo_header, 1, sizeof(ipv6_pseudo_header));

    memcpy((void *) ipv6_pseudo_header.source_address, ipv6_packet->packet_ipv6hdr->saddr.s6_addr, 16);
    memcpy((void *) ipv6_pseudo_header.destination_address, ipv6_packet->packet_ipv6hdr->daddr.s6_addr, 16);
    ipv6_pseudo_header.length = htonl((uint32_t) ipv6_packet->payload_size);
    memset((void *) ipv6_pseudo_header.zeroes, 0, 3);
    ipv6_pseudo_header.protocol = *(ipv6_packet->ipv6_carried_protocol_field);

    return _t64f_checksum__sum_16bit_words((uint8_t *) &ipv6_pseudo_header, sizeof(ipv6_pseudo_header));
}

static uint16_t _t64f_checksum__pack_into_16bits(uint32_t packed_32bit_number) {
    while(packed_32bit_number > 0xffff)
        packed_32bit_number = ((packed_32bit_number & 0xffff) + (packed_32bit_number >> 16));

    return ((uint16_t) packed_32bit_number);
}
