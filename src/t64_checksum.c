/*
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
*/

#include"t64_tundra.h"
#include"t64_checksum.h"

#include"t64_utils.h"


static uint32_t _t64f_checksum__sum_ipv4_pseudo_header(const struct iphdr *ipv4_header, const size_t transport_header_and_data_length);
static uint32_t _t64f_checksum__sum_ipv6_pseudo_header(const struct ipv6hdr *ipv6_header, const uint8_t carried_protocol, const size_t transport_header_and_data_length);
static uint32_t _t64f_checksum__sum_16bit_words(const uint8_t *bytes, size_t length);
static uint16_t _t64f_checksum__pack_into_16bits(uint32_t packed_32bit_number);


uint16_t t64f_checksum__calculate_ipv4_header_checksum(const struct iphdr *ipv4_header) {
    return ~_t64f_checksum__pack_into_16bits(_t64f_checksum__sum_16bit_words((const uint8_t *) ipv4_header, ((size_t) ipv4_header->ihl) * 4));
}

// The "zeroable" prefix in 'zeroable_payload2_size' just means that if 'nullable_payload2_ptr' is NULL, the size
// should be zero to maintain consistency; it does not mean that 'payload1_size' cannot be zero!
uint16_t t64f_checksum__calculate_rfc1071_checksum_for_ipv4(const uint8_t *payload1_ptr, const size_t payload1_size, const uint8_t *nullable_payload2_ptr, const size_t zeroable_payload2_size, const struct iphdr *nullable_ipv4_header) {
    uint32_t sum = _t64f_checksum__sum_16bit_words(payload1_ptr, payload1_size);

    if(nullable_payload2_ptr != NULL)
        sum += _t64f_checksum__sum_16bit_words(nullable_payload2_ptr, zeroable_payload2_size);

    if(nullable_ipv4_header != NULL)
        sum += _t64f_checksum__sum_ipv4_pseudo_header(nullable_ipv4_header, payload1_size + zeroable_payload2_size); // If 'zeroable_payload2_size' is zero, the sum won't be affected.

    return ~_t64f_checksum__pack_into_16bits(sum);
}

// The "zeroable" prefix in 'zeroable_payload2_size' just means that if 'nullable_payload2_ptr' is NULL, the size
// should be zero to maintain consistency; it does not mean that 'payload1_size' cannot be zero!
uint16_t t64f_checksum__calculate_rfc1071_checksum_for_ipv6(const uint8_t *payload1_ptr, const size_t payload1_size, const uint8_t *nullable_payload2_ptr, const size_t zeroable_payload2_size, const struct ipv6hdr *nullable_ipv6_header, const uint8_t carried_protocol) {
    uint32_t sum = _t64f_checksum__sum_16bit_words(payload1_ptr, payload1_size);

    if(nullable_payload2_ptr != NULL)
        sum += _t64f_checksum__sum_16bit_words(nullable_payload2_ptr, zeroable_payload2_size);

    if(nullable_ipv6_header != NULL)
        sum += _t64f_checksum__sum_ipv6_pseudo_header(nullable_ipv6_header, carried_protocol, payload1_size + zeroable_payload2_size); // If 'zeroable_payload2_size' is zero, the sum won't be affected.

    return ~_t64f_checksum__pack_into_16bits(sum);
}

// For TCP & UDP packets whose payloads do not change when translated
// It is not necessary to replace the whole pseudo-header (only the IP addresses need to be replaced), since the
//  Length, Zeroes and Protocol fields produce the same sum in both pseudo-header versions despite them
//  being ordered (addition is commutative) and sized (in the IPv6 pseudo-header, the first 16 bits of the Length
//  and Zeroes field are always zero [in practice]; therefore, they do not affect the sum [x + 0 = x]) differently
uint16_t t64f_checksum__incrementally_recalculate_rfc1071_checksum_4to6(const uint16_t old_checksum, const struct iphdr *old_ipv4_header, const struct ipv6hdr *new_ipv6_header) {
    const uint32_t old_ips_sum = (
        _t64f_checksum__sum_16bit_words((const uint8_t *) &old_ipv4_header->saddr, 4) +
        _t64f_checksum__sum_16bit_words((const uint8_t *) &old_ipv4_header->daddr, 4)
    );
    const uint32_t new_ips_sum = (
        _t64f_checksum__sum_16bit_words((const uint8_t *) new_ipv6_header->saddr.s6_addr, 16) +
        _t64f_checksum__sum_16bit_words((const uint8_t *) new_ipv6_header->daddr.s6_addr, 16)
    );

    // new_checksum = ~(~old_checksum - old_ips_sum + new_ips_sum)
    return ~_t64f_checksum__pack_into_16bits(_t64f_checksum__pack_into_16bits(~old_checksum - _t64f_checksum__pack_into_16bits(old_ips_sum)) + _t64f_checksum__pack_into_16bits(new_ips_sum));
}

uint16_t t64f_checksum__incrementally_recalculate_rfc1071_checksum_6to4(const uint16_t old_checksum, const struct ipv6hdr *old_ipv6_header, const struct iphdr *new_ipv4_header) {
    const uint32_t old_ips_sum = (
        _t64f_checksum__sum_16bit_words((const uint8_t *) old_ipv6_header->saddr.s6_addr, 16) +
        _t64f_checksum__sum_16bit_words((const uint8_t *) old_ipv6_header->daddr.s6_addr, 16)
    );
    const uint32_t new_ips_sum = (
        _t64f_checksum__sum_16bit_words((const uint8_t *) &new_ipv4_header->saddr, 4) +
        _t64f_checksum__sum_16bit_words((const uint8_t *) &new_ipv4_header->daddr, 4)
    );

    // new_checksum = ~(~old_checksum - old_ips_sum + new_ips_sum)
    return ~_t64f_checksum__pack_into_16bits(_t64f_checksum__pack_into_16bits(~old_checksum - _t64f_checksum__pack_into_16bits(old_ips_sum)) + _t64f_checksum__pack_into_16bits(new_ips_sum));
}

static uint32_t _t64f_checksum__sum_ipv4_pseudo_header(const struct iphdr *ipv4_header, const size_t transport_header_and_data_length) {
    // If the 'volatile' modifier is not present there and the program is compiled using gcc with optimization turned
    //  on, the checksum computation does not work!
    volatile struct __attribute__((__packed__)) {
        uint32_t source_address;
        uint32_t destination_address;
        uint8_t zeroes;
        uint8_t protocol;
        uint16_t length;
    } ipv4_pseudo_header;

    ipv4_pseudo_header.source_address = ipv4_header->saddr;
    ipv4_pseudo_header.destination_address = ipv4_header->daddr;
    ipv4_pseudo_header.zeroes = 0;
    ipv4_pseudo_header.protocol = ipv4_header->protocol;
    ipv4_pseudo_header.length = htons((uint16_t) transport_header_and_data_length);

    return _t64f_checksum__sum_16bit_words((const uint8_t *) &ipv4_pseudo_header, sizeof(ipv4_pseudo_header));
}

static uint32_t _t64f_checksum__sum_ipv6_pseudo_header(const struct ipv6hdr *ipv6_header, const uint8_t carried_protocol, const size_t transport_header_and_data_length) {
    // If the 'volatile' modifier is not present there and the program is compiled using gcc with optimization turned
    //  on, the checksum computation does not work!
    volatile struct __attribute__((__packed__)) {
        uint8_t source_address[16];
        uint8_t destination_address[16];
        uint32_t length;
        uint8_t zeroes[3];
        uint8_t protocol;
    } ipv6_pseudo_header;

    memcpy((void *) ipv6_pseudo_header.source_address, ipv6_header->saddr.s6_addr, 16);
    memcpy((void *) ipv6_pseudo_header.destination_address, ipv6_header->daddr.s6_addr, 16);
    ipv6_pseudo_header.length = htonl((uint32_t) transport_header_and_data_length);
    T64M_UTILS__MEMORY_ZERO_OUT((void *) ipv6_pseudo_header.zeroes, 3);
    ipv6_pseudo_header.protocol = carried_protocol;

    return _t64f_checksum__sum_16bit_words((const uint8_t *) &ipv6_pseudo_header, sizeof(ipv6_pseudo_header));
}

static uint32_t _t64f_checksum__sum_16bit_words(const uint8_t *bytes, size_t length_in_bytes) {
    uint32_t sum = 0;

    while(length_in_bytes > 1) { // At least 2 bytes are left
        sum += *((const uint16_t *) bytes);
        bytes += 2;
        length_in_bytes -= 2;
    }

    if(length_in_bytes > 0) { // In case 'length_in_bytes' is an odd number, there will be one unprocessed byte left at the end
        const uint16_t temp = (uint16_t) (*bytes);
        sum += htons((uint16_t) (temp << 8)); // The checksum is calculated with all bytes being in network order (= big endian)
    }

    return sum;
}

static uint16_t _t64f_checksum__pack_into_16bits(uint32_t packed_32bit_number) {
    while(packed_32bit_number > 0xffff)
        packed_32bit_number = ((packed_32bit_number & 0xffff) + (packed_32bit_number >> 16));

    return ((uint16_t) packed_32bit_number);
}
