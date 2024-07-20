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

#include"tundra.h"
#include"checksum.h"

#include"utils.h"


// See RFC 1071 - https://datatracker.ietf.org/doc/html/rfc1071


static uint32_t _sum_ipv4_pseudo_header(const struct iphdr *ipv4_header, const size_t transport_header_and_data_length);
static uint32_t _sum_ipv6_pseudo_header(const struct ipv6hdr *ipv6_header, const uint8_t carried_protocol, const size_t transport_header_and_data_length);
static uint32_t _sum_16bit_words(const uint8_t *bytes, size_t length);
static uint16_t _pack_into_16bits(uint32_t packed_32bit_number);


uint16_t checksum__calculate_ipv4_header_checksum(const struct iphdr *ipv4_header) {
    const uint32_t sum = _sum_16bit_words((const uint8_t *) ipv4_header, ((size_t) ipv4_header->ihl) * 4);

    return (uint16_t) ~_pack_into_16bits(sum);
}

// The "zeroable" prefix in 'zeroable_payload2_size' just means that if 'nullable_payload2_ptr' is NULL, the size
// should be zero to maintain consistency; it does not mean that 'payload1_size' cannot be zero!
uint16_t checksum__calculate_checksum_ipv4(const uint8_t *payload1_ptr, const size_t payload1_size, const uint8_t *nullable_payload2_ptr, const size_t zeroable_payload2_size, const struct iphdr *nullable_ipv4_header) {
    uint32_t sum = _sum_16bit_words(payload1_ptr, payload1_size);

    if(nullable_payload2_ptr != NULL)
        sum += _sum_16bit_words(nullable_payload2_ptr, zeroable_payload2_size);

    if(nullable_ipv4_header != NULL)
        sum += _sum_ipv4_pseudo_header(nullable_ipv4_header, payload1_size + zeroable_payload2_size); // If 'zeroable_payload2_size' is zero, the sum won't be affected.

    return (uint16_t) ~_pack_into_16bits(sum);
}

// The "zeroable" prefix in 'zeroable_payload2_size' just means that if 'nullable_payload2_ptr' is NULL, the size
// should be zero to maintain consistency; it does not mean that 'payload1_size' cannot be zero!
uint16_t checksum__calculate_checksum_ipv6(const uint8_t *payload1_ptr, const size_t payload1_size, const uint8_t *nullable_payload2_ptr, const size_t zeroable_payload2_size, const struct ipv6hdr *nullable_ipv6_header, const uint8_t carried_protocol) {
    uint32_t sum = _sum_16bit_words(payload1_ptr, payload1_size);

    if(nullable_payload2_ptr != NULL)
        sum += _sum_16bit_words(nullable_payload2_ptr, zeroable_payload2_size);

    if(nullable_ipv6_header != NULL)
        sum += _sum_ipv6_pseudo_header(nullable_ipv6_header, carried_protocol, payload1_size + zeroable_payload2_size); // If 'zeroable_payload2_size' is zero, the sum won't be affected.

    return (uint16_t) ~_pack_into_16bits(sum);
}

// For TCP & UDP packets whose payloads do not change when translated
// It is not necessary to replace the whole pseudo-header (only the IP addresses need to be replaced), since the
//  Length, Zeroes and Protocol fields produce the same sum in both pseudo-header versions despite them
//  being ordered (addition is commutative) and sized (in the IPv6 pseudo-header, the first 16 bits of the Length
//  and Zeroes field are always zero [in practice]; therefore, they do not affect the sum [x + 0 = x]) differently
uint16_t checksum__recalculate_checksum_4to6(const uint16_t old_checksum, const struct iphdr *old_ipv4_header, const struct ipv6hdr *new_ipv6_header) {
    const uint32_t old_ips_sum = (
        _sum_16bit_words((const uint8_t *) &old_ipv4_header->saddr, 4) +
        _sum_16bit_words((const uint8_t *) &old_ipv4_header->daddr, 4)
    );
    const uint32_t new_ips_sum = (
        _sum_16bit_words((const uint8_t *) new_ipv6_header->saddr.s6_addr, 16) +
        _sum_16bit_words((const uint8_t *) new_ipv6_header->daddr.s6_addr, 16)
    );

    // new_checksum = ~(~old_checksum - old_ips_sum + new_ips_sum)
    const uint32_t intermed_sum_1 = (uint32_t) (~old_checksum - _pack_into_16bits(old_ips_sum));
    const uint32_t intermed_sum_2 = (uint32_t) (_pack_into_16bits(intermed_sum_1) + _pack_into_16bits(new_ips_sum));
    return (uint16_t) ~_pack_into_16bits(intermed_sum_2);
}

uint16_t checksum__recalculate_checksum_6to4(const uint16_t old_checksum, const struct ipv6hdr *old_ipv6_header, const struct iphdr *new_ipv4_header) {
    const uint32_t old_ips_sum = (
        _sum_16bit_words((const uint8_t *) old_ipv6_header->saddr.s6_addr, 16) +
        _sum_16bit_words((const uint8_t *) old_ipv6_header->daddr.s6_addr, 16)
    );
    const uint32_t new_ips_sum = (
        _sum_16bit_words((const uint8_t *) &new_ipv4_header->saddr, 4) +
        _sum_16bit_words((const uint8_t *) &new_ipv4_header->daddr, 4)
    );

    // new_checksum = ~(~old_checksum - old_ips_sum + new_ips_sum)
    const uint32_t intermed_sum_1 = (uint32_t) (~old_checksum - _pack_into_16bits(old_ips_sum));
    const uint32_t intermed_sum_2 = (uint32_t) (_pack_into_16bits(intermed_sum_1) + _pack_into_16bits(new_ips_sum));
    return (uint16_t) ~_pack_into_16bits(intermed_sum_2);
}

static uint32_t _sum_ipv4_pseudo_header(const struct iphdr *ipv4_header, const size_t transport_header_and_data_length) {
    const uint16_t length_big_endian = htons((uint16_t) transport_header_and_data_length);
    uint8_t pseudo_header[12];

    // https://datatracker.ietf.org/doc/html/rfc9293#v4pseudo
    memcpy(pseudo_header, &ipv4_header->saddr, 4);  // Source address
    memcpy(pseudo_header + 4, &ipv4_header->daddr, 4);  // Destination address
    pseudo_header[8] = 0;  // Zeroes
    pseudo_header[9] = ipv4_header->protocol;  // Protocol
    memcpy(pseudo_header + 10, &length_big_endian, 2);  // Length

    return _sum_16bit_words(pseudo_header, 12);
}

static uint32_t _sum_ipv6_pseudo_header(const struct ipv6hdr *ipv6_header, const uint8_t carried_protocol, const size_t transport_header_and_data_length) {
    const uint32_t length_big_endian = htonl((uint32_t) transport_header_and_data_length);
    uint8_t pseudo_header[40];

    // https://datatracker.ietf.org/doc/html/rfc8200#section-8.1
    memcpy(pseudo_header, ipv6_header->saddr.s6_addr, 16);  // Source address
    memcpy(pseudo_header + 16, ipv6_header->daddr.s6_addr, 16);  // Destination address
    memcpy(pseudo_header + 32, &length_big_endian, 4);  // Length
    UTILS__MEM_ZERO_OUT(pseudo_header + 36, 3);  // Zeroes
    pseudo_header[39] = carried_protocol;  // Protocol

    return _sum_16bit_words(pseudo_header, 40);
}

static uint32_t _sum_16bit_words(const uint8_t *bytes, size_t length_in_bytes) {
    uint32_t sum = 0;

    while(length_in_bytes > 1) { // At least 2 bytes are left
        // Memory alignment
        uint16_t temp;
        memcpy(&temp, bytes, 2);
        sum += temp;

        bytes += 2;
        length_in_bytes -= 2;
    }

    if(length_in_bytes > 0) { // In case 'length_in_bytes' is an odd number, there will be one unprocessed byte left at the end
        const uint16_t temp = (uint16_t) (*bytes);
        sum += htons((uint16_t) (temp << 8)); // The checksum is calculated with all bytes being in network order (= big endian)
    }

    return sum;
}

static uint16_t _pack_into_16bits(uint32_t packed_32bit_number) {
    while(packed_32bit_number > 0xffff)
        packed_32bit_number = ((packed_32bit_number & 0xffff) + (packed_32bit_number >> 16));

    return (uint16_t) packed_32bit_number;
}
