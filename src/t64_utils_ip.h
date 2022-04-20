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

#ifndef _T64I_UTILS_IP_H
#define _T64I_UTILS_IP_H

#include"t64_tundra.h"
#include"t64_utils.h"


#define T64M_UTILS_IP__IPV4_ADDRESSES_EQUAL(ipv4_address1, ipv4_address2) (T64M_UTILS__MEMORY_EQUAL((ipv4_address1), (ipv4_address2), 4))
#define T64M_UTILS_IP__IPV6_ADDRESSES_EQUAL(ipv6_address1, ipv6_address2) (T64M_UTILS__MEMORY_EQUAL((ipv6_address1), (ipv6_address2), 16))

#define T64M_UTILS_IP__IPV4_PACKET_NEEDS_FRAGMENTATION(context, ipv4_packet_ptr) ((ipv4_packet_ptr)->packet_size > (context)->configuration->translator_ipv4_outbound_mtu)
#define T64M_UTILS_IP__IPV6_PACKET_NEEDS_FRAGMENTATION(context, ipv6_packet_ptr) ((ipv6_packet_ptr)->packet_size > (context)->configuration->translator_ipv6_outbound_mtu)

#define T64M_UTILS_IP__GET_IPV4_FRAGMENT_RESERVED_BIT(ipv4_header_ptr) (!!(ntohs((ipv4_header_ptr)->frag_off) & 0x8000))
#define T64M_UTILS_IP__GET_IPV4_DONT_FRAGMENT_BIT(ipv4_header_ptr) (!!(ntohs((ipv4_header_ptr)->frag_off) & 0x4000))
#define T64M_UTILS_IP__GET_IPV4_MORE_FRAGMENTS_BIT(ipv4_header_ptr) (!!(ntohs((ipv4_header_ptr)->frag_off) & 0x2000))
#define T64M_UTILS_IP__GET_IPV4_FRAGMENT_OFFSET(ipv4_header_ptr) (ntohs((ipv4_header_ptr)->frag_off) & 0x1fff)
#define T64M_UTILS_IP__CONSTRUCT_IPV4_FRAGMENT_OFFSET_AND_FLAGS_FIELD(dont_fragment, more_fragments, fragment_offset) (htons((uint16_t) ( (((uint16_t) (!!(dont_fragment))) << 14) | (((uint16_t) (!!(more_fragments))) << 13) | (((uint16_t) (fragment_offset)) & 0x1fff) )))
#define T64MM_UTILS_IP__IS_IPV4_PACKET_FRAGMENTED(ipv4_header_ptr) (T64M_UTILS_IP__GET_IPV4_FRAGMENT_OFFSET((ipv4_header_ptr)) != 0 || T64M_UTILS_IP__GET_IPV4_MORE_FRAGMENTS_BIT((ipv4_header_ptr)) != 0)

#define T64M_UTILS_IP__GET_IPV6_FRAGMENT_OFFSET(ipv6_fragment_header_ptr) (ntohs((ipv6_fragment_header_ptr)->offset_and_flags) >> 3)
#define T64M_UTILS_IP__GET_IPV6_FRAGMENT_RESERVED_BITS(ipv6_fragment_header_ptr) ((ntohs((ipv6_fragment_header_ptr)->offset_and_flags) >> 1) & 0x3)
#define T64M_UTILS_IP__GET_IPV6_FRAGMENT_MORE_FRAGMENTS_BIT(ipv6_fragment_header_ptr) (ntohs((ipv6_fragment_header_ptr)->offset_and_flags) & 0x1)
#define T64M_UTILS_IP__CONSTRUCT_IPV6_FRAGMENT_OFFSET_AND_FLAGS_FIELD(fragment_offset, more_fragments) (htons((uint16_t) ( (((uint16_t) (fragment_offset)) << 3) | ((uint16_t) (!!(more_fragments))) )))
#define T64M_UTILS_IP__IS_IPV6_PACKET_FRAGMENTED(packet_struct_ptr) ((packet_struct_ptr)->ipv6_fragment_header != NULL)


extern bool t64f_utils_ip__is_ipv4_address_unusable(const uint8_t *ipv4_address);
extern bool t64f_utils_ip__is_ipv6_address_unusable(const uint8_t *ipv6_address);
extern bool t64f_utils_ip__is_ipv4_address_private(const uint8_t *ipv4_address);
extern bool t64f_utils_ip__is_ipv4_embedded_ipv6_address_translatable(const t64ts_tundra__xlat_thread_context *context, const uint8_t *embedded_ipv4_address);
extern bool t64f_utils_ip__is_ip_protocol_number_forbidden(const uint8_t ip_protocol_number);
extern uint16_t t64f_utils_ip__calculate_ipv4_header_checksum(const struct iphdr *ipv4_packet);
extern uint16_t t64f_utils_ip__calculate_rfc1071_checksum(const t64ts_tundra__packet *packet, const bool include_pseudo_header, const bool return_0xffff_checksum_if_it_is_zero);
extern void t64f_utils_ip__generate_basic_icmpv4_or_icmpv6_header_to_empty_out_packet_payload(t64ts_tundra__xlat_thread_context *context, const uint8_t icmp_type, const uint8_t icmp_code);


#endif // _T64I_UTILS_IP_H
