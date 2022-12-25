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
#define T64M_UTILS_IP__IPV6_PREFIXES_EQUAL(ipv6_prefix1, ipv6_prefix2) (T64M_UTILS__MEMORY_EQUAL((ipv6_prefix1), (ipv6_prefix2), 12))

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


extern bool t64f_utils_ip__is_ipv4_address_unusable(const uint8_t *ipv4_address);
extern bool t64f_utils_ip__is_ipv6_address_unusable(const uint8_t *ipv6_address);
extern bool t64f_utils_ip__is_ipv4_address_unusable_or_private(const uint8_t *ipv4_address);
extern bool t64f_utils_ip__is_ip_protocol_number_forbidden(const uint8_t ip_protocol_number);
extern void t64f_utils_ip__generate_ipv6_fragment_identifier(t64ts_tundra__xlat_thread_context *context, uint8_t *destination);
extern void t64f_utils_ip__generate_ipv4_fragment_identifier(t64ts_tundra__xlat_thread_context *context, uint8_t *destination);


#endif // _T64I_UTILS_IP_H
