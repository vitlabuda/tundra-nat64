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

#pragma once
#include"tundra.h"

#include"utils.h"


// If a macro's name ends with 'UNSAFE', it means that at least one of its arguments is used more than once in its
//  expansion/definition.
// Therefore, arguments "passed" to these macros must always be expressions which cannot possibly have any side
//  effects - while simple literals, constants or variables are fine, anything more sophisticated may not be OK.

#define UTILS_IP__IPV4_ADDR_EQ(ipv4_address1, ipv4_address2) (UTILS__MEM_EQ((ipv4_address1), (ipv4_address2), 4))
#define UTILS_IP__IPV6_ADDR_EQ(ipv6_address1, ipv6_address2) (UTILS__MEM_EQ((ipv6_address1), (ipv6_address2), 16))
#define UTILS_IP__IPV6_PREFIX_EQ(ipv6_prefix1, ipv6_prefix2) (UTILS__MEM_EQ((ipv6_prefix1), (ipv6_prefix2), 12))

#define UTILS_IP__GET_IPV4_FRAG_RESERVED_BIT(ipv4_header_ptr) (!!(ntohs((ipv4_header_ptr)->frag_off) & 0x8000))
#define UTILS_IP__GET_IPV4_DONT_FRAG(ipv4_header_ptr) (!!(ntohs((ipv4_header_ptr)->frag_off) & 0x4000))
#define UTILS_IP__GET_IPV4_MORE_FRAGS(ipv4_header_ptr) (!!(ntohs((ipv4_header_ptr)->frag_off) & 0x2000))
#define UTILS_IP__GET_IPV4_FRAG_OFFSET(ipv4_header_ptr) (ntohs((ipv4_header_ptr)->frag_off) & 0x1fff)
#define UTILS_IP__CONSTRUCT_IPV4_FRAG_OFFSET_AND_FLAGS(dont_fragment, more_fragments, fragment_offset) (htons((uint16_t) ( (((uint16_t) (!!(dont_fragment))) << 14) | (((uint16_t) (!!(more_fragments))) << 13) | (((uint16_t) (fragment_offset)) & 0x1fff) )))
#define UTILS_IP__IS_IPV4_PACKET_FRAGMENTED_UNSAFE(ipv4_header_ptr) (UTILS_IP__GET_IPV4_FRAG_OFFSET((ipv4_header_ptr)) != 0 || UTILS_IP__GET_IPV4_MORE_FRAGS((ipv4_header_ptr)) != 0)

#define UTILS_IP__GET_IPV6_FRAG_OFFSET(ipv6_fragment_header_ptr) (ntohs((ipv6_fragment_header_ptr)->offset_and_flags) >> 3)
#define UTILS_IP__GET_IPV6_FRAG_RESERVED_BITS(ipv6_fragment_header_ptr) ((ntohs((ipv6_fragment_header_ptr)->offset_and_flags) >> 1) & 0x3)
#define UTILS_IP__GET_IPV6_MORE_FRAGS(ipv6_fragment_header_ptr) (ntohs((ipv6_fragment_header_ptr)->offset_and_flags) & 0x1)
#define UTILS_IP__CONSTRUCT_IPV6_FRAG_OFFSET_AND_FLAGS(fragment_offset, more_fragments) (htons((uint16_t) ( (((uint16_t) (fragment_offset)) << 3) | ((uint16_t) (!!(more_fragments))) )))


extern bool utils_ip__is_ipv4_addr_unusable(const uint8_t *ipv4_address);
extern bool utils_ip__is_ipv6_addr_unusable(const uint8_t *ipv6_address);
extern bool utils_ip__is_ipv4_addr_unusable_or_private(const uint8_t *ipv4_address);
extern bool utils_ip__is_ip_proto_forbidden(const uint8_t ip_protocol_number);
extern void utils_ip__generate_ipv6_frag_id(tundra__thread_ctx *const ctx, uint8_t *destination);
extern void utils_ip__generate_ipv4_frag_id(tundra__thread_ctx *const ctx, uint8_t *destination);
