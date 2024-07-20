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
#include"router_ipv6.h"

#include"utils.h"
#include"checksum.h"
#include"xlat_io.h"


static void _send_icmpv6_to_in_ipv6_packet_src(const tundra__thread_ctx *const ctx, const uint8_t icmpv6_type, const uint8_t icmpv6_code, const uint16_t rest_of_header2);
static bool _construct_ipv6_header(const tundra__thread_ctx *const ctx, struct ipv6hdr *out_ipv6_header);
static void _construct_icmpv6_header(const uint8_t icmpv6_type, const uint8_t icmpv6_code, const uint16_t rest_of_header2, struct icmp6hdr *out_icmpv6_header);


void router_ipv6__send_address_unreachable_to_in_ipv6_packet_src(const tundra__thread_ctx *const ctx) {
    _send_icmpv6_to_in_ipv6_packet_src(ctx, 1, 3, 0);
}

void router_ipv6__send_time_exceeded_to_in_ipv6_packet_src(const tundra__thread_ctx *const ctx) {
    _send_icmpv6_to_in_ipv6_packet_src(ctx, 3, 0, 0);
}

void router_ipv6__send_packet_too_big_to_in_ipv6_packet_src(const tundra__thread_ctx *const ctx, const uint16_t mtu) {
    _send_icmpv6_to_in_ipv6_packet_src(ctx, 2, 0, mtu);
}

static void _send_icmpv6_to_in_ipv6_packet_src(const tundra__thread_ctx *const ctx, const uint8_t icmpv6_type, const uint8_t icmpv6_code, const uint16_t rest_of_header2) {
    struct ipv6hdr ipv6_header; // 40 bytes
    if(!_construct_ipv6_header(ctx, &ipv6_header))
        return;

    struct icmp6hdr icmpv6_header; // 8 bytes
    _construct_icmpv6_header(icmpv6_type, icmpv6_code, rest_of_header2, &icmpv6_header);

    const uint8_t *icmpv6_payload_ptr = ctx->in_packet_buffer;
    // Clamping the packet in error's size to 1232 bytes means that the resulting ICMPv6 error message packet will
    //  always fit into 1280 bytes, which is the minimum IPv6 MTU, and therefore the packet will never have to be
    //  fragmented.
    const size_t icmpv6_payload_size = UTILS__MINIMUM_UNSAFE(ctx->in_packet_size, 1232);

    icmpv6_header.icmp6_cksum = 0;
    icmpv6_header.icmp6_cksum = checksum__calculate_checksum_ipv6((const uint8_t *) &icmpv6_header, 8, icmpv6_payload_ptr, icmpv6_payload_size, &ipv6_header, 58);

    xlat_io__send_ipv6_packet(ctx, &ipv6_header, NULL, (const uint8_t *) &icmpv6_header, 8, icmpv6_payload_ptr, icmpv6_payload_size);
}

static bool _construct_ipv6_header(const tundra__thread_ctx *const ctx, struct ipv6hdr *out_ipv6_header) {
    if(ctx->in_packet_size < 40)
        return false;

    const struct ipv6hdr *in_ipv6_header = (const struct ipv6hdr *) __builtin_assume_aligned(ctx->in_packet_buffer, 64);
    if(in_ipv6_header->version != 6)
        return false;

    out_ipv6_header->version = 6;
    out_ipv6_header->priority = 0;
    UTILS__MEM_ZERO_OUT(out_ipv6_header->flow_lbl, 3);
    out_ipv6_header->payload_len = 0; // Set to a correct value later
    out_ipv6_header->nexthdr = 58; // ICMPv6
    out_ipv6_header->hop_limit = ctx->config->router_generated_packet_ttl;
    memcpy(out_ipv6_header->saddr.s6_addr, ctx->config->router_ipv6, 16);
    memcpy(out_ipv6_header->daddr.s6_addr, in_ipv6_header->saddr.s6_addr, 16);

    return true;
}

static void _construct_icmpv6_header(const uint8_t icmpv6_type, const uint8_t icmpv6_code, const uint16_t rest_of_header2, struct icmp6hdr *out_icmpv6_header) {
    out_icmpv6_header->icmp6_type = icmpv6_type;
    out_icmpv6_header->icmp6_code = icmpv6_code;

    uint16_t *out_icmpv6_header_raw = (uint16_t *) out_icmpv6_header;
    out_icmpv6_header_raw[2] = 0; // rest_of_header1 - always 0
    out_icmpv6_header_raw[3] = htons(rest_of_header2);
}
