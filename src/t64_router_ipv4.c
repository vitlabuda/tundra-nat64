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
#include"t64_router_ipv4.h"

#include"t64_utils_ip.h"
#include"t64_checksum.h"
#include"t64_xlat_io.h"


static void _t64f_router_ipv4__send_icmpv4_message_to_in_ipv4_packet_source_host(t64ts_tundra__xlat_thread_context *context, const uint8_t icmpv4_type, const uint8_t icmpv4_code, const uint16_t rest_of_header2);
static bool _t64f_router_ipv4__construct_ipv4_header_for_icmpv4_message(t64ts_tundra__xlat_thread_context *context, struct iphdr *out_ipv4_header);
static void _t64f_router_ipv4__construct_icmpv4_header(const uint8_t icmpv4_type, const uint8_t icmpv4_code, const uint16_t rest_of_header2, struct icmphdr *out_icmpv4_header);


void t64f_router_ipv4__send_icmpv4_destination_host_unreachable_message_to_in_ipv4_packet_source_host(t64ts_tundra__xlat_thread_context *context) {
    _t64f_router_ipv4__send_icmpv4_message_to_in_ipv4_packet_source_host(context, 3, 1, 0);
}

void t64f_router_ipv4__send_icmpv4_time_exceeded_message_to_in_ipv4_packet_source_host(t64ts_tundra__xlat_thread_context *context) {
    _t64f_router_ipv4__send_icmpv4_message_to_in_ipv4_packet_source_host(context, 11, 0, 0);
}

void t64f_router_ipv4__send_icmpv4_fragmentation_needed_message_to_in_ipv4_packet_source_host(t64ts_tundra__xlat_thread_context *context, const uint16_t mtu) {
    _t64f_router_ipv4__send_icmpv4_message_to_in_ipv4_packet_source_host(context, 3, 4, mtu);
}

static void _t64f_router_ipv4__send_icmpv4_message_to_in_ipv4_packet_source_host(t64ts_tundra__xlat_thread_context *context, const uint8_t icmpv4_type, const uint8_t icmpv4_code, const uint16_t rest_of_header2) {
    struct iphdr ipv4_header; // 20 bytes
    if(!_t64f_router_ipv4__construct_ipv4_header_for_icmpv4_message(context, &ipv4_header))
        return;

    struct icmphdr icmpv4_header; // 8 bytes
    _t64f_router_ipv4__construct_icmpv4_header(icmpv4_type, icmpv4_code, rest_of_header2, &icmpv4_header);

    const uint8_t *icmpv4_payload_ptr = context->in_packet_buffer;
    // Clamping the packet in error's size to 68 bytes means that at least 8 bytes of its payload will always be sent in
    //  the ICMP message (i.e. even if it has the largest possible header - 60 bytes), and that the resulting ICMP error
    //  message will fit in the minimum IPv4 MTU accepted by this program - 96 bytes (i.e. the program will never have
    //  to fragment the ICMP message).
    const size_t icmpv4_payload_size = T64MM_UTILS__MINIMUM(context->in_packet_size, 68);

    icmpv4_header.checksum = 0;
    icmpv4_header.checksum = t64f_checksum__calculate_rfc1071_checksum_for_ipv4((const uint8_t *) &icmpv4_header, 8, icmpv4_payload_ptr, icmpv4_payload_size, NULL);

    t64f_xlat_io__send_ipv4_packet(context, &ipv4_header, (const uint8_t *) &icmpv4_header, 8, icmpv4_payload_ptr, icmpv4_payload_size);
}

static bool _t64f_router_ipv4__construct_ipv4_header_for_icmpv4_message(t64ts_tundra__xlat_thread_context *context, struct iphdr *out_ipv4_header) {
    if(context->in_packet_size < 20)
        return false;

    const struct iphdr *in_ipv4_header = (const struct iphdr *) context->in_packet_buffer;
    if(in_ipv4_header->version != 4)
        return false;

    out_ipv4_header->version = 4;
    out_ipv4_header->ihl = 5; // 20 bytes
    out_ipv4_header->tos = 0;
    out_ipv4_header->tot_len = 0; // Set to a correct value later
    t64f_utils_ip__generate_ipv4_fragment_identifier(context, (uint8_t *) &out_ipv4_header->id);
    out_ipv4_header->frag_off = 0;
    out_ipv4_header->ttl = context->configuration->router_generated_packet_ttl;
    out_ipv4_header->protocol = 1; // ICMPv4
    out_ipv4_header->check = 0; // Computed later
    memcpy(&out_ipv4_header->saddr, context->configuration->router_ipv4, 4);
    memcpy(&out_ipv4_header->daddr, &in_ipv4_header->saddr, 4);

    return true;
}

static void _t64f_router_ipv4__construct_icmpv4_header(const uint8_t icmpv4_type, const uint8_t icmpv4_code, const uint16_t rest_of_header2, struct icmphdr *out_icmpv4_header) {
    out_icmpv4_header->type = icmpv4_type;
    out_icmpv4_header->code = icmpv4_code;

    uint16_t *out_icmpv4_header_raw = (uint16_t *) out_icmpv4_header;
    out_icmpv4_header_raw[2] = 0; // rest_of_header1 - always 0
    out_icmpv4_header_raw[3] = htons(rest_of_header2);
}
