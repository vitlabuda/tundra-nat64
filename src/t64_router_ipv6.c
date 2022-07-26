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
#include"t64_router_ipv6.h"

#include"t64_utils.h"
#include"t64_utils_ip.h"
#include"t64_checksum.h"
#include"t64_xlat_io.h"


static void _t64f_router_ipv6__generate_and_send_icmpv6_message_back_to_in_ipv6_packet_source_host(t64ts_tundra__xlat_thread_context *context, const uint8_t icmp_type, const uint8_t icmp_code, const uint16_t additional_2bytes);
static void _t64f_router_ipv6__generate_header_of_icmp_ipv6_packet_sent_back_to_in_ipv6_packet_source_host_into_out_packet(t64ts_tundra__xlat_thread_context *context);
static void _t64f_router_ipv6__append_part_of_in_ipv6_packet_to_icmpv6_header_in_out_packet(t64ts_tundra__xlat_thread_context *context);


/*
 * When this function is called, in_packet's IPv6 header(s) must be fully validated and all the packet's properties
 *  (i.e. 'packet_size', 'payload_raw', 'payload_size', 'ipv6_fragment_header' and 'ipv6_carried_protocol_field') must
 *  be set correctly. The packet's payload does not have to be validated. In other words, this function can be called
 *  at any point after the '_t64f_xlat_6to4__evaluate_in_packet()' function succeeds.
 * This function overwrites all the contents of out_packet - it generates the ICMPv6 packet there and sends it out.
 *  Therefore, after a call of this function returns, the translator MUST stop translating the current in_packet
 *  immediately!
 */
void t64f_router_ipv6__generate_and_send_icmpv6_address_unreachable_message_back_to_in_ipv6_packet_source_host(t64ts_tundra__xlat_thread_context *context) {
    _t64f_router_ipv6__generate_and_send_icmpv6_message_back_to_in_ipv6_packet_source_host(context, 1, 3, 0);
}

/*
 * When this function is called, in_packet's IPv6 header(s) must be fully validated and all the packet's properties
 *  (i.e. 'packet_size', 'payload_raw', 'payload_size', 'ipv6_fragment_header' and 'ipv6_carried_protocol_field') must
 *  be set correctly. The packet's payload does not have to be validated. In other words, this function can be called
 *  at any point after the '_t64f_xlat_6to4__evaluate_in_packet()' function succeeds.
 * This function overwrites all the contents of out_packet - it generates the ICMPv6 packet there and sends it out.
 *  Therefore, after a call of this function returns, the translator MUST stop translating the current in_packet
 *  immediately!
 */
void t64f_router_ipv6__generate_and_send_icmpv6_time_exceeded_message_back_to_in_ipv6_packet_source_host(t64ts_tundra__xlat_thread_context *context) {
    _t64f_router_ipv6__generate_and_send_icmpv6_message_back_to_in_ipv6_packet_source_host(context, 3, 0, 0);
}

/*
 * When this function is called, in_packet's IPv6 header(s) must be fully validated and all the packet's properties
 *  (i.e. 'packet_size', 'payload_raw', 'payload_size', 'ipv6_fragment_header' and 'ipv6_carried_protocol_field') must
 *  be set correctly. The packet's payload does not have to be validated. In other words, this function can be called
 *  at any point after the '_t64f_xlat_6to4__evaluate_in_packet()' function succeeds.
 * This function overwrites all the contents of out_packet - it generates the ICMPv6 packet there and sends it out.
 *  Therefore, after a call of this function returns, the translator MUST stop translating the current in_packet
 *  immediately!
 */
void t64f_router_ipv6__generate_and_send_icmpv6_packet_too_big_message_back_to_in_ipv6_packet_source_host(t64ts_tundra__xlat_thread_context *context, uint16_t mtu) {
    _t64f_router_ipv6__generate_and_send_icmpv6_message_back_to_in_ipv6_packet_source_host(context, 2, 0, htons(mtu));
}

static void _t64f_router_ipv6__generate_and_send_icmpv6_message_back_to_in_ipv6_packet_source_host(t64ts_tundra__xlat_thread_context *context, const uint8_t icmp_type, const uint8_t icmp_code, const uint16_t additional_2bytes) {
    _t64f_router_ipv6__generate_header_of_icmp_ipv6_packet_sent_back_to_in_ipv6_packet_source_host_into_out_packet(context);

    // OUT-PACKET-REMAINING-BUFFER-SIZE: at least 1520 bytes - 40 bytes IPv6 header = at least 1480 bytes free; 8 bytes needed (for ICMPv6 header)

    t64f_utils_ip__generate_basic_icmpv4v6_header_to_empty_packet_payload(&context->out_packet, icmp_type, icmp_code);
    memcpy(context->out_packet.payload_raw + 6, &additional_2bytes, 2);

    _t64f_router_ipv6__append_part_of_in_ipv6_packet_to_icmpv6_header_in_out_packet(context);

    context->out_packet.payload_icmpv6hdr->icmp6_cksum = 0;
    context->out_packet.payload_icmpv6hdr->icmp6_cksum = t64f_checksum__calculate_rfc1071_checksum(&context->out_packet, true);

    t64f_xlat_io__possibly_fragment_and_send_ipv6_out_packet(context);
}

static void _t64f_router_ipv6__generate_header_of_icmp_ipv6_packet_sent_back_to_in_ipv6_packet_source_host_into_out_packet(t64ts_tundra__xlat_thread_context *context) {
    // OUT-PACKET-REMAINING-BUFFER-SIZE: at least 1520 bytes free; 40 bytes needed (for IPv6 header)

    context->out_packet.packet_ipv6hdr->version = 6;
    context->out_packet.packet_ipv6hdr->priority = 0;
    T64M_UTILS__MEMORY_ZERO_OUT(context->out_packet.packet_ipv6hdr->flow_lbl, 3);
    context->out_packet.packet_ipv6hdr->payload_len = 0; // This is set to a correct value when the packet is sent (at this moment, it is not known what the final size of the packet's payload will be)
    context->out_packet.packet_ipv6hdr->nexthdr = 58; // ICMPv6
    context->out_packet.packet_ipv6hdr->hop_limit = T64C_TUNDRA__GENERATED_PACKET_TTL;
    memcpy(context->out_packet.packet_ipv6hdr->saddr.s6_addr, context->configuration->router_ipv6, 16);
    memcpy(context->out_packet.packet_ipv6hdr->daddr.s6_addr, context->in_packet.packet_ipv6hdr->saddr.s6_addr, 16);

    context->out_packet.packet_size = 40;
    context->out_packet.payload_raw = (context->out_packet.packet_raw + 40);
    context->out_packet.payload_size = 0;
    context->out_packet.ipv6_fragment_header = NULL;
    context->out_packet.ipv6_carried_protocol_field = &context->out_packet.packet_ipv6hdr->nexthdr;
}

static void _t64f_router_ipv6__append_part_of_in_ipv6_packet_to_icmpv6_header_in_out_packet(t64ts_tundra__xlat_thread_context *context) {
    // OUT-PACKET-REMAINING-BUFFER-SIZE: at least 1520 bytes - 40 bytes IPv6 header - 8 bytes ICMPv6 header = at least 1472 bytes free; up to 1232 bytes needed

    const size_t copied_bytes = t64f_utils__secure_memcpy_with_size_clamping(
        context->out_packet.payload_raw + 8,
        context->in_packet.packet_raw,
        context->in_packet.packet_size,
        (1280 - context->out_packet.packet_size) // 1280 bytes - 40 bytes IPv6 header - 8 bytes ICMPv6 header = 1232 bytes
    );
    context->out_packet.packet_size += copied_bytes;
    context->out_packet.payload_size += copied_bytes;
}
