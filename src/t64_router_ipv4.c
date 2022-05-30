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
#include"t64_router_ipv4.h"

#include"t64_utils_ip.h"
#include"t64_checksum.h"
#include"t64_xlat_io.h"


static void _t64f_router_ipv4__generate_header_of_ipv4_packet_sent_back_to_in_ipv4_packet_source_host_into_out_packet(t64ts_tundra__xlat_thread_context *context, const uint8_t protocol);
static void _t64f_router_ipv4__append_part_of_in_ipv4_packet_to_icmpv4_header_in_out_packet(t64ts_tundra__xlat_thread_context *context);


/*
 * When this function is called, in_packet's IPv4 header must be fully validated and all the packet's properties (i.e.
 *  'packet_size', 'payload_raw' and 'payload_size') must be set correctly. The packet's payload does not have to be
 *  validated. In other words, this function can be called at any point after the '_t64f_xlat_4to6__evaluate_in_packet()'
 *  function succeeds.
 * This function overwrites all the contents of out_packet - it generates the ICMPv4 packet there and sends it out.
 *  Therefore, after a call of this function returns, the translator MUST stop translating the current in_packet
 *  immediately!
 */
void t64f_router_ipv4__generate_and_send_icmpv4_time_exceeded_message_back_to_in_ipv4_packet_source_host(t64ts_tundra__xlat_thread_context *context) {
    _t64f_router_ipv4__generate_header_of_ipv4_packet_sent_back_to_in_ipv4_packet_source_host_into_out_packet(context, 1);

    // OUT-PACKET-REMAINING-BUFFER-SIZE: at least 1520 bytes - 20 bytes IPv4 header = at least 1500 bytes free; 8 bytes needed (for ICMPv4 header)

    t64f_utils_ip__generate_basic_icmpv4v6_header_to_empty_packet_payload(&context->out_packet, 11, 0);

    _t64f_router_ipv4__append_part_of_in_ipv4_packet_to_icmpv4_header_in_out_packet(context);

    context->out_packet.payload_icmpv4hdr->checksum = 0;
    context->out_packet.payload_icmpv4hdr->checksum = t64f_checksum__calculate_rfc1071_checksum(&context->out_packet, false);

    t64f_xlat_io__possibly_fragment_and_send_ipv4_out_packet(context);
}

/*
 * When this function is called, in_packet's IPv4 header must be fully validated and all the packet's properties (i.e.
 *  'packet_size', 'payload_raw' and 'payload_size') must be set correctly. The packet's payload does not have to be
 *  validated. In other words, this function can be called at any point after the '_t64f_xlat_4to6__evaluate_in_packet()'
 *  function succeeds.
 * This function overwrites all the contents of out_packet - it generates the ICMPv4 packet there and sends it out.
 *  Therefore, after a call of this function returns, the translator MUST stop translating the current in_packet
 *  immediately!
 */
void t64f_router_ipv4__generate_and_send_icmpv4_fragmentation_needed_message_back_to_in_ipv4_packet_source_host(t64ts_tundra__xlat_thread_context *context, uint16_t mtu) {
    _t64f_router_ipv4__generate_header_of_ipv4_packet_sent_back_to_in_ipv4_packet_source_host_into_out_packet(context, 1);

    // OUT-PACKET-REMAINING-BUFFER-SIZE: at least 1520 bytes - 20 bytes IPv4 header = at least 1500 bytes free; 8 bytes needed (for ICMPv4 header)

    t64f_utils_ip__generate_basic_icmpv4v6_header_to_empty_packet_payload(&context->out_packet, 3, 4);
    mtu = htons(mtu);
    memcpy(context->out_packet.payload_raw + 6, &mtu, 2);

    _t64f_router_ipv4__append_part_of_in_ipv4_packet_to_icmpv4_header_in_out_packet(context);

    context->out_packet.payload_icmpv4hdr->checksum = 0;
    context->out_packet.payload_icmpv4hdr->checksum = t64f_checksum__calculate_rfc1071_checksum(&context->out_packet, false);

    t64f_xlat_io__possibly_fragment_and_send_ipv4_out_packet(context);
}

static void _t64f_router_ipv4__generate_header_of_ipv4_packet_sent_back_to_in_ipv4_packet_source_host_into_out_packet(t64ts_tundra__xlat_thread_context *context, const uint8_t protocol) {
    // OUT-PACKET-REMAINING-BUFFER-SIZE: at least 1520 bytes free; 20 bytes needed (for IPv4 header)

    context->out_packet.packet_ipv4hdr->version = 4;
    context->out_packet.packet_ipv4hdr->ihl = 5; // = 20 bytes
    context->out_packet.packet_ipv4hdr->tos = 0;
    context->out_packet.packet_ipv4hdr->tot_len = 0; // This is set to a correct value when the packet is sent (at this moment, it is not known what the final size of the packet will be)
    t64f_utils_ip__generate_ipv4_fragment_identifier(context, (uint8_t *) &context->out_packet.packet_ipv4hdr->id);
    context->out_packet.packet_ipv4hdr->frag_off = 0;
    context->out_packet.packet_ipv4hdr->ttl = T64C_TUNDRA__GENERATED_PACKET_TTL;
    context->out_packet.packet_ipv4hdr->protocol = protocol;
    context->out_packet.packet_ipv4hdr->check = 0; // This is set to a correct value when the packet is sent (at this moment, it is not known what the final state of the packet's header will be)
    memcpy(&context->out_packet.packet_ipv4hdr->saddr, context->configuration->router_ipv4, 4);
    memcpy(&context->out_packet.packet_ipv4hdr->daddr, &context->in_packet.packet_ipv4hdr->saddr, 4);

    context->out_packet.packet_size = 20;
    context->out_packet.payload_raw = (context->out_packet.packet_raw + 20);
    context->out_packet.payload_size = 0;
}

static void _t64f_router_ipv4__append_part_of_in_ipv4_packet_to_icmpv4_header_in_out_packet(t64ts_tundra__xlat_thread_context *context) {
    // OUT-PACKET-REMAINING-BUFFER-SIZE: at least 1520 bytes - 20 bytes IPv4 header - 8 bytes ICMPv4 header = at least 1492 bytes free; up to 68 bytes needed (up to 60 bytes IPv4 header + up to 8 bytes payload)

    size_t copy_size = context->in_packet.payload_size;
    if(copy_size > 8)
        copy_size = 8;
    copy_size += (context->in_packet.packet_ipv4hdr->ihl * 4); // t64f_utils__secure_memcpy_with_size_clamping() cannot be used due to this

    memcpy(context->out_packet.payload_raw + 8, context->in_packet.packet_raw, copy_size);
    context->out_packet.packet_size += copy_size;
    context->out_packet.payload_size += copy_size;
}
