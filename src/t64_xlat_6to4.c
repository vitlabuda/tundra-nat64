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
#include"t64_xlat_6to4.h"

#include"t64_utils.h"
#include"t64_utils_ip.h"
#include"t64_checksum.h"
#include"t64_xlat_io.h"
#include"t64_xlat_6to4_icmp.h"
#include"t64_router_ipv6.h"
#include"t64_xlat_addr_nat64.h"
#include"t64_xlat_addr_clat.h"
#include"t64_xlat_addr_siit.h"


static bool _t64f_xlat_6to4__evaluate_in_packet(t64ts_tundra__xlat_thread_context *context);
static void _t64f_xlat_6to4__translate_in_packet_headers_to_out_packet_headers(t64ts_tundra__xlat_thread_context *context);
static bool _t64f_xlat_6to4__translate_in_packet_payload_to_out_packet_payload(t64ts_tundra__xlat_thread_context *context);
static void _t64f_xlat_6to4__appropriately_send_out_out_packet(t64ts_tundra__xlat_thread_context *context);


void t64f_xlat_6to4__handle_packet(t64ts_tundra__xlat_thread_context *context) {
    /*
     * REQUIRED-STATE-OF-PACKET-BUFFERS:
     *
     * in_packet->packet_raw (content) -- An unvalidated IPv6 (!) packet
     * in_packet->packet_size -- The unvalidated IPv6 packet's size
     * in_packet->payload_raw -- Undefined
     * in_packet->payload_size -- Undefined
     * in_packet->ipv6_fragment_header -- Undefined
     * in_packet->ipv6_carried_protocol_field -- Undefined
     *
     * out_packet->packet_raw (content) -- Undefined
     * out_packet->packet_size -- Undefined
     * out_packet->payload_raw -- Undefined
     * out_packet->payload_size -- Undefined
     * out_packet->ipv6_fragment_header -- Undefined
     * out_packet->ipv6_carried_protocol_field -- Undefined
     */

    if(!_t64f_xlat_6to4__evaluate_in_packet(context))
        return;

    _t64f_xlat_6to4__translate_in_packet_headers_to_out_packet_headers(context);

    // It would be possible to decide which function to use beforehand and then call it indirectly using a function
    //  pointer, but indirect function calls are usually slow.
    switch(context->configuration->translator_mode) {
        case T64TE_TUNDRA__TRANSLATOR_MODE_NAT64:
            if(!t64f_xlat_addr_nat64__perform_6to4_address_translation_for_main_packet(context, (const uint8_t *) context->in_packet.packet_ipv6hdr->saddr.s6_addr, (const uint8_t *) context->in_packet.packet_ipv6hdr->daddr.s6_addr, (uint8_t *) &context->out_packet.packet_ipv4hdr->saddr, (uint8_t *) &context->out_packet.packet_ipv4hdr->daddr))
                return;
            break;

        case T64TE_TUNDRA__TRANSLATOR_MODE_CLAT:
            if(!t64f_xlat_addr_clat__perform_6to4_address_translation_for_main_packet(context, (const uint8_t *) context->in_packet.packet_ipv6hdr->saddr.s6_addr, (const uint8_t *) context->in_packet.packet_ipv6hdr->daddr.s6_addr, (uint8_t *) &context->out_packet.packet_ipv4hdr->saddr, (uint8_t *) &context->out_packet.packet_ipv4hdr->daddr))
                return;
            break;

        case T64TE_TUNDRA__TRANSLATOR_MODE_SIIT:
            if(!t64f_xlat_addr_siit__perform_6to4_address_translation_for_main_packet(context, (const uint8_t *) context->in_packet.packet_ipv6hdr->saddr.s6_addr, (const uint8_t *) context->in_packet.packet_ipv6hdr->daddr.s6_addr, (uint8_t *) &context->out_packet.packet_ipv4hdr->saddr, (uint8_t *) &context->out_packet.packet_ipv4hdr->daddr))
                return;
            break;

        default:
            return; // This should never happen!
    }

    // At this moment, the entire in_packet's IPv6 header has been validated (including any IPv6 extension headers);
    //  therefore, it is now safe to send ICMP messages back to the packet's source host.
    if(context->out_packet.packet_ipv4hdr->ttl < 1) {
        t64f_router_ipv6__generate_and_send_icmpv6_time_exceeded_message_back_to_in_ipv6_packet_source_host(context);
        return;
    }

    if(!_t64f_xlat_6to4__translate_in_packet_payload_to_out_packet_payload(context))
        return;

    // The IPv4 'out_packet' is now complete.
    _t64f_xlat_6to4__appropriately_send_out_out_packet(context);
}

static bool _t64f_xlat_6to4__evaluate_in_packet(t64ts_tundra__xlat_thread_context *context) {
    /*
     * REQUIRED-STATE-OF-PACKET-BUFFERS:
     *
     * in_packet->packet_raw (content) -- An unvalidated IPv6 (!) packet
     * in_packet->packet_size -- The unvalidated IPv6 packet's size
     * in_packet->payload_raw -- Undefined
     * in_packet->payload_size -- Undefined
     * in_packet->ipv6_fragment_header -- Undefined
     * in_packet->ipv6_carried_protocol_field -- Undefined
     *
     * out_packet->packet_raw (content) -- Undefined
     * out_packet->packet_size -- Undefined
     * out_packet->payload_raw -- Undefined
     * out_packet->payload_size -- Undefined
     * out_packet->ipv6_fragment_header -- Undefined
     * out_packet->ipv6_carried_protocol_field -- Undefined
     */

    if(context->in_packet.packet_size < 40)
        return false; // The smallest possible IPv6 packet is 40 bytes in size.

    // Version is guaranteed to be 6

    // Traffic class & Flow label need not be checked

    // Payload length
    if(ntohs(context->in_packet.packet_ipv6hdr->payload_len) != (context->in_packet.packet_size - 40))
        return false;

    // Hop limit
    if(context->in_packet.packet_ipv6hdr->hop_limit < 1)
        return false; // The packet should have already been dropped!

    // Source & destination address is checked & translated using 'addr_xlat_functions' later.

    // Next header & Fragmentation (walks through all IPv6 extension headers)
    {
        t64ts_tundra__ipv6_fragment_header *fragment_header = NULL;
        uint8_t *protocol_field = &context->in_packet.packet_ipv6hdr->nexthdr;
        uint8_t *current_header_ptr = (context->in_packet.packet_raw + 40);
        ssize_t remaining_packet_size = (((ssize_t) context->in_packet.packet_size) - 40);

        while(
            (fragment_header == NULL) &&
            (*protocol_field == 0 || *protocol_field == 43 || *protocol_field == 44 || *protocol_field == 60)
        ) {
            if(remaining_packet_size < 8)
                return false;

            if(*protocol_field == 43) { // Routing Header for IPv6
                /*
                 * From RFC 7915, section 5.1:
                 *  If a Routing header with a non-zero Segments Left field is present,
                 *  then the packet MUST NOT be translated, and an ICMPv6 "parameter
                 *  problem/erroneous header field encountered" (Type 4, Code 0) error
                 *  message, with the Pointer field indicating the first byte of the
                 *  Segments Left field, SHOULD be returned to the sender.
                 */
                if(current_header_ptr[3] != 0)
                    return false;

            } else if(*protocol_field == 44) { // Fragment Header
                fragment_header = (t64ts_tundra__ipv6_fragment_header *) current_header_ptr;
                if(fragment_header->reserved != 0 || T64M_UTILS_IP__GET_IPV6_FRAGMENT_RESERVED_BITS(fragment_header) != 0)
                    return false;
            }

            // current_header_ptr[1] is guaranteed to be zero in case of a fragment header (checked above)
            const ssize_t current_header_size = (8 + (((ssize_t) (current_header_ptr[1])) * 8));

            protocol_field = current_header_ptr; // The first field of every IPv6 extension header is "next header"
            current_header_ptr += current_header_size; // Move to a next header or the payload
            remaining_packet_size -= current_header_size;
        }

        if(remaining_packet_size < 0)
            return false;

        if(
            t64f_utils_ip__is_ip_protocol_number_forbidden(*protocol_field) ||
            (*protocol_field == 1) // Internet Control Message Protocol (ICMPv4)
        ) return false;

        context->in_packet.payload_raw = current_header_ptr;
        context->in_packet.payload_size = (size_t) remaining_packet_size;
        context->in_packet.ipv6_fragment_header = fragment_header;
        context->in_packet.ipv6_carried_protocol_field = protocol_field;
    }

    return true;
}

static void _t64f_xlat_6to4__translate_in_packet_headers_to_out_packet_headers(t64ts_tundra__xlat_thread_context *context) {
    /*
     * REQUIRED-STATE-OF-PACKET-BUFFERS:
     *
     * in_packet->packet_raw (content) -- An IPv6 packet whose headers (base header + all extension headers, if there are any, BUT excluding source & destination IP address!) have been validated
     * in_packet->packet_size -- The IPv6 packet's size (at least 40 bytes)
     * in_packet->payload_raw -- The packet's unvalidated payload (the pointer points to the beginning of the transport protocol header)
     * in_packet->payload_size -- The size of the packet's unvalidated payload (zero if the packet does not carry any payload)
     * in_packet->ipv6_fragment_header -- A pointer to the fragmentation header if the packet contains it; NULL otherwise
     * in_packet->ipv6_carried_protocol_field -- A pointer to the byte which contains the number of the transport protocol carried by the packet
     *
     * out_packet->packet_raw (content) -- Undefined
     * out_packet->packet_size -- Undefined
     * out_packet->payload_raw -- Undefined
     * out_packet->payload_size -- Undefined
     * out_packet->ipv6_fragment_header -- Undefined
     * out_packet->ipv6_carried_protocol_field -- Undefined
     */

    // OUT-PACKET-REMAINING-BUFFER-SIZE: at least 1520 bytes free; 20 bytes needed (for IPv4 header)

    // Version
    context->out_packet.packet_ipv4hdr->version = 4;

    // IHL
    context->out_packet.packet_ipv4hdr->ihl = 5; // = 20 bytes

    // DSCP & ECN
    context->out_packet.packet_ipv4hdr->tos = (uint8_t) (
        (context->configuration->translator_6to4_copy_dscp_and_ecn) ?
        ((context->in_packet.packet_ipv6hdr->priority << 4) | (context->in_packet.packet_ipv6hdr->flow_lbl[0] >> 4)) :
        (0)
    );

    // Total length
    context->out_packet.packet_ipv4hdr->tot_len = 0; // This is set to a correct value when the packet is sent (at this moment, it is not known what the final size of the packet will be)

    // Identification, fragment flags & fragment offset
    if(T64M_UTILS_IP__IS_IPV6_PACKET_FRAGMENTED(&context->in_packet)) {
        context->out_packet.packet_ipv4hdr->id = context->in_packet.ipv6_fragment_header->identification[1];
        context->out_packet.packet_ipv4hdr->frag_off = T64M_UTILS_IP__CONSTRUCT_IPV4_FRAGMENT_OFFSET_AND_FLAGS_FIELD(
            0,
            T64M_UTILS_IP__GET_IPV6_FRAGMENT_MORE_FRAGMENTS_BIT(context->in_packet.ipv6_fragment_header),
            T64M_UTILS_IP__GET_IPV6_FRAGMENT_OFFSET(context->in_packet.ipv6_fragment_header)
        );
    } else {
        t64f_utils_ip__generate_ipv4_fragment_identifier(context, (uint8_t *) &context->out_packet.packet_ipv4hdr->id);
        context->out_packet.packet_ipv4hdr->frag_off = 0;
    }

    // Time to live
    context->out_packet.packet_ipv4hdr->ttl = (context->in_packet.packet_ipv6hdr->hop_limit - 1);

    // Protocol
    context->out_packet.packet_ipv4hdr->protocol = *(context->in_packet.ipv6_carried_protocol_field);

    // Header checksum
    context->out_packet.packet_ipv4hdr->check = 0; // This is set to a correct value when the packet is sent (at this moment, it is not known what the final state of the packet's header will be)

    // Source & destination address is checked & translated using 'addr_xlat_functions' later.

    context->out_packet.packet_size = 20;
    context->out_packet.payload_raw = (context->out_packet.packet_raw + 20);
    context->out_packet.payload_size = 0;
}

static bool _t64f_xlat_6to4__translate_in_packet_payload_to_out_packet_payload(t64ts_tundra__xlat_thread_context *context) {
    /*
     * REQUIRED-STATE-OF-PACKET-BUFFERS:
     *
     * in_packet->packet_raw (content) -- An IPv6 packet whose headers (base header + all extension headers, if there are any) have been validated
     * in_packet->packet_size -- The IPv6 packet's size (at least 40 bytes)
     * in_packet->payload_raw -- The packet's unvalidated payload (the pointer points to the beginning of the transport protocol header)
     * in_packet->payload_size -- The size of the packet's unvalidated payload (zero if the packet does not carry any payload)
     * in_packet->ipv6_fragment_header -- A pointer to the fragmentation header if the packet contains it; NULL otherwise
     * in_packet->ipv6_carried_protocol_field -- A pointer to the byte which contains the number of the transport protocol carried by the packet
     *
     * out_packet->packet_raw (content) -- An IPv4 header (whose 'tot_len' and 'check' fields are zero - they are set just before the packet is sent out)
     * out_packet->packet_size -- The size of the IPv4 header (always 20 bytes)
     * out_packet->payload_raw -- A pointer to the first byte after the packet's header (the translated payload shall be placed here)
     * out_packet->payload_size -- Zero
     * out_packet->ipv6_fragment_header -- Undefined (as the packet is IPv4)
     * out_packet->ipv6_carried_protocol_field -- Undefined (as the packet is IPv4)
     */

    // Translation from ICMPv6 to ICMPv4 requires a special workflow
    if(context->out_packet.packet_ipv4hdr->protocol == 58) {
        context->out_packet.packet_ipv4hdr->protocol = 1;
        return t64f_xlat_6to4_icmp__translate_icmpv6_to_icmpv4(context);
    }

    // Data of other transport protocols are simply copied from 'in_packet' to 'out_packet'
    if(!t64f_utils__secure_memcpy(
        context->out_packet.payload_raw,
        context->in_packet.payload_raw,
        context->in_packet.payload_size,
        (T64C_TUNDRA__MAX_PACKET_SIZE - context->out_packet.packet_size)
    )) return false;

    context->out_packet.packet_size += context->in_packet.payload_size;
    context->out_packet.payload_size = context->in_packet.payload_size;

    // However, some transport protocols contain checksums whose correct value changes when performing NAT64/CLAT translation
    if(T64M_UTILS_IP__GET_IPV4_FRAGMENT_OFFSET(context->out_packet.packet_ipv4hdr) == 0) {
        if(context->out_packet.packet_ipv4hdr->protocol == 6 && context->out_packet.payload_size >= 20) { // TCP
            context->out_packet.payload_tcphdr->check = t64f_checksum__incrementally_recalculate_rfc1071_checksum(context->out_packet.payload_tcphdr->check, &context->in_packet, &context->out_packet);

        } else if(context->out_packet.packet_ipv4hdr->protocol == 17 && context->out_packet.payload_size >= 8) { // UDP
            if(context->out_packet.payload_udphdr->check == 0)
                return false;

            const uint16_t new_checksum = t64f_checksum__incrementally_recalculate_rfc1071_checksum(context->out_packet.payload_udphdr->check, &context->in_packet, &context->out_packet);
            context->out_packet.payload_udphdr->check = ((new_checksum == 0) ? 0xffff : new_checksum);
        }
    }

    return true;
}

static void _t64f_xlat_6to4__appropriately_send_out_out_packet(t64ts_tundra__xlat_thread_context *context) {
    /*
     * REQUIRED-STATE-OF-PACKET-BUFFERS:
     *
     * in_packet->packet_raw (content) -- An IPv6 packet whose headers (base header + all extension headers, if there are any) have been validated
     * in_packet->packet_size -- The IPv6 packet's size (at least 40 bytes)
     * in_packet->payload_raw -- The packet's unvalidated payload (the pointer points to the beginning of the transport protocol header)
     * in_packet->payload_size -- The size of the packet's unvalidated payload (zero if the packet does not carry any payload)
     * in_packet->ipv6_fragment_header -- A pointer to the fragmentation header if the packet contains it; NULL otherwise
     * in_packet->ipv6_carried_protocol_field -- A pointer to the byte which contains the number of the transport protocol carried by the packet
     *
     * out_packet->packet_raw (content) -- An IPv4 packet (whose header fields 'tot_len' and 'check' fields are zero - they are set just before the packet is sent out)
     * out_packet->packet_size -- The size of the IPv4 packet (header + payload)
     * out_packet->payload_raw -- A pointer to the first byte after the packet's header where the translated payload is located
     * out_packet->payload_size -- The size of the packet's payload
     * out_packet->ipv6_fragment_header -- Undefined (as the packet is IPv4)
     * out_packet->ipv6_carried_protocol_field -- Undefined (as the packet is IPv4)
     */

    const uint16_t more_fragments = T64M_UTILS_IP__GET_IPV4_MORE_FRAGMENTS_BIT(context->out_packet.packet_ipv4hdr);
    const uint16_t fragment_offset = T64M_UTILS_IP__GET_IPV4_FRAGMENT_OFFSET(context->out_packet.packet_ipv4hdr);

    if(context->out_packet.packet_size <= 1260) {
        context->out_packet.packet_ipv4hdr->frag_off = T64M_UTILS_IP__CONSTRUCT_IPV4_FRAGMENT_OFFSET_AND_FLAGS_FIELD(0, more_fragments, fragment_offset);

        t64f_xlat_io__possibly_fragment_and_send_ipv4_out_packet(context);
    } else {
        context->out_packet.packet_ipv4hdr->frag_off = T64M_UTILS_IP__CONSTRUCT_IPV4_FRAGMENT_OFFSET_AND_FLAGS_FIELD(1, more_fragments, fragment_offset);

        if(T64M_UTILS_IP__IPV4_PACKET_NEEDS_FRAGMENTATION(context, &context->out_packet)) {
            // Why (IPv4 MTU + 20)? "Worst case scenario" example: The IPv4 MTU is 1500 bytes; the IPv6 host sends
            //  a 1520-byte (1500 + 20) IPv6 packet; its 40-byte IPv6 header is stripped, resulting in 1480 bytes
            //  of data; a 20-byte IPv4 header is prepended to the data, resulting in a 1500-byte IPv4 packet (the
            //  biggest packet that fits into the IPv4 MTU).
            // In addition, if the MTU that would be sent in the ICMPv6 error message would be lower than 1280 bytes
            //  (the minimum IPv6 MTU), is it clamped to 1280 bytes; therefore, the origin host need not handle
            //  IPv6 links with MTUs lower than 1280 bytes (such links shall not exist according to standards).
            //  If the IPv6 host would then send a 1280-byte IPv6 packet, it would pass through the translator, as
            //  the resulting IPv4 packet would have been 1260 bytes in size and therefore could be fragmented.
            //  This means that 1280-byte IPv6 packets are always able to pass through the translator (= the
            //  translator is standards-compliant, as IPv6 nodes must be able to handle 1280-byte IPv6 packets).
            t64f_router_ipv6__generate_and_send_icmpv6_packet_too_big_message_back_to_in_ipv6_packet_source_host(context, T64MM_UTILS__MAXIMUM(1280, ((uint16_t) context->configuration->translator_ipv4_outbound_mtu) + 20));
        } else {
            t64f_xlat_io__send_specified_ipv4_packet(context, &context->out_packet);
        }
    }
}
