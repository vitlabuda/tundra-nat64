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
#include"t64_xlat_addr.h"


typedef struct {
    struct iphdr ipv4_header;
    const uint8_t *payload_ptr; // Points to a part of 'context->in_packet_buffer' --> must not be modified!
    size_t payload_size;
    bool is_fragment;
    bool is_fragment_offset_zero;
} _t64ts_xlat_6to4__out_ipv4_packet_data;


static bool _t64f_xlat_6to4__validate_and_translate_ip_header(t64ts_tundra__xlat_thread_context *context, _t64ts_xlat_6to4__out_ipv4_packet_data *out_packet_data);
static void _t64f_xlat_6to4__translate_icmpv6_payload_to_icmpv4_and_send(t64ts_tundra__xlat_thread_context *context, _t64ts_xlat_6to4__out_ipv4_packet_data *out_packet_data);
static void _t64f_xlat_6to4__translate_tcp_payload_and_send(const t64ts_tundra__xlat_thread_context *context, _t64ts_xlat_6to4__out_ipv4_packet_data *out_packet_data);
static void _t64f_xlat_6to4__translate_udp_payload_and_send(const t64ts_tundra__xlat_thread_context *context, _t64ts_xlat_6to4__out_ipv4_packet_data *out_packet_data);
static void _t64f_xlat_6to4__translate_generic_payload_and_send(const t64ts_tundra__xlat_thread_context *context, _t64ts_xlat_6to4__out_ipv4_packet_data *out_packet_data);
static void _t64f_xlat_6to4__appropriately_send_ipv4_packet(const t64ts_tundra__xlat_thread_context *context, struct iphdr *ipv4_header, const uint8_t *nullable_payload1_ptr, const size_t zeroable_payload1_size_m8, const uint8_t *payload2_ptr, const size_t payload2_size);
static void _t64f_xlat_6to4__fragment_and_send_ipv4_packet(const t64ts_tundra__xlat_thread_context *context, struct iphdr *ipv4_header, const uint8_t *nullable_payload1_ptr, const size_t zeroable_payload1_size_m8, const uint8_t *payload2_ptr, const size_t payload2_size);
static bool _t64f_xlat_6to4__fragment_and_send_ipv4_packet_part(const t64ts_tundra__xlat_thread_context *context, struct iphdr *ready_ipv4_header, const uint8_t *current_payload_part_ptr, size_t remaining_payload_part_size, size_t *fragment_offset_8byte_chunks, const bool more_fragments_after_this_part, const bool dont_fragment, const size_t max_fragment_payload_size);


void t64f_xlat_6to4__handle_packet(t64ts_tundra__xlat_thread_context *context) {
    _t64ts_xlat_6to4__out_ipv4_packet_data out_packet_data;
    if(!_t64f_xlat_6to4__validate_and_translate_ip_header(context, &out_packet_data))
        return;

    // At this moment, the entire in_packet's IPv6 header has been validated (including any IPv6 extension headers);
    //  therefore, it is now safe to send ICMP messages back to the packet's source host.
    if(out_packet_data.ipv4_header.ttl < 1) {
        t64f_router_ipv6__send_icmpv6_time_exceeded_message_to_in_ipv6_packet_source_host(context);
        return;
    }

    switch(out_packet_data.ipv4_header.protocol) {
        case 1: // ICMPv4
            _t64f_xlat_6to4__translate_icmpv6_payload_to_icmpv4_and_send(context, &out_packet_data);
            break;

        case 6: // TCP
            _t64f_xlat_6to4__translate_tcp_payload_and_send(context, &out_packet_data);
            break;

        case 17: // UDP
            _t64f_xlat_6to4__translate_udp_payload_and_send(context, &out_packet_data);
            break;

        default:
            _t64f_xlat_6to4__translate_generic_payload_and_send(context, &out_packet_data);
            break;
    }
}

static bool _t64f_xlat_6to4__validate_and_translate_ip_header(t64ts_tundra__xlat_thread_context *context, _t64ts_xlat_6to4__out_ipv4_packet_data *out_packet_data) {
    if(context->in_packet_size < 40)
        return false;

    const struct ipv6hdr *in_ipv6_header = (const struct ipv6hdr *) context->in_packet_buffer;
    struct iphdr *out_ipv4_header = &out_packet_data->ipv4_header;

    // :: IP version ('in_ipv6_header->version' is guaranteed to be 6)
    out_ipv4_header->version = 4;

    // :: IHL (always set to 5 = 20 bytes -> no IPv4 options)
    out_ipv4_header->ihl = 5;

    // :: Traffic class -> DCSP & ECN (no validation needs to be done)
    out_ipv4_header->tos = (uint8_t) (
        (context->configuration->translator_6to4_copy_dscp_and_ecn) ?
        ((in_ipv6_header->priority << 4) | (in_ipv6_header->flow_lbl[0] >> 4)) :
        (0)
    );

    // :: Flow label (discarded during translation, no validation needs to be done)

    // :: Payload length -> Total length (input packet validated, correct value in output packet set later)
    if(ntohs(in_ipv6_header->payload_len) != (context->in_packet_size - 40))
        return false;
    out_ipv4_header->tot_len = 0; // Set to a correct value later

    // :: Hop limit -> TTL (decremented, possible time exceeded ICMP packet sent later)
    if(in_ipv6_header->hop_limit < 1)
        return false; // The packet should have already been dropped!
    out_ipv4_header->ttl = (in_ipv6_header->hop_limit - 1);

    // :: Header checksum (computed later, when the packet is finished)
    out_ipv4_header->check = 0; // Set to 0 (necessary for the checksum computation happening later)

    // :: Next header, extension headers -> Protocol, identification, fragment offset, flags
    {
        const uint8_t *current_header_ptr = (const uint8_t *) (context->in_packet_buffer + 40);
        ssize_t remaining_packet_size = ((ssize_t) context->in_packet_size) - 40;
        uint8_t current_header_number = in_ipv6_header->nexthdr;
        const t64ts_tundra__ipv6_fragment_header *ipv6_fragment_header_ptr = NULL;

        while(
            (ipv6_fragment_header_ptr == NULL) &&
            (current_header_number == 0 || current_header_number == 43 || current_header_number == 44 || current_header_number == 60)
        ) {
            if(remaining_packet_size < 8)
                return false;

            if(current_header_number == 43) { // Routing Header for IPv6
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

            } else if(current_header_number == 44) { // Fragment Header
                ipv6_fragment_header_ptr = (const t64ts_tundra__ipv6_fragment_header *) current_header_ptr;

                if(ipv6_fragment_header_ptr->reserved != 0 || T64M_UTILS_IP__GET_IPV6_FRAGMENT_RESERVED_BITS(ipv6_fragment_header_ptr) != 0)
                    return false;
            }

            current_header_number = current_header_ptr[0]; // The first field of every IPv6 extension header is "next header"

            // current_header_ptr[1] is guaranteed to be zero in case of a fragment header (checked above)
            const ssize_t current_header_size = 8 + (((ssize_t) current_header_ptr[1]) * 8);
            current_header_ptr += current_header_size; // Move to a next header or the payload
            remaining_packet_size -= current_header_size;
        }

        if(remaining_packet_size < 0)
            return false;

        if(
            t64f_utils_ip__is_ip_protocol_number_forbidden(current_header_number) ||
            (current_header_number == 1) // Internet Control Message Protocol (ICMPv4)
        ) return false;

        // --- Save & act upon the "gathered information" ---
        out_packet_data->payload_ptr = current_header_ptr;
        out_packet_data->payload_size = (size_t) remaining_packet_size;

        out_ipv4_header->protocol = (current_header_number == 58) ? 1 : current_header_number;

        if(ipv6_fragment_header_ptr != NULL) {
            // If there are more fragments after this one, this fragment's payload size must be a multiple of 8, as
            //  fragment offsets in IPv4/v6 headers are specified in 8-byte units.
            const uint16_t more_fragments = T64M_UTILS_IP__GET_IPV6_FRAGMENT_MORE_FRAGMENTS_BIT(ipv6_fragment_header_ptr);
            if(more_fragments && (out_packet_data->payload_size % 8) != 0)
                return false;

            const uint16_t fragment_offset = T64M_UTILS_IP__GET_IPV6_FRAGMENT_OFFSET(ipv6_fragment_header_ptr);

            out_ipv4_header->id = ipv6_fragment_header_ptr->identification[1];
            out_ipv4_header->frag_off = T64M_UTILS_IP__CONSTRUCT_IPV4_FRAGMENT_OFFSET_AND_FLAGS_FIELD(0, more_fragments, fragment_offset);

            out_packet_data->is_fragment_offset_zero = (bool) (fragment_offset == 0);
        } else {
            t64f_utils_ip__generate_ipv4_fragment_identifier(context, (uint8_t *) &out_ipv4_header->id);
            out_ipv4_header->frag_off = 0;

            out_packet_data->is_fragment_offset_zero = true;
        }
    }

    // :: Source & destination IP address
    // NOTE: All header fields of the input packet (including any IPv4 options) have been validated at this point,
    //  except the source & destination IP address; therefore, after validating these two fields, the address
    //  translation function may choose to send an ICMP error message back to the source host.
    if(!t64f_xlat_addr__perform_6to4_address_translation_for_main_packet(
        context,
        (const uint8_t *) (in_ipv6_header->saddr.s6_addr),
        (const uint8_t *) (in_ipv6_header->daddr.s6_addr),
        (uint8_t *) &out_ipv4_header->saddr,
        (uint8_t *) &out_ipv4_header->daddr
    )) return false;

    // If the input IPv6 packet has a fragment header, it does not necessarily mean that the packet is fragmented -
    //  it is possible for the fragment header to have both its offset and the more fragments bit set to zero, which
    //  effectively means that the program has the whole, unfragmented packet on its hands.
    out_packet_data->is_fragment = (bool) T64MM_UTILS_IP__IS_IPV4_PACKET_FRAGMENTED(out_ipv4_header);

    return true;
}

static void _t64f_xlat_6to4__translate_icmpv6_payload_to_icmpv4_and_send(t64ts_tundra__xlat_thread_context *context, _t64ts_xlat_6to4__out_ipv4_packet_data *out_packet_data) {
    if(out_packet_data->is_fragment)
        return;

    // The IPv6 header at the beginning of 'context->in_packet_buffer' has already been validated at this point.
    if(t64f_checksum__calculate_rfc1071_checksum_for_ipv6(out_packet_data->payload_ptr, out_packet_data->payload_size, NULL, 0, (const struct ipv6hdr *) context->in_packet_buffer, 58) != 0)
        return;

    t64ts_xlat_6to4_icmp__out_icmpv4_message_data out_message_data;
    if(!t64f_xlat_6to4_icmp__translate_icmpv6_to_icmpv4(
        context,
        out_packet_data->payload_ptr,
        out_packet_data->payload_size,
        &out_message_data
    )) return;

    if(out_message_data.nullable_message_end_ptr == NULL)
        _t64f_xlat_6to4__appropriately_send_ipv4_packet(
            context, &out_packet_data->ipv4_header,
            NULL, 0,
            out_message_data.message_start_36b, out_message_data.message_start_size_m8u
        );
    else
        _t64f_xlat_6to4__appropriately_send_ipv4_packet(
            context, &out_packet_data->ipv4_header,
            out_message_data.message_start_36b, out_message_data.message_start_size_m8u,
            out_message_data.nullable_message_end_ptr, out_message_data.zeroable_message_end_size
        );
}

static void _t64f_xlat_6to4__translate_tcp_payload_and_send(const t64ts_tundra__xlat_thread_context *context, _t64ts_xlat_6to4__out_ipv4_packet_data *out_packet_data) {
    if(out_packet_data->is_fragment_offset_zero && out_packet_data->payload_size >= 20) { // 20 or more bytes
        uint8_t new_tcp_payload_start_buffer[24];
        struct tcphdr *new_tcp_header = (struct tcphdr *) new_tcp_payload_start_buffer;

        if(out_packet_data->payload_size >= 24) { // 24 or more bytes
            memcpy(new_tcp_payload_start_buffer, out_packet_data->payload_ptr, 24);

            new_tcp_header->check = t64f_checksum__incrementally_recalculate_rfc1071_checksum_6to4(new_tcp_header->check, (const struct ipv6hdr *) context->in_packet_buffer, &out_packet_data->ipv4_header);

            _t64f_xlat_6to4__appropriately_send_ipv4_packet(
                context, &out_packet_data->ipv4_header,
                new_tcp_payload_start_buffer, 24,
                (out_packet_data->payload_ptr + 24), (out_packet_data->payload_size - 24)
            );
        } else { // 20, 21, 22 or 23 bytes
            memcpy(new_tcp_payload_start_buffer, out_packet_data->payload_ptr, out_packet_data->payload_size);

            new_tcp_header->check = t64f_checksum__incrementally_recalculate_rfc1071_checksum_6to4(new_tcp_header->check, (const struct ipv6hdr *) context->in_packet_buffer, &out_packet_data->ipv4_header);

            _t64f_xlat_6to4__appropriately_send_ipv4_packet(
                context, &out_packet_data->ipv4_header,
                NULL, 0,
                new_tcp_payload_start_buffer, out_packet_data->payload_size
            );
        }
    } else {
        _t64f_xlat_6to4__appropriately_send_ipv4_packet(
            context, &out_packet_data->ipv4_header,
            NULL, 0,
            out_packet_data->payload_ptr, out_packet_data->payload_size
        );
    }
}

static void _t64f_xlat_6to4__translate_udp_payload_and_send(const t64ts_tundra__xlat_thread_context *context, _t64ts_xlat_6to4__out_ipv4_packet_data *out_packet_data) {
    if(out_packet_data->is_fragment_offset_zero && out_packet_data->payload_size >= 8) {
        struct udphdr new_udp_header;
        memcpy(&new_udp_header, out_packet_data->payload_ptr, 8);

        if(new_udp_header.check == 0)
            return;

        const uint16_t new_checksum = t64f_checksum__incrementally_recalculate_rfc1071_checksum_6to4(new_udp_header.check, (const struct ipv6hdr *) context->in_packet_buffer, &out_packet_data->ipv4_header);
        new_udp_header.check = (new_checksum == 0 ? 0xffff : new_checksum);

        _t64f_xlat_6to4__appropriately_send_ipv4_packet(
            context, &out_packet_data->ipv4_header,
            (const uint8_t *) &new_udp_header, 8,
            (out_packet_data->payload_ptr + 8), (out_packet_data->payload_size - 8)
        );
    } else {
        _t64f_xlat_6to4__appropriately_send_ipv4_packet(
            context, &out_packet_data->ipv4_header,
            NULL, 0,
            out_packet_data->payload_ptr, out_packet_data->payload_size
        );
    }
}

static void _t64f_xlat_6to4__translate_generic_payload_and_send(const t64ts_tundra__xlat_thread_context *context, _t64ts_xlat_6to4__out_ipv4_packet_data *out_packet_data) {
    _t64f_xlat_6to4__appropriately_send_ipv4_packet(
        context, &out_packet_data->ipv4_header,
        NULL, 0,
        out_packet_data->payload_ptr, out_packet_data->payload_size
    );
}

static void _t64f_xlat_6to4__appropriately_send_ipv4_packet(
    const t64ts_tundra__xlat_thread_context *context,
    struct iphdr *ipv4_header,
    const uint8_t *nullable_payload1_ptr,
    const size_t zeroable_payload1_size_m8,
    const uint8_t *payload2_ptr,
    const size_t payload2_size
) {
    const size_t total_packet_size = 20 + zeroable_payload1_size_m8 + payload2_size;
    const uint16_t more_fragments = T64M_UTILS_IP__GET_IPV4_MORE_FRAGMENTS_BIT(ipv4_header);
    const uint16_t fragment_offset = T64M_UTILS_IP__GET_IPV4_FRAGMENT_OFFSET(ipv4_header);

    if(total_packet_size <= 1260) {
        ipv4_header->frag_off = T64M_UTILS_IP__CONSTRUCT_IPV4_FRAGMENT_OFFSET_AND_FLAGS_FIELD(0, more_fragments, fragment_offset);

        if(total_packet_size > context->configuration->translator_ipv4_outbound_mtu) {
            _t64f_xlat_6to4__fragment_and_send_ipv4_packet(context, ipv4_header, nullable_payload1_ptr, zeroable_payload1_size_m8, payload2_ptr, payload2_size);
        } else {
            t64f_xlat_io__send_ipv4_packet(context, ipv4_header, nullable_payload1_ptr, zeroable_payload1_size_m8, payload2_ptr, payload2_size);
        }
    } else {
        if(total_packet_size > context->configuration->translator_ipv4_outbound_mtu) {
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
            t64f_router_ipv6__send_icmpv6_packet_too_big_message_to_in_ipv6_packet_source_host(
                context,
                T64MM_UTILS__MAXIMUM(1280, (uint16_t) (context->configuration->translator_ipv4_outbound_mtu + 20))
            );
        } else {
            ipv4_header->frag_off = T64M_UTILS_IP__CONSTRUCT_IPV4_FRAGMENT_OFFSET_AND_FLAGS_FIELD(1, more_fragments, fragment_offset);

            t64f_xlat_io__send_ipv4_packet(context, ipv4_header, nullable_payload1_ptr, zeroable_payload1_size_m8, payload2_ptr, payload2_size);
        }
    }
}

static void _t64f_xlat_6to4__fragment_and_send_ipv4_packet(
    const t64ts_tundra__xlat_thread_context *context,
    struct iphdr *ipv4_header,
    const uint8_t *nullable_payload1_ptr,
    const size_t zeroable_payload1_size_m8,
    const uint8_t *payload2_ptr,
    const size_t payload2_size
) {
    if((zeroable_payload1_size_m8 % 8) != 0)
        return; // This should never happen!

    // Compute the maximum size of a fragment's payload
    size_t max_fragment_payload_size = (context->configuration->translator_ipv4_outbound_mtu - 20);
    max_fragment_payload_size -= (max_fragment_payload_size % 8); // Fragment offsets are specified in 8-byte units

    // Initialize the necessary variables
    size_t fragment_offset_8byte_chunks = T64M_UTILS_IP__GET_IPV4_FRAGMENT_OFFSET(ipv4_header);
    const bool more_fragments_after_this_packet = (bool) T64M_UTILS_IP__GET_IPV4_MORE_FRAGMENTS_BIT(ipv4_header);
    const bool dont_fragment = (bool) T64M_UTILS_IP__GET_IPV4_DONT_FRAGMENT_BIT(ipv4_header);

    // Send the first part of payload
    if(nullable_payload1_ptr != NULL && zeroable_payload1_size_m8 > 0) {
        if(!_t64f_xlat_6to4__fragment_and_send_ipv4_packet_part(
            context,
            ipv4_header,
            nullable_payload1_ptr,
            zeroable_payload1_size_m8,
            &fragment_offset_8byte_chunks,
            (payload2_size > 0 ? true : more_fragments_after_this_packet),
            dont_fragment,
            max_fragment_payload_size
        )) return;
    }

    // Send the second part of payload
    if(payload2_size > 0)
        (void) _t64f_xlat_6to4__fragment_and_send_ipv4_packet_part(
            context,
            ipv4_header,
            payload2_ptr,
            payload2_size,
            &fragment_offset_8byte_chunks,
            more_fragments_after_this_packet,
            dont_fragment,
            max_fragment_payload_size
        );
}

static bool _t64f_xlat_6to4__fragment_and_send_ipv4_packet_part(
    const t64ts_tundra__xlat_thread_context *context,
    struct iphdr *ready_ipv4_header,
    const uint8_t *current_payload_part_ptr,
    size_t remaining_payload_part_size,
    size_t *fragment_offset_8byte_chunks,
    const bool more_fragments_after_this_part,
    const bool dont_fragment,
    const size_t max_fragment_payload_size
) {
    if(more_fragments_after_this_part && (remaining_payload_part_size % 8) != 0)
        return false;

    while(remaining_payload_part_size > 0) {
        const size_t this_fragment_payload_size = T64MM_UTILS__MINIMUM(remaining_payload_part_size, max_fragment_payload_size);
        const bool more_fragments_after_this_fragment = (remaining_payload_part_size > max_fragment_payload_size ? true : more_fragments_after_this_part);

        if (*fragment_offset_8byte_chunks > 8191) // (2^13) - 1 == 8191 (fragment offset is stored in 13 bits)
            return false;

        ready_ipv4_header->frag_off = T64M_UTILS_IP__CONSTRUCT_IPV4_FRAGMENT_OFFSET_AND_FLAGS_FIELD(
            (uint16_t) dont_fragment,
            (uint16_t) more_fragments_after_this_fragment,
            (uint16_t) *fragment_offset_8byte_chunks
        );

        t64f_xlat_io__send_ipv4_packet(context, ready_ipv4_header, current_payload_part_ptr, this_fragment_payload_size, NULL, 0);

        current_payload_part_ptr += this_fragment_payload_size;
        remaining_payload_part_size -= this_fragment_payload_size;
        *fragment_offset_8byte_chunks += (this_fragment_payload_size / 8);
    }

    return true;
}
