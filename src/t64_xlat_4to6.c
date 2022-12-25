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
#include"t64_xlat_4to6.h"

#include"t64_utils.h"
#include"t64_utils_ip.h"
#include"t64_checksum.h"
#include"t64_xlat_io.h"
#include"t64_xlat_4to6_icmp.h"
#include"t64_router_ipv4.h"
#include"t64_xlat_addr.h"


typedef struct {
    struct ipv6hdr ipv6_header;
    t64ts_tundra__ipv6_fragment_header ipv6_fragment_header; // Invalid if 'is_fragment' == false
    const uint8_t *payload_ptr; // Points to a part of 'context->in_packet_buffer' --> must not be modified!
    size_t payload_size;
    uint8_t carried_protocol;
    bool is_fragment;
    bool is_fragment_offset_zero;
    bool dont_fragment;
} _t64ts_xlat_4to6__out_ipv6_packet_data;


static bool _t64f_xlat_4to6__validate_and_translate_ip_header(t64ts_tundra__xlat_thread_context *context, _t64ts_xlat_4to6__out_ipv6_packet_data *out_packet_data);
static void _t64f_xlat_4to6__translate_icmpv4_payload_to_icmpv6_and_send(t64ts_tundra__xlat_thread_context *context, _t64ts_xlat_4to6__out_ipv6_packet_data *out_packet_data);
static void _t64f_xlat_4to6__translate_tcp_payload_and_send(t64ts_tundra__xlat_thread_context *context, _t64ts_xlat_4to6__out_ipv6_packet_data *out_packet_data);
static void _t64f_xlat_4to6__translate_udp_payload_and_send(t64ts_tundra__xlat_thread_context *context, _t64ts_xlat_4to6__out_ipv6_packet_data *out_packet_data);
static void _t64f_xlat_4to6__translate_generic_payload_and_send(t64ts_tundra__xlat_thread_context *context, _t64ts_xlat_4to6__out_ipv6_packet_data *out_packet_data);
static void _t64f_xlat_4to6__appropriately_send_ipv6_packet(t64ts_tundra__xlat_thread_context *context, struct ipv6hdr *ipv6_header, const t64ts_tundra__ipv6_fragment_header *nullable_ipv6_fragment_header, const uint8_t *nullable_payload1_ptr, const size_t zeroable_payload1_size_m8, const uint8_t *payload2_ptr, const size_t payload2_size, const bool dont_fragment);
static void _t64f_xlat_4to6__fragment_and_send_ipv6_packet(t64ts_tundra__xlat_thread_context *context, struct ipv6hdr *ipv6_header, const t64ts_tundra__ipv6_fragment_header *nullable_ipv6_fragment_header, const uint8_t *nullable_payload1_ptr, const size_t zeroable_payload1_size_m8, const uint8_t *payload2_ptr, const size_t payload2_size);
static bool _t64f_xlat_4to6__fragment_and_send_ipv6_packet_part(const t64ts_tundra__xlat_thread_context *context, struct ipv6hdr *ready_ipv6_header, t64ts_tundra__ipv6_fragment_header *ready_ipv6_fragment_header, const uint8_t *payload_part_ptr, const size_t payload_part_size, size_t *fragment_offset_8byte_chunks, const bool more_fragments_after_this_part, const size_t max_fragment_payload_size);


void t64f_xlat_4to6__handle_packet(t64ts_tundra__xlat_thread_context *context) {
    _t64ts_xlat_4to6__out_ipv6_packet_data out_packet_data;
    if(!_t64f_xlat_4to6__validate_and_translate_ip_header(context, &out_packet_data))
        return;

    // At this moment, the entire in_packet's IPv4 header has been validated (including any IPv4 options);
    //  therefore, it is now safe to send ICMP messages back to the packet's source host.
    if(out_packet_data.ipv6_header.hop_limit < 1) {
        t64f_router_ipv4__send_icmpv4_time_exceeded_message_to_in_ipv4_packet_source_host(context);
        return;
    }

    switch(out_packet_data.carried_protocol) {
        case 6: // TCP
            _t64f_xlat_4to6__translate_tcp_payload_and_send(context, &out_packet_data);
            break;

        case 17: // UDP
            _t64f_xlat_4to6__translate_udp_payload_and_send(context, &out_packet_data);
            break;

        case 58: // ICMPv6
            _t64f_xlat_4to6__translate_icmpv4_payload_to_icmpv6_and_send(context, &out_packet_data);
            break;

        default:
            _t64f_xlat_4to6__translate_generic_payload_and_send(context, &out_packet_data);
            break;
    }
}

static bool _t64f_xlat_4to6__validate_and_translate_ip_header(t64ts_tundra__xlat_thread_context *context, _t64ts_xlat_4to6__out_ipv6_packet_data *out_packet_data) {
    if(context->in_packet_size < 20)
        return false;

    const struct iphdr *in_ipv4_header = (const struct iphdr *) context->in_packet_buffer;
    struct ipv6hdr *out_ipv6_header = &out_packet_data->ipv6_header;

    // :: IP version ('in_ipv4_header->version' is guaranteed to be 4)
    out_ipv6_header->version = 6;

    // :: IHL (validated, discarded during translation)
    const size_t in_ipv4_header_size = ((size_t) in_ipv4_header->ihl) * 4;
    if(in_ipv4_header_size < 20 || in_ipv4_header_size > context->in_packet_size)
        return false;

    // :: DSCP & ECN -> Traffic class; Flow label (no validation needs to be done)
    if(context->configuration->translator_4to6_copy_dscp_and_ecn) {
        out_ipv6_header->priority = (uint8_t) (in_ipv4_header->tos >> 4);
        out_ipv6_header->flow_lbl[0] = (uint8_t) (in_ipv4_header->tos << 4);
    } else {
        out_ipv6_header->priority = 0;
        out_ipv6_header->flow_lbl[0] = 0;
    }
    out_ipv6_header->flow_lbl[1] = 0;
    out_ipv6_header->flow_lbl[2] = 0;

    // :: Total length -> Payload length (input packet validated, correct value in output packet set later)
    if(ntohs(in_ipv4_header->tot_len) != context->in_packet_size)
        return false;
    out_ipv6_header->payload_len = 0; // Set to a correct value later

    // :: Reserved bit (part of the flags field)
    if(T64M_UTILS_IP__GET_IPV4_FRAGMENT_RESERVED_BIT(in_ipv4_header) != 0)
        return false;

    // :: TTL -> Hop limit (decremented, possible time exceeded ICMP packet sent later)
    if(in_ipv4_header->ttl < 1)
        return false; // The packet should have already been dropped!
    out_ipv6_header->hop_limit = (in_ipv4_header->ttl - 1);

    // :: Header checksum (validated, discarded during translation)
    if(t64f_checksum__calculate_ipv4_header_checksum(in_ipv4_header) != 0)
        return false;

    // :: IPv4 Options (validated, discarded during translation)
    {
        /*
         * From RFC 7915, section 4.1:
         *  If any IPv4 options are present in the IPv4 packet, they MUST be
         *  ignored and the packet translated normally; there is no attempt to
         *  translate the options.  However, if an unexpired source route option
         *  is present, then the packet MUST instead be discarded, and an ICMPv4
         *  "Destination Unreachable, Source Route Failed" (Type 3, Code 5) error
         *  message SHOULD be returned to the sender.
         */

        const uint8_t *current_option_ptr = (const uint8_t *) (context->in_packet_buffer + 20);
        ssize_t remaining_options_size = ((ssize_t) in_ipv4_header_size) - 20;

        while(remaining_options_size > 0) {
            const uint8_t option_type = *current_option_ptr;
            if(option_type == 131 || option_type == 137) // Loose Source Route, Strict Source Route
                return false;

            ssize_t current_option_size; // https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
            if(option_type == 0 || option_type == 1) { // End of Options List, No Operation
                current_option_size = 1;
            } else {
                if(remaining_options_size < 2)
                    return false;

                current_option_size = current_option_ptr[1];
                if(current_option_size < 2)
                    return false;
            }

            current_option_ptr += current_option_size;
            remaining_options_size -= current_option_size;
            if(remaining_options_size < 0)
                return false;
        }
    }

    // :: Protocol -> Next header (possibly in the fragment header)
    if(
        t64f_utils_ip__is_ip_protocol_number_forbidden(in_ipv4_header->protocol) ||
        (in_ipv4_header->protocol == 58) // ICMP for IPv6
    ) return false;
    const uint8_t ipv6_carried_protocol = (in_ipv4_header->protocol == 1) ? 58 : in_ipv4_header->protocol;

    // :: DF bit (saved for later)
    out_packet_data->dont_fragment = (bool) T64M_UTILS_IP__GET_IPV4_DONT_FRAGMENT_BIT(in_ipv4_header);

    // :: Fragment offset
    const uint16_t fragment_offset = T64M_UTILS_IP__GET_IPV4_FRAGMENT_OFFSET(in_ipv4_header);
    out_packet_data->is_fragment_offset_zero = (bool) (fragment_offset == 0);

    // :: Identification, fragment offset & MF bit -> Fragmentation header
    t64ts_tundra__ipv6_fragment_header *out_ipv6_fragment_header = &out_packet_data->ipv6_fragment_header;
    if(T64MM_UTILS_IP__IS_IPV4_PACKET_FRAGMENTED(in_ipv4_header)) {
        out_ipv6_header->nexthdr = 44;

        out_ipv6_fragment_header->next_header = ipv6_carried_protocol;
        out_ipv6_fragment_header->reserved = 0;
        out_ipv6_fragment_header->offset_and_flags = T64M_UTILS_IP__CONSTRUCT_IPV6_FRAGMENT_OFFSET_AND_FLAGS_FIELD(
            fragment_offset,
            T64M_UTILS_IP__GET_IPV4_MORE_FRAGMENTS_BIT(in_ipv4_header)
        );
        out_ipv6_fragment_header->identification[0] = 0;
        out_ipv6_fragment_header->identification[1] = in_ipv4_header->id;

        out_packet_data->is_fragment = true;
    } else {
        out_ipv6_header->nexthdr = ipv6_carried_protocol;

        T64M_UTILS__MEMORY_ZERO_OUT(out_ipv6_fragment_header, sizeof(t64ts_tundra__ipv6_fragment_header));

        out_packet_data->is_fragment = false;
    }

    // :: Source & destination IP address
    // NOTE: All header fields of the input packet (including any IPv4 options) have been validated at this point,
    //  except the source & destination IP address; therefore, after validating these two fields, the address
    //  translation function may choose to send an ICMP error message back to the source host.
    if(!t64f_xlat_addr__perform_4to6_address_translation_for_main_packet(
        context,
        (const uint8_t *) &in_ipv4_header->saddr,
        (const uint8_t *) &in_ipv4_header->daddr,
        (uint8_t *) (out_ipv6_header->saddr.s6_addr),
        (uint8_t *) (out_ipv6_header->daddr.s6_addr)
    )) return false;

    out_packet_data->payload_ptr = (const uint8_t *) (context->in_packet_buffer + in_ipv4_header_size);
    out_packet_data->payload_size = (context->in_packet_size - in_ipv4_header_size);
    out_packet_data->carried_protocol = ipv6_carried_protocol;

    return true;
}

static void _t64f_xlat_4to6__translate_icmpv4_payload_to_icmpv6_and_send(t64ts_tundra__xlat_thread_context *context, _t64ts_xlat_4to6__out_ipv6_packet_data *out_packet_data) {
    // https://www.rfc-editor.org/rfc/rfc7915.html#page-4 -> "Fragmented ICMP/ICMPv6 packets will not be translated by IP/ICMP translators."
    if(out_packet_data->is_fragment)
        return;

    if(t64f_checksum__calculate_rfc1071_checksum_for_ipv4(out_packet_data->payload_ptr, out_packet_data->payload_size, NULL, 0, NULL) != 0)
        return;

    t64ts_xlat_4to6_icmp__out_icmpv6_message_data out_message_data;
    if(!t64f_xlat_4to6_icmp__translate_icmpv4_to_icmpv6(
        context,
        out_packet_data->payload_ptr,
        out_packet_data->payload_size,
        (const struct ipv6hdr *) &out_packet_data->ipv6_header,
        &out_message_data
    )) return;

    _t64f_xlat_4to6__appropriately_send_ipv6_packet(
        context, &out_packet_data->ipv6_header, (out_packet_data->is_fragment ? &out_packet_data->ipv6_fragment_header : NULL),
        out_message_data.message_start_64b, out_message_data.message_start_size_m8,
        out_message_data.message_end_ptr, out_message_data.message_end_size,
        out_packet_data->dont_fragment
    );
}

static void _t64f_xlat_4to6__translate_tcp_payload_and_send(t64ts_tundra__xlat_thread_context *context, _t64ts_xlat_4to6__out_ipv6_packet_data *out_packet_data) {
    if(out_packet_data->is_fragment_offset_zero && out_packet_data->payload_size >= 20) { // 20 or more bytes
        uint8_t new_tcp_payload_start_buffer[24];
        struct tcphdr *new_tcp_header = (struct tcphdr *) new_tcp_payload_start_buffer;

        if(out_packet_data->payload_size >= 24) { // 24 or more bytes
            memcpy(new_tcp_payload_start_buffer, out_packet_data->payload_ptr, 24);

            new_tcp_header->check = t64f_checksum__incrementally_recalculate_rfc1071_checksum_4to6(new_tcp_header->check, (const struct iphdr *) context->in_packet_buffer, &out_packet_data->ipv6_header);

            _t64f_xlat_4to6__appropriately_send_ipv6_packet(
                context, &out_packet_data->ipv6_header, (out_packet_data->is_fragment ? &out_packet_data->ipv6_fragment_header : NULL),
                new_tcp_payload_start_buffer, 24,
                (out_packet_data->payload_ptr + 24), (out_packet_data->payload_size - 24),
                out_packet_data->dont_fragment
            );
        } else { // 20, 21, 22 or 23 bytes
            memcpy(new_tcp_payload_start_buffer, out_packet_data->payload_ptr, out_packet_data->payload_size);

            new_tcp_header->check = t64f_checksum__incrementally_recalculate_rfc1071_checksum_4to6(new_tcp_header->check, (const struct iphdr *) context->in_packet_buffer, &out_packet_data->ipv6_header);

            _t64f_xlat_4to6__appropriately_send_ipv6_packet(
                context, &out_packet_data->ipv6_header, (out_packet_data->is_fragment ? &out_packet_data->ipv6_fragment_header : NULL),
                NULL, 0,
                new_tcp_payload_start_buffer, out_packet_data->payload_size,
                out_packet_data->dont_fragment
            );
        }
    } else {
        _t64f_xlat_4to6__appropriately_send_ipv6_packet(
            context, &out_packet_data->ipv6_header, (out_packet_data->is_fragment ? &out_packet_data->ipv6_fragment_header : NULL),
            NULL, 0,
            out_packet_data->payload_ptr, out_packet_data->payload_size,
            out_packet_data->dont_fragment
        );
    }
}

static void _t64f_xlat_4to6__translate_udp_payload_and_send(t64ts_tundra__xlat_thread_context *context, _t64ts_xlat_4to6__out_ipv6_packet_data *out_packet_data) {
    if(out_packet_data->is_fragment_offset_zero && out_packet_data->payload_size >= 8) {
        struct udphdr new_udp_header;
        memcpy(&new_udp_header, out_packet_data->payload_ptr, 8);

        if(new_udp_header.check == 0)
            return;

        const uint16_t new_checksum = t64f_checksum__incrementally_recalculate_rfc1071_checksum_4to6(new_udp_header.check, (const struct iphdr *) context->in_packet_buffer, &out_packet_data->ipv6_header);
        new_udp_header.check = (new_checksum == 0 ? 0xffff : new_checksum);

        _t64f_xlat_4to6__appropriately_send_ipv6_packet(
            context, &out_packet_data->ipv6_header, (out_packet_data->is_fragment ? &out_packet_data->ipv6_fragment_header : NULL),
            (const uint8_t *) &new_udp_header, 8,
            (out_packet_data->payload_ptr + 8), (out_packet_data->payload_size - 8),
            out_packet_data->dont_fragment
        );
    } else {
        _t64f_xlat_4to6__appropriately_send_ipv6_packet(
            context, &out_packet_data->ipv6_header, (out_packet_data->is_fragment ? &out_packet_data->ipv6_fragment_header : NULL),
            NULL, 0,
            out_packet_data->payload_ptr, out_packet_data->payload_size,
            out_packet_data->dont_fragment
        );
    }
}

static void _t64f_xlat_4to6__translate_generic_payload_and_send(t64ts_tundra__xlat_thread_context *context, _t64ts_xlat_4to6__out_ipv6_packet_data *out_packet_data) {
    _t64f_xlat_4to6__appropriately_send_ipv6_packet(
        context, &out_packet_data->ipv6_header, (out_packet_data->is_fragment ? &out_packet_data->ipv6_fragment_header : NULL),
        NULL, 0,
        out_packet_data->payload_ptr, out_packet_data->payload_size,
        out_packet_data->dont_fragment
    );
}

static void _t64f_xlat_4to6__appropriately_send_ipv6_packet(
    t64ts_tundra__xlat_thread_context *context,
    struct ipv6hdr *ipv6_header,
    const t64ts_tundra__ipv6_fragment_header *nullable_ipv6_fragment_header,
    const uint8_t *nullable_payload1_ptr,
    const size_t zeroable_payload1_size_m8,
    const uint8_t *payload2_ptr,
    const size_t payload2_size,
    const bool dont_fragment
) {
    const size_t total_packet_size = 40 + (nullable_ipv6_fragment_header != NULL ? 8 : 0) + zeroable_payload1_size_m8 + payload2_size;

    if(total_packet_size > context->configuration->translator_ipv6_outbound_mtu) {
        if(dont_fragment) {
            // Why (IPv6 MTU - 28)? "Worst case scenario" example: The IPv6 MTU is 1280 bytes; the IPv4 host sends a
            //  1252-byte (1280 - 28) fragmented IPv4 packet whose header has 20 bytes; during translation, the IPv4
            //  header is stripped, resulting in 1232 bytes of data; the 40-byte IPv6 header and 8-byte fragmentation
            //  extension header is prepended to the data, resulting in a 1280-byte IPv6 packet (the biggest packet that
            //  fits into the IPv6 MTU)
            t64f_router_ipv4__send_icmpv4_fragmentation_needed_message_to_in_ipv4_packet_source_host(
                context,
                (uint16_t) (context->configuration->translator_ipv6_outbound_mtu - 28)
            );
        } else {
            _t64f_xlat_4to6__fragment_and_send_ipv6_packet(context, ipv6_header, nullable_ipv6_fragment_header, nullable_payload1_ptr, zeroable_payload1_size_m8, payload2_ptr, payload2_size);
        }
    } else {
        t64f_xlat_io__send_ipv6_packet(context, ipv6_header, nullable_ipv6_fragment_header, nullable_payload1_ptr, zeroable_payload1_size_m8, payload2_ptr, payload2_size);
    }
}

static void _t64f_xlat_4to6__fragment_and_send_ipv6_packet(
    t64ts_tundra__xlat_thread_context *context,
    struct ipv6hdr *ipv6_header,
    const t64ts_tundra__ipv6_fragment_header *nullable_ipv6_fragment_header,
    const uint8_t *nullable_payload1_ptr,
    const size_t zeroable_payload1_size_m8,
    const uint8_t *payload2_ptr,
    const size_t payload2_size
) {
    if((zeroable_payload1_size_m8 % 8) != 0)
        return; // This should never happen!

    // Compute the maximum size of a fragment's payload
    size_t max_fragment_payload_size = (context->configuration->translator_ipv6_outbound_mtu - 48);
    max_fragment_payload_size -= (max_fragment_payload_size % 8); // Fragment offsets are specified in 8-byte units

    // Initialize the necessary variables
    t64ts_tundra__ipv6_fragment_header new_ipv6_fragment_header;
    size_t fragment_offset_8byte_chunks;
    bool more_fragments_after_this_packet;
    if(nullable_ipv6_fragment_header != NULL) {
        memcpy(&new_ipv6_fragment_header, nullable_ipv6_fragment_header, 8);

        fragment_offset_8byte_chunks = T64M_UTILS_IP__GET_IPV6_FRAGMENT_OFFSET(nullable_ipv6_fragment_header);
        more_fragments_after_this_packet = (bool) T64M_UTILS_IP__GET_IPV6_FRAGMENT_MORE_FRAGMENTS_BIT(nullable_ipv6_fragment_header);
    } else {
        new_ipv6_fragment_header.next_header = ipv6_header->nexthdr;
        new_ipv6_fragment_header.reserved = 0;
        new_ipv6_fragment_header.offset_and_flags = 0;
        t64f_utils_ip__generate_ipv6_fragment_identifier(context, (uint8_t *) new_ipv6_fragment_header.identification);

        ipv6_header->nexthdr = 44;

        fragment_offset_8byte_chunks = 0;
        more_fragments_after_this_packet = false;
    }

    // Send the first part of payload
    if(nullable_payload1_ptr != NULL && zeroable_payload1_size_m8 > 0) {
        if(!_t64f_xlat_4to6__fragment_and_send_ipv6_packet_part(
            context,
            ipv6_header,
            &new_ipv6_fragment_header,
            nullable_payload1_ptr,
            zeroable_payload1_size_m8,
            &fragment_offset_8byte_chunks,
            (payload2_size > 0 ? true : more_fragments_after_this_packet),
            max_fragment_payload_size
        )) return;
    }

    // Send the second part of payload
    if(payload2_size > 0)
        (void) _t64f_xlat_4to6__fragment_and_send_ipv6_packet_part(
            context,
            ipv6_header,
            &new_ipv6_fragment_header,
            payload2_ptr,
            payload2_size,
            &fragment_offset_8byte_chunks,
            more_fragments_after_this_packet,
            max_fragment_payload_size
        );
}

static bool _t64f_xlat_4to6__fragment_and_send_ipv6_packet_part(
    const t64ts_tundra__xlat_thread_context *context,
    struct ipv6hdr *ready_ipv6_header,
    t64ts_tundra__ipv6_fragment_header *ready_ipv6_fragment_header,
    const uint8_t *current_payload_part_ptr,
    size_t remaining_payload_part_size,
    size_t *fragment_offset_8byte_chunks,
    const bool more_fragments_after_this_part,
    const size_t max_fragment_payload_size
) {
    if(more_fragments_after_this_part && (remaining_payload_part_size % 8) != 0)
        return false;

    while(remaining_payload_part_size > 0) {
        const size_t this_fragment_payload_size = T64MM_UTILS__MINIMUM(remaining_payload_part_size, max_fragment_payload_size);
        const bool more_fragments_after_this_fragment = (remaining_payload_part_size > max_fragment_payload_size ? true : more_fragments_after_this_part);

        if(*fragment_offset_8byte_chunks > 8191) // (2^13) - 1 == 8191 (fragment offset is stored in 13 bits)
            return false;

        ready_ipv6_fragment_header->offset_and_flags = T64M_UTILS_IP__CONSTRUCT_IPV6_FRAGMENT_OFFSET_AND_FLAGS_FIELD(
            (uint16_t) *fragment_offset_8byte_chunks,
            (uint16_t) more_fragments_after_this_fragment
        );

        t64f_xlat_io__send_ipv6_packet(context, ready_ipv6_header, ready_ipv6_fragment_header, current_payload_part_ptr, this_fragment_payload_size, NULL, 0);

        current_payload_part_ptr += this_fragment_payload_size;
        remaining_payload_part_size -= this_fragment_payload_size;
        *fragment_offset_8byte_chunks += (this_fragment_payload_size / 8);
    }

    return true;
}
