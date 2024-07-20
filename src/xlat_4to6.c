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
#include"xlat_4to6.h"

#include"utils.h"
#include"utils_ip.h"
#include"checksum.h"
#include"xlat_io.h"
#include"xlat_4to6_icmp.h"
#include"router_ipv4.h"
#include"xlat_addr.h"


typedef struct _out_ipv6_packet_data {
    struct ipv6hdr ipv6_header;
    tundra__ipv6_frag_header ipv6_fragment_header; // Invalid if 'is_fragment' == false
    const uint8_t *payload_ptr; // Points to a part of 'ctx->in_packet_buffer' --> must not be modified!
    size_t payload_size;
    uint8_t carried_protocol;
    bool is_fragment;
    bool is_fragment_offset_zero;
    bool dont_fragment;
} _out_ipv6_packet_data;


static bool _validate_and_translate_ip_header(tundra__thread_ctx *const ctx, _out_ipv6_packet_data *const out_packet_data);
static void _translate_icmpv4_payload_to_icmpv6_and_send(tundra__thread_ctx *const ctx, _out_ipv6_packet_data *const out_packet_data);
static void _translate_tcp_payload_and_send(tundra__thread_ctx *const ctx, _out_ipv6_packet_data *const out_packet_data);
static void _translate_udp_payload_and_send(tundra__thread_ctx *const ctx, _out_ipv6_packet_data *const out_packet_data);
static void _translate_generic_payload_and_send(tundra__thread_ctx *const ctx, _out_ipv6_packet_data *const out_packet_data);
static void _appropriately_send_ipv6_packet(tundra__thread_ctx *const ctx, struct ipv6hdr *ipv6_header, const tundra__ipv6_frag_header *nullable_ipv6_fragment_header, const uint8_t *nullable_payload1_ptr, const size_t zeroable_payload1_size_m8, const uint8_t *payload2_ptr, const size_t payload2_size, const bool dont_fragment);
static void _fragment_and_send_ipv6_packet(tundra__thread_ctx *const ctx, struct ipv6hdr *ipv6_header, const tundra__ipv6_frag_header *nullable_ipv6_fragment_header, const uint8_t *nullable_payload1_ptr, const size_t zeroable_payload1_size_m8, const uint8_t *payload2_ptr, const size_t payload2_size);
static bool _fragment_and_send_ipv6_packet_part(const tundra__thread_ctx *const ctx, struct ipv6hdr *ready_ipv6_header, tundra__ipv6_frag_header *ready_ipv6_fragment_header, const uint8_t *payload_part_ptr, const size_t payload_part_size, size_t *fragment_offset_8byte_chunks, const bool more_fragments_after_this_part, const size_t max_fragment_payload_size);


void xlat_4to6__handle_packet(tundra__thread_ctx *const ctx) {
    _out_ipv6_packet_data out_packet_data;
    if(!_validate_and_translate_ip_header(ctx, &out_packet_data))
        return;

    // At this moment, the entire in_packet's IPv4 header has been validated (including any IPv4 options);
    //  therefore, it is now safe to send ICMP messages back to the packet's source host.
    if(out_packet_data.ipv6_header.hop_limit < 1) {
        router_ipv4__send_time_exceeded_to_in_ipv4_packet_src(ctx);
        return;
    }

    switch(out_packet_data.carried_protocol) {
        case 6: // TCP
            _translate_tcp_payload_and_send(ctx, &out_packet_data);
            break;

        case 17: // UDP
            _translate_udp_payload_and_send(ctx, &out_packet_data);
            break;

        case 58: // ICMPv6
            _translate_icmpv4_payload_to_icmpv6_and_send(ctx, &out_packet_data);
            break;

        default:
            _translate_generic_payload_and_send(ctx, &out_packet_data);
            break;
    }
}

static bool _validate_and_translate_ip_header(tundra__thread_ctx *const ctx, _out_ipv6_packet_data *const out_packet_data) {
    if(ctx->in_packet_size < 20)
        return false;

    const struct iphdr *in_ipv4_header = (const struct iphdr *) __builtin_assume_aligned(ctx->in_packet_buffer, 64);
    struct ipv6hdr *out_ipv6_header = &out_packet_data->ipv6_header;

    // :: IP version ('in_ipv4_header->version' is guaranteed to be 4)
    out_ipv6_header->version = 6;

    // :: IHL (validated, discarded during translation)
    const size_t in_ipv4_header_size = ((size_t) in_ipv4_header->ihl) * 4;
    if(in_ipv4_header_size < 20 || in_ipv4_header_size > ctx->in_packet_size)
        return false;

    // :: DSCP & ECN -> Traffic class; Flow label (no validation needs to be done)
    if(ctx->config->translator_4to6_copy_dscp_and_ecn) {
        // FALSE-POSITIVE: The value assigned to 'out_ipv6_header->priority' cannot be such that it would not fit into
        //  4 bits; however, since C does not support bit-field type casts, e.g. '(uint8_t : 4)', there seems to be
        //  no other way to let the compiler know that this is OK other than to ignore this warning.
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wconversion"
        out_ipv6_header->priority = (uint8_t) (in_ipv4_header->tos >> 4);
        #pragma GCC diagnostic pop

        out_ipv6_header->flow_lbl[0] = (uint8_t) (in_ipv4_header->tos << 4);
    } else {
        out_ipv6_header->priority = 0;
        out_ipv6_header->flow_lbl[0] = 0;
    }
    out_ipv6_header->flow_lbl[1] = 0;
    out_ipv6_header->flow_lbl[2] = 0;

    // :: Total length -> Payload length (input packet validated, correct value in output packet set later)
    if(ntohs(in_ipv4_header->tot_len) != ctx->in_packet_size)
        return false;
    out_ipv6_header->payload_len = 0; // Set to a correct value later

    // :: Reserved bit (part of the flags field)
    if(UTILS_IP__GET_IPV4_FRAG_RESERVED_BIT(in_ipv4_header) != 0)
        return false;

    // :: TTL -> Hop limit (decremented, possible time exceeded ICMP packet sent later)
    if(in_ipv4_header->ttl < 1)
        return false; // The packet should have already been dropped!
    out_ipv6_header->hop_limit = (uint8_t) (in_ipv4_header->ttl - 1);

    // :: Header checksum (validated, discarded during translation)
    if(checksum__calculate_ipv4_header_checksum(in_ipv4_header) != 0)
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

        const uint8_t *current_option_ptr = (const uint8_t *) (ctx->in_packet_buffer + 20);
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
        utils_ip__is_ip_proto_forbidden(in_ipv4_header->protocol) ||
        (in_ipv4_header->protocol == 58) // ICMP for IPv6
    ) return false;
    const uint8_t ipv6_carried_protocol = (in_ipv4_header->protocol == 1) ? 58 : in_ipv4_header->protocol;

    // :: DF bit (saved for later)
    out_packet_data->dont_fragment = (bool) UTILS_IP__GET_IPV4_DONT_FRAG(in_ipv4_header);

    // :: Fragment offset
    const uint16_t fragment_offset = UTILS_IP__GET_IPV4_FRAG_OFFSET(in_ipv4_header);
    out_packet_data->is_fragment_offset_zero = (bool) (fragment_offset == 0);

    // :: More fragments
    const uint16_t more_fragments = UTILS_IP__GET_IPV4_MORE_FRAGS(in_ipv4_header);

    // :: Identification, fragment offset & more fragments bit -> Fragmentation header
    tundra__ipv6_frag_header *out_ipv6_fragment_header = &out_packet_data->ipv6_fragment_header;
    if(UTILS_IP__IS_IPV4_PACKET_FRAGMENTED_UNSAFE(in_ipv4_header)) {
        out_ipv6_header->nexthdr = 44;

        out_ipv6_fragment_header->next_header = ipv6_carried_protocol;
        out_ipv6_fragment_header->reserved = 0;
        out_ipv6_fragment_header->offset_and_flags = UTILS_IP__CONSTRUCT_IPV6_FRAG_OFFSET_AND_FLAGS(fragment_offset, more_fragments);
        out_ipv6_fragment_header->identification[0] = 0;
        out_ipv6_fragment_header->identification[1] = in_ipv4_header->id;

        out_packet_data->is_fragment = true;
    } else {
        out_ipv6_header->nexthdr = ipv6_carried_protocol;

        UTILS__MEM_ZERO_OUT(out_ipv6_fragment_header, sizeof(tundra__ipv6_frag_header));

        out_packet_data->is_fragment = false;
    }

    // :: Source & destination IP address
    // NOTE: All header fields of the input packet (including any IPv4 options) have been validated at this point,
    //  except the source & destination IP address; therefore, after validating these two fields, the address
    //  translation function may choose to send an ICMP error message back to the source host.
    if(!xlat_addr__translate_4to6_addr_for_main_packet(
        ctx,
        (const uint8_t *) &in_ipv4_header->saddr,
        (const uint8_t *) &in_ipv4_header->daddr,
        (uint8_t *) (out_ipv6_header->saddr.s6_addr),
        (uint8_t *) (out_ipv6_header->daddr.s6_addr)
    )) return false;

    out_packet_data->payload_ptr = (const uint8_t *) (ctx->in_packet_buffer + in_ipv4_header_size);
    out_packet_data->payload_size = (ctx->in_packet_size - in_ipv4_header_size);

    // If there are more fragments after this one, this fragment's payload size must be a multiple of 8, as fragment
    //  offsets in IPv4/v6 headers are specified in 8-byte units.
    if(more_fragments && (out_packet_data->payload_size % 8) != 0)
        return false;

    out_packet_data->carried_protocol = ipv6_carried_protocol;

    return true;
}

static void _translate_icmpv4_payload_to_icmpv6_and_send(tundra__thread_ctx *const ctx, _out_ipv6_packet_data *const out_packet_data) {
    // https://www.rfc-editor.org/rfc/rfc7915.html#page-4 -> "Fragmented ICMP/ICMPv6 packets will not be translated by IP/ICMP translators."
    if(out_packet_data->is_fragment)
        return;

    if(checksum__calculate_checksum_ipv4(out_packet_data->payload_ptr, out_packet_data->payload_size, NULL, 0, NULL) != 0)
        return;

    xlat_4to6_icmp__out_icmpv6_message_data out_message_data __attribute__((aligned(64)));
    if(!xlat_4to6_icmp__translate_icmpv4_to_icmpv6(
        ctx,
        out_packet_data->payload_ptr,
        out_packet_data->payload_size,
        (const struct ipv6hdr *) &out_packet_data->ipv6_header,
        &out_message_data
    )) return;

    _appropriately_send_ipv6_packet(
        ctx, &out_packet_data->ipv6_header, (out_packet_data->is_fragment ? &out_packet_data->ipv6_fragment_header : NULL),
        out_message_data.message_start_64b, out_message_data.message_start_size_m8,
        out_message_data.message_end_ptr, out_message_data.message_end_size,
        out_packet_data->dont_fragment
    );
}

static void _translate_tcp_payload_and_send(tundra__thread_ctx *const ctx, _out_ipv6_packet_data *const out_packet_data) {
    if(out_packet_data->is_fragment_offset_zero && out_packet_data->payload_size >= 20) { // 20 or more bytes
        uint8_t new_tcp_payload_start_buffer[24] __attribute__((aligned(64)));
        struct tcphdr *new_tcp_header = (struct tcphdr *) __builtin_assume_aligned(new_tcp_payload_start_buffer, 64);

        if(out_packet_data->payload_size >= 24) { // 24 or more bytes
            memcpy(new_tcp_payload_start_buffer, out_packet_data->payload_ptr, 24);

            new_tcp_header->check = checksum__recalculate_checksum_4to6(
                new_tcp_header->check,
                (const struct iphdr *) __builtin_assume_aligned(ctx->in_packet_buffer, 64),
                &out_packet_data->ipv6_header
            );

            _appropriately_send_ipv6_packet(
                ctx, &out_packet_data->ipv6_header, (out_packet_data->is_fragment ? &out_packet_data->ipv6_fragment_header : NULL),
                new_tcp_payload_start_buffer, 24,
                (out_packet_data->payload_ptr + 24), (out_packet_data->payload_size - 24),
                out_packet_data->dont_fragment
            );
        } else { // 20, 21, 22 or 23 bytes
            memcpy(new_tcp_payload_start_buffer, out_packet_data->payload_ptr, out_packet_data->payload_size);

            new_tcp_header->check = checksum__recalculate_checksum_4to6(
                new_tcp_header->check,
                (const struct iphdr *) __builtin_assume_aligned(ctx->in_packet_buffer, 64),
                &out_packet_data->ipv6_header
            );

            _appropriately_send_ipv6_packet(
                ctx, &out_packet_data->ipv6_header, (out_packet_data->is_fragment ? &out_packet_data->ipv6_fragment_header : NULL),
                NULL, 0,
                new_tcp_payload_start_buffer, out_packet_data->payload_size,
                out_packet_data->dont_fragment
            );
        }
    } else {
        _appropriately_send_ipv6_packet(
            ctx, &out_packet_data->ipv6_header, (out_packet_data->is_fragment ? &out_packet_data->ipv6_fragment_header : NULL),
            NULL, 0,
            out_packet_data->payload_ptr, out_packet_data->payload_size,
            out_packet_data->dont_fragment
        );
    }
}

static void _translate_udp_payload_and_send(tundra__thread_ctx *const ctx, _out_ipv6_packet_data *const out_packet_data) {
    if(out_packet_data->is_fragment_offset_zero && out_packet_data->payload_size >= 8) {
        struct udphdr new_udp_header;
        memcpy(&new_udp_header, out_packet_data->payload_ptr, 8);

        if(new_udp_header.check == 0)
            return;

        const uint16_t new_checksum = checksum__recalculate_checksum_4to6(
            new_udp_header.check,
            (const struct iphdr *) __builtin_assume_aligned(ctx->in_packet_buffer, 64),
            &out_packet_data->ipv6_header
        );
        new_udp_header.check = (new_checksum == 0 ? 0xffff : new_checksum);

        _appropriately_send_ipv6_packet(
            ctx, &out_packet_data->ipv6_header, (out_packet_data->is_fragment ? &out_packet_data->ipv6_fragment_header : NULL),
            (const uint8_t *) &new_udp_header, 8,
            (out_packet_data->payload_ptr + 8), (out_packet_data->payload_size - 8),
            out_packet_data->dont_fragment
        );
    } else {
        _appropriately_send_ipv6_packet(
            ctx, &out_packet_data->ipv6_header, (out_packet_data->is_fragment ? &out_packet_data->ipv6_fragment_header : NULL),
            NULL, 0,
            out_packet_data->payload_ptr, out_packet_data->payload_size,
            out_packet_data->dont_fragment
        );
    }
}

static void _translate_generic_payload_and_send(tundra__thread_ctx *const ctx, _out_ipv6_packet_data *const out_packet_data) {
    _appropriately_send_ipv6_packet(
        ctx, &out_packet_data->ipv6_header, (out_packet_data->is_fragment ? &out_packet_data->ipv6_fragment_header : NULL),
        NULL, 0,
        out_packet_data->payload_ptr, out_packet_data->payload_size,
        out_packet_data->dont_fragment
    );
}

static void _appropriately_send_ipv6_packet(
    tundra__thread_ctx *const ctx,
    struct ipv6hdr *ipv6_header,
    const tundra__ipv6_frag_header *nullable_ipv6_fragment_header,
    const uint8_t *nullable_payload1_ptr,
    const size_t zeroable_payload1_size_m8,
    const uint8_t *payload2_ptr,
    const size_t payload2_size,
    const bool dont_fragment
) {
    const size_t total_packet_size = 40 + (size_t) (nullable_ipv6_fragment_header != NULL ? 8 : 0) + zeroable_payload1_size_m8 + payload2_size;

    if(total_packet_size > ctx->config->translator_ipv6_outbound_mtu) {
        if(dont_fragment) {
            // Why (IPv6 MTU - 28)? "Worst case scenario" example: The IPv6 MTU is 1280 bytes; the IPv4 host sends a
            //  1252-byte (1280 - 28) fragmented IPv4 packet whose header has 20 bytes; during translation, the IPv4
            //  header is stripped, resulting in 1232 bytes of data; the 40-byte IPv6 header and 8-byte fragmentation
            //  extension header is prepended to the data, resulting in a 1280-byte IPv6 packet (the biggest packet that
            //  fits into the IPv6 MTU)
            router_ipv4__send_fragmentation_needed_to_in_ipv4_packet_src(
                ctx,
                (uint16_t) (ctx->config->translator_ipv6_outbound_mtu - 28)
            );
        } else {
            _fragment_and_send_ipv6_packet(ctx, ipv6_header, nullable_ipv6_fragment_header, nullable_payload1_ptr, zeroable_payload1_size_m8, payload2_ptr, payload2_size);
        }
    } else {
        xlat_io__send_ipv6_packet(ctx, ipv6_header, nullable_ipv6_fragment_header, nullable_payload1_ptr, zeroable_payload1_size_m8, payload2_ptr, payload2_size);
    }
}

static void _fragment_and_send_ipv6_packet(
    tundra__thread_ctx *const ctx,
    struct ipv6hdr *ipv6_header,
    const tundra__ipv6_frag_header *nullable_ipv6_fragment_header,
    const uint8_t *nullable_payload1_ptr,
    const size_t zeroable_payload1_size_m8,
    const uint8_t *payload2_ptr,
    const size_t payload2_size
) {
    if((zeroable_payload1_size_m8 % 8) != 0)
        return; // This should never happen!

    // Compute the maximum size of a fragment's payload
    size_t max_fragment_payload_size = (ctx->config->translator_ipv6_outbound_mtu - 48);
    max_fragment_payload_size -= (max_fragment_payload_size % 8); // Fragment offsets are specified in 8-byte units

    // Initialize the necessary variables
    tundra__ipv6_frag_header new_ipv6_fragment_header;
    size_t fragment_offset_8byte_chunks;
    bool more_fragments_after_this_packet;
    if(nullable_ipv6_fragment_header != NULL) {
        memcpy(&new_ipv6_fragment_header, nullable_ipv6_fragment_header, 8);

        fragment_offset_8byte_chunks = UTILS_IP__GET_IPV6_FRAG_OFFSET(nullable_ipv6_fragment_header);
        more_fragments_after_this_packet = (bool) UTILS_IP__GET_IPV6_MORE_FRAGS(nullable_ipv6_fragment_header);
    } else {
        new_ipv6_fragment_header.next_header = ipv6_header->nexthdr;
        new_ipv6_fragment_header.reserved = 0;
        new_ipv6_fragment_header.offset_and_flags = 0;
        utils_ip__generate_ipv6_frag_id(ctx, (uint8_t *) new_ipv6_fragment_header.identification);

        ipv6_header->nexthdr = 44;

        fragment_offset_8byte_chunks = 0;
        more_fragments_after_this_packet = false;
    }

    // Send the first part of payload
    if(nullable_payload1_ptr != NULL && zeroable_payload1_size_m8 > 0) {
        if(!_fragment_and_send_ipv6_packet_part(
            ctx,
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
        (void) _fragment_and_send_ipv6_packet_part(
            ctx,
            ipv6_header,
            &new_ipv6_fragment_header,
            payload2_ptr,
            payload2_size,
            &fragment_offset_8byte_chunks,
            more_fragments_after_this_packet,
            max_fragment_payload_size
        );
}

static bool _fragment_and_send_ipv6_packet_part(
    const tundra__thread_ctx *const ctx,
    struct ipv6hdr *ready_ipv6_header,
    tundra__ipv6_frag_header *ready_ipv6_fragment_header,
    const uint8_t *current_payload_part_ptr,
    size_t remaining_payload_part_size,
    size_t *fragment_offset_8byte_chunks,
    const bool more_fragments_after_this_part,
    const size_t max_fragment_payload_size
) {
    if(more_fragments_after_this_part && (remaining_payload_part_size % 8) != 0)
        return false;

    while(remaining_payload_part_size > 0) {
        const size_t this_fragment_payload_size = UTILS__MINIMUM_UNSAFE(remaining_payload_part_size, max_fragment_payload_size);
        const bool more_fragments_after_this_fragment = (remaining_payload_part_size > max_fragment_payload_size ? true : more_fragments_after_this_part);

        if(*fragment_offset_8byte_chunks > 8191) // (2^13) - 1 == 8191 (fragment offset is stored in 13 bits)
            return false;

        ready_ipv6_fragment_header->offset_and_flags = UTILS_IP__CONSTRUCT_IPV6_FRAG_OFFSET_AND_FLAGS(
            (uint16_t) *fragment_offset_8byte_chunks,
            (uint16_t) more_fragments_after_this_fragment
        );

        xlat_io__send_ipv6_packet(ctx, ready_ipv6_header, ready_ipv6_fragment_header, current_payload_part_ptr, this_fragment_payload_size, NULL, 0);

        current_payload_part_ptr += this_fragment_payload_size;
        remaining_payload_part_size -= this_fragment_payload_size;
        *fragment_offset_8byte_chunks += (this_fragment_payload_size / 8);
    }

    return true;
}
