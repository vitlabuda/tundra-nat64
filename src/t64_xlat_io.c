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
#include"t64_xlat_io.h"

#include"t64_utils_ip.h"
#include"t64_checksum.h"
#include"t64_log.h"


static void _t64f_xlat_io__generate_ipv4_fragment_from_out_packet_to_tmp_packet(t64ts_tundra__xlat_thread_context *context, const uint16_t fragment_offset_and_flags, const uint8_t *payload_copy_from_ptr, const size_t payload_copy_size);
static void _t64f_xlat_io__generate_ipv6_fragment_from_out_packet_to_tmp_packet(t64ts_tundra__xlat_thread_context *context, const uint32_t fragment_identification, const uint16_t fragment_offset_and_flags, const uint8_t *payload_copy_from_ptr, const size_t payload_copy_size);
static void _t64f_xlat_io__send_specified_packet(const t64ts_tundra__xlat_thread_context *context, const t64ts_tundra__packet *packet);
static void _t64f_xlat_io__wait_for_packet_write_fd_to_be_available(const t64ts_tundra__xlat_thread_context *context);
static bool _t64f_xlat_io__send_specified_packet_via_packet_write_fd(const t64ts_tundra__xlat_thread_context *context, const t64ts_tundra__packet *packet);


bool t64f_xlat_io__receive_packet_into_in_packet(t64ts_tundra__xlat_thread_context *context) {
    const ssize_t read_return_value = read(context->packet_read_fd, context->in_packet.packet_raw, T64C_TUNDRA__MAX_PACKET_SIZE);

    if(read_return_value < 0) {
        if(errno == EAGAIN || errno == EWOULDBLOCK)
            return false;

        t64f_log__thread_crash(context->thread_id, true, "An error occurred while receiving a packet!");
    }

    if(read_return_value == 0)
        t64f_log__thread_crash(context->thread_id, false, "An end-of-file occurred while receiving a packet!");

    context->in_packet.packet_size = (size_t) read_return_value;

    return true;
}

/*
 * If 'context->out_packet' fits into the configured outbound MTU, it is sent out.
 * Otherwise, the packet is fragmented and the generated fragments are sent out consecutively instead.
 * 'context->out_packet' needs to be a fully valid IPv4 packet (both its header and payload must be valid), except its
 *  header's 'total length' and 'header checksum' fields which should be zero (they are set when the packet is sent out),
 *  and it must not contain any IPv4 options (its 'ihl' field must be equal to 5; this is not a problem, since the
 *  translator does not generate packets with IPv4 options).
 */
void t64f_xlat_io__possibly_fragment_and_send_ipv4_out_packet(t64ts_tundra__xlat_thread_context *context) {
    if(!T64M_UTILS_IP__IPV4_PACKET_NEEDS_FRAGMENTATION(context, &context->out_packet)) {
        t64f_xlat_io__send_specified_ipv4_packet(context, &context->out_packet);
        return;
    }

    // If the packet needs fragmentation:
    {
        size_t max_fragment_payload_size = (context->configuration->translator_ipv4_outbound_mtu - 20);
        max_fragment_payload_size = (max_fragment_payload_size - (max_fragment_payload_size % 8)); // Fragment offsets are specified in 8-byte units

        size_t fragment_offset_8byte_blocks = T64M_UTILS_IP__GET_IPV4_FRAGMENT_OFFSET(context->out_packet.packet_ipv4hdr); // Modified after each fragment
        const uint16_t more_fragments_after_this_packet = T64M_UTILS_IP__GET_IPV4_MORE_FRAGMENTS_BIT(context->out_packet.packet_ipv4hdr);
        const uint16_t dont_fragment = T64M_UTILS_IP__GET_IPV4_DONT_FRAGMENT_BIT(context->out_packet.packet_ipv4hdr);

        if(more_fragments_after_this_packet && (context->out_packet.payload_size % 8) != 0)
            return;

        uint8_t *payload_ptr = context->out_packet.payload_raw; // Modified after each fragment
        size_t payload_remaining_bytes = context->out_packet.payload_size; // Modified after each fragment

        while(payload_remaining_bytes > 0) {
            size_t this_fragment_payload_size;
            uint16_t more_fragments_after_this_fragment;
            if(payload_remaining_bytes > max_fragment_payload_size) {
                // This is NOT the last fragment of this packet:
                this_fragment_payload_size = max_fragment_payload_size;
                more_fragments_after_this_fragment = 1;
            } else {
                // This is the last fragment of this packet:
                this_fragment_payload_size = payload_remaining_bytes;
                more_fragments_after_this_fragment = more_fragments_after_this_packet;
            }

            if(fragment_offset_8byte_blocks > 8191) // (2^13) - 1 == 8191 (fragment offset is stored in 13 bits)
                return;

            const uint16_t fragment_offset_and_flags = T64M_UTILS_IP__CONSTRUCT_IPV4_FRAGMENT_OFFSET_AND_FLAGS_FIELD(
                    dont_fragment,
                    more_fragments_after_this_fragment,
                    fragment_offset_8byte_blocks
            );
            _t64f_xlat_io__generate_ipv4_fragment_from_out_packet_to_tmp_packet(
                    context,
                    fragment_offset_and_flags,
                    payload_ptr,
                    this_fragment_payload_size
            );
            t64f_xlat_io__send_specified_ipv4_packet(context, &context->tmp_packet);

            payload_ptr += this_fragment_payload_size;
            payload_remaining_bytes -= this_fragment_payload_size;
            fragment_offset_8byte_blocks += (this_fragment_payload_size / 8);
        }
    }
}

static void _t64f_xlat_io__generate_ipv4_fragment_from_out_packet_to_tmp_packet(t64ts_tundra__xlat_thread_context *context, const uint16_t fragment_offset_and_flags, const uint8_t *payload_copy_from_ptr, const size_t payload_copy_size) {
    context->tmp_packet.packet_ipv4hdr->version = 4;
    context->tmp_packet.packet_ipv4hdr->ihl = 5;
    context->tmp_packet.packet_ipv4hdr->tos = context->out_packet.packet_ipv4hdr->tos;
    context->tmp_packet.packet_ipv4hdr->tot_len = 0; // This is set to a correct value when the packet is sent
    context->tmp_packet.packet_ipv4hdr->id = context->out_packet.packet_ipv4hdr->id;
    context->tmp_packet.packet_ipv4hdr->frag_off = fragment_offset_and_flags;
    context->tmp_packet.packet_ipv4hdr->ttl = context->out_packet.packet_ipv4hdr->ttl;
    context->tmp_packet.packet_ipv4hdr->protocol = context->out_packet.packet_ipv4hdr->protocol;
    context->tmp_packet.packet_ipv4hdr->check = 0; // This is set to a correct value when the packet is sent
    context->tmp_packet.packet_ipv4hdr->saddr = context->out_packet.packet_ipv4hdr->saddr;
    context->tmp_packet.packet_ipv4hdr->daddr = context->out_packet.packet_ipv4hdr->daddr;

    uint8_t *payload_ptr = (context->tmp_packet.packet_raw + 20);
    memcpy(payload_ptr, payload_copy_from_ptr, payload_copy_size);

    context->tmp_packet.packet_size = (payload_copy_size + 20);
    context->tmp_packet.payload_raw = payload_ptr;
    context->tmp_packet.payload_size = payload_copy_size;
}

/*
 * Sets the specified IPv4 packet's 'total length' and 'header checksum' header fields and sends the packet out.
 * The packet needs to be fully valid (except the aforementioned 'total length' and 'header checksum' fields which should be zero).
 * WARNING: This function does not fragment the packet - if its size is larger than the configured MTU, it is silently dropped!
 */
void t64f_xlat_io__send_specified_ipv4_packet(t64ts_tundra__xlat_thread_context *context, t64ts_tundra__packet *ipv4_packet) {
    if(ipv4_packet->packet_size < 20 || ipv4_packet->packet_size > 65535)
        return;

    if(T64M_UTILS_IP__IPV4_PACKET_NEEDS_FRAGMENTATION(context, ipv4_packet))
        return;

    ipv4_packet->packet_ipv4hdr->tot_len = htons((uint16_t) ipv4_packet->packet_size);
    ipv4_packet->packet_ipv4hdr->check = 0; // "For purposes of computing the checksum, the value of the checksum field is zero."
    ipv4_packet->packet_ipv4hdr->check = t64f_checksum__calculate_ipv4_header_checksum(ipv4_packet->packet_ipv4hdr);

    _t64f_xlat_io__send_specified_packet(context, ipv4_packet);
}

/*
 * If 'context->out_packet' fits into the configured outbound MTU, it is sent out.
 * Otherwise, the packet is fragmented and the generated fragments are sent out consecutively instead.
 * 'context->out_packet' needs to be a fully valid IPv6 packet (both its header(s) and payload must be valid), except
 *  its base header's 'payload length' field which should be zero (it is set automatically when the packet is sent out),
 *  and it must contain no extension headers other than a single (optional) fragmentation header (referenced by
 *  'out_packet.ipv6_fragment_header'; this is not a problem, as the translator does not generate packets with other
 *  extension headers).
 */
void t64f_xlat_io__possibly_fragment_and_send_ipv6_out_packet(t64ts_tundra__xlat_thread_context *context) {
    if(!T64M_UTILS_IP__IPV6_PACKET_NEEDS_FRAGMENTATION(context, &context->out_packet)) {
        t64f_xlat_io__send_specified_ipv6_packet(context, &context->out_packet);
        return;
    }

    // If the packet needs fragmentation:
    {
        size_t max_fragment_payload_size = (context->configuration->translator_ipv6_outbound_mtu - 48);
        max_fragment_payload_size = (max_fragment_payload_size - (max_fragment_payload_size % 8)); // Fragment offsets are specified in 8-byte units

        size_t fragment_offset_8byte_blocks; // Modified after each fragment
        uint16_t more_fragments_after_this_packet;
        uint32_t fragment_identification;
        if(T64M_UTILS_IP__IS_IPV6_PACKET_FRAGMENTED(&context->out_packet)) {
            // If 'out_packet' is a fragment:
            fragment_offset_8byte_blocks = T64M_UTILS_IP__GET_IPV6_FRAGMENT_OFFSET(context->out_packet.ipv6_fragment_header);
            more_fragments_after_this_packet = T64M_UTILS_IP__GET_IPV6_FRAGMENT_MORE_FRAGMENTS_BIT(context->out_packet.ipv6_fragment_header);
            memcpy(&fragment_identification, context->out_packet.ipv6_fragment_header->identification, 4);
        } else {
            // If 'out_packet' is a whole, not yet fragmented packet:
            fragment_offset_8byte_blocks = 0;
            more_fragments_after_this_packet = 0;
            t64f_utils_ip__generate_ipv6_fragment_identifier(context, (uint8_t *) &fragment_identification);
        }

        if(more_fragments_after_this_packet && (context->out_packet.payload_size % 8) != 0)
            return;

        uint8_t *payload_ptr = context->out_packet.payload_raw; // Modified after each fragment
        size_t payload_remaining_bytes = context->out_packet.payload_size; // Modified after each fragment

        while(payload_remaining_bytes > 0) {
            size_t this_fragment_payload_size;
            uint16_t more_fragments_after_this_fragment;
            if(payload_remaining_bytes > max_fragment_payload_size) {
                // This is NOT the last fragment of this packet:
                this_fragment_payload_size = max_fragment_payload_size;
                more_fragments_after_this_fragment = 1;
            } else {
                // This is the last fragment of this packet:
                this_fragment_payload_size = payload_remaining_bytes;
                more_fragments_after_this_fragment = more_fragments_after_this_packet;
            }

            if(fragment_offset_8byte_blocks > 8191) // (2^13) - 1 == 8191 (fragment offset is stored in 13 bits)
                return;

            const uint16_t fragment_offset_and_flags = T64M_UTILS_IP__CONSTRUCT_IPV6_FRAGMENT_OFFSET_AND_FLAGS_FIELD(
                    fragment_offset_8byte_blocks,
                    more_fragments_after_this_fragment
            );
            _t64f_xlat_io__generate_ipv6_fragment_from_out_packet_to_tmp_packet(
                    context,
                    fragment_identification,
                    fragment_offset_and_flags,
                    payload_ptr,
                    this_fragment_payload_size
            );
            t64f_xlat_io__send_specified_ipv6_packet(context, &context->tmp_packet);

            payload_ptr += this_fragment_payload_size;
            payload_remaining_bytes -= this_fragment_payload_size;
            fragment_offset_8byte_blocks += (this_fragment_payload_size / 8);
        }
    }
}

static void _t64f_xlat_io__generate_ipv6_fragment_from_out_packet_to_tmp_packet(t64ts_tundra__xlat_thread_context *context, const uint32_t fragment_identification, const uint16_t fragment_offset_and_flags, const uint8_t *payload_copy_from_ptr, const size_t payload_copy_size) {
    context->tmp_packet.packet_ipv6hdr->version = 6;
    context->tmp_packet.packet_ipv6hdr->priority = context->out_packet.packet_ipv6hdr->priority;
    memcpy(context->tmp_packet.packet_ipv6hdr->flow_lbl, context->out_packet.packet_ipv6hdr->flow_lbl, 3);
    context->tmp_packet.packet_ipv6hdr->payload_len = 0; // This is set to a correct value when the packet is sent
    context->tmp_packet.packet_ipv6hdr->nexthdr = 44; // Fragmentation header
    context->tmp_packet.packet_ipv6hdr->hop_limit = context->out_packet.packet_ipv6hdr->hop_limit;
    memcpy(context->tmp_packet.packet_ipv6hdr->saddr.s6_addr, context->out_packet.packet_ipv6hdr->saddr.s6_addr, 16);
    memcpy(context->tmp_packet.packet_ipv6hdr->daddr.s6_addr, context->out_packet.packet_ipv6hdr->daddr.s6_addr, 16);

    t64ts_tundra__ipv6_fragment_header *fragment_header_ptr = (t64ts_tundra__ipv6_fragment_header *) (context->tmp_packet.packet_raw + 40);
    fragment_header_ptr->next_header = *(context->out_packet.ipv6_carried_protocol_field);
    fragment_header_ptr->reserved = 0;
    fragment_header_ptr->offset_and_flags = fragment_offset_and_flags;
    memcpy(fragment_header_ptr->identification, &fragment_identification, 4);

    uint8_t *payload_ptr = (context->tmp_packet.packet_raw + 48);
    memcpy(payload_ptr, payload_copy_from_ptr, payload_copy_size);

    context->tmp_packet.packet_size = (payload_copy_size + 48);
    context->tmp_packet.payload_raw = payload_ptr;
    context->tmp_packet.payload_size = payload_copy_size;
    context->tmp_packet.ipv6_fragment_header = fragment_header_ptr;
    context->tmp_packet.ipv6_carried_protocol_field = &fragment_header_ptr->next_header;
}

/*
 * Sets the specified IPv6 packet's 'payload length' header field and sends the packet out.
 * The packet needs to be fully valid (except the aforementioned 'payload length' field which should be zero).
 * WARNING: This function does not fragment the packet - if its size is larger than the configured MTU, it is silently dropped!
 */
void t64f_xlat_io__send_specified_ipv6_packet(t64ts_tundra__xlat_thread_context *context, t64ts_tundra__packet *ipv6_packet) {
    if(ipv6_packet->packet_size < 40 || ipv6_packet->packet_size > 65535)
        return;

    if(T64M_UTILS_IP__IPV6_PACKET_NEEDS_FRAGMENTATION(context, ipv6_packet))
        return;

    ipv6_packet->packet_ipv6hdr->payload_len = htons((uint16_t) (ipv6_packet->packet_size - 40));

    _t64f_xlat_io__send_specified_packet(context, ipv6_packet);
}

static void _t64f_xlat_io__send_specified_packet(const t64ts_tundra__xlat_thread_context *context, const t64ts_tundra__packet *packet) {
    while(!_t64f_xlat_io__send_specified_packet_via_packet_write_fd(context, packet))
        _t64f_xlat_io__wait_for_packet_write_fd_to_be_available(context);
}

static void _t64f_xlat_io__wait_for_packet_write_fd_to_be_available(const t64ts_tundra__xlat_thread_context *context) {
    struct pollfd poll_fd;
    T64M_UTILS__MEMORY_ZERO_OUT(&poll_fd, sizeof(struct pollfd));
    poll_fd.fd = context->packet_write_fd;
    poll_fd.events = POLLOUT;

    if(poll(&poll_fd, 1, -1) < 0)
        t64f_log__thread_crash(context->thread_id, true, "Failed to poll() for 'packet_write_fd' to become available for writing!");

    if(poll_fd.revents == POLLOUT)
        return;

    if(poll_fd.revents != 0)
        t64f_log__thread_crash(context->thread_id, false, "poll() reported an error associated with 'packet_write_fd' (revents = %hd)!", poll_fd.revents);

    t64f_log__thread_crash_invalid_internal_state(context->thread_id, "poll() with infinite timeout returned without reporting any events");
}

static bool _t64f_xlat_io__send_specified_packet_via_packet_write_fd(const t64ts_tundra__xlat_thread_context *context, const t64ts_tundra__packet *packet) {
    const ssize_t write_return_value = write(context->packet_write_fd, packet->packet_raw, packet->packet_size);

    if(write_return_value < 0) {
        if(errno == EAGAIN || errno == EWOULDBLOCK)
            return false;

        t64f_log__thread_crash(context->thread_id, true, "An error occurred while sending a packet!");
    }

    if(((size_t) write_return_value) != packet->packet_size)
        t64f_log__thread_info(context->thread_id, "Only a part of an outbound packet could be sent (sent = %zu bytes, packet size = %zu bytes).", (size_t) write_return_value, packet->packet_size);

    return true;
}
