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

#include"t64_utils.h"
#include"t64_checksum.h"
#include"t64_log.h"
#include"t64_xlat_interrupt.h"


static void _t64f_xlat_io__send_packet(const t64ts_tundra__xlat_thread_context *context, const struct iovec *iov, const int iovcnt, const size_t total_packet_size);


void t64f_xlat_io__receive_packet_into_in_packet_buffer(t64ts_tundra__xlat_thread_context *context) {
    const ssize_t ret_value = t64f_xlat_interrupt__read(context->packet_read_fd, context->in_packet_buffer, T64C_TUNDRA__MAX_PACKET_SIZE);

    if(ret_value < 0)
        t64f_log__thread_crash(context->thread_id, true, "An error occurred while receiving a packet!");

    if(ret_value == 0)
        t64f_log__thread_crash(context->thread_id, false, "An end-of-file occurred while receiving a packet!");

    context->in_packet_size = (size_t) ret_value;
}

void t64f_xlat_io__send_ipv4_packet(const t64ts_tundra__xlat_thread_context *context, struct iphdr *ipv4_header, const uint8_t *nullable_payload1_ptr, const size_t zeroable_payload1_size, const uint8_t *nullable_payload2_ptr, const size_t zeroable_payload2_size) {
    struct iovec iov[3];
    T64M_UTILS__MEMORY_ZERO_OUT(iov, 3 * sizeof(struct iovec));
    int iovcnt = 0;
    size_t total_packet_size = 0;

    // Initialize the 'iov' array
    iov[iovcnt].iov_base = (void *) ipv4_header; // Using 'iovcnt' here is not necessary (it is always 0), but it is done so for consistency
    iov[iovcnt++].iov_len = 20;
    total_packet_size += 20;

    if(nullable_payload1_ptr != NULL && zeroable_payload1_size > 0) {
        iov[iovcnt].iov_base = (void *) nullable_payload1_ptr;
        iov[iovcnt++].iov_len = zeroable_payload1_size;
        total_packet_size += zeroable_payload1_size;
    }

    if(nullable_payload2_ptr != NULL && zeroable_payload2_size > 0) {
        iov[iovcnt].iov_base = (void *) nullable_payload2_ptr;
        iov[iovcnt++].iov_len = zeroable_payload2_size;
        total_packet_size += zeroable_payload2_size;
    }

    if(total_packet_size > context->configuration->translator_ipv4_outbound_mtu)
        return;

    // Fill in the missing parts of the IPv4 header
    ipv4_header->tot_len = htons((uint16_t) total_packet_size);
    ipv4_header->check = 0;
    ipv4_header->check = t64f_checksum__calculate_ipv4_header_checksum(ipv4_header);

    // Send the packet out
    _t64f_xlat_io__send_packet(context, iov, iovcnt, total_packet_size);
}

void t64f_xlat_io__send_ipv6_packet(const t64ts_tundra__xlat_thread_context *context, struct ipv6hdr *ipv6_header, const t64ts_tundra__ipv6_fragment_header *nullable_ipv6_fragment_header, const uint8_t *nullable_payload1_ptr, const size_t zeroable_payload1_size, const uint8_t *nullable_payload2_ptr, const size_t zeroable_payload2_size) {
    struct iovec iov[4];
    T64M_UTILS__MEMORY_ZERO_OUT(iov, 4 * sizeof(struct iovec));
    int iovcnt = 0;
    size_t total_packet_size = 0;

    // Initialize the 'iov' array
    iov[iovcnt].iov_base = (void *) ipv6_header; // Using 'iovcnt' here is not necessary (it is always 0), but it is done so for consistency
    iov[iovcnt++].iov_len = 40;
    total_packet_size += 40;

    if(nullable_ipv6_fragment_header != NULL) {
        iov[iovcnt].iov_base = (void *) nullable_ipv6_fragment_header;
        iov[iovcnt++].iov_len = 8;
        total_packet_size += 8;
    }

    if(nullable_payload1_ptr != NULL && zeroable_payload1_size > 0) {
        iov[iovcnt].iov_base = (void *) nullable_payload1_ptr;
        iov[iovcnt++].iov_len = zeroable_payload1_size;
        total_packet_size += zeroable_payload1_size;
    }

    if(nullable_payload2_ptr != NULL && zeroable_payload2_size > 0) {
        iov[iovcnt].iov_base = (void *) nullable_payload2_ptr;
        iov[iovcnt++].iov_len = zeroable_payload2_size;
        total_packet_size += zeroable_payload2_size;
    }

    if(total_packet_size > context->configuration->translator_ipv6_outbound_mtu)
        return;

    // Fill in the missing parts of the IPv6 header
    ipv6_header->payload_len = htons((uint16_t) (total_packet_size - 40));

    // Send the packet out
    _t64f_xlat_io__send_packet(context, iov, iovcnt, total_packet_size);
}

static void _t64f_xlat_io__send_packet(const t64ts_tundra__xlat_thread_context *context, const struct iovec *iov, const int iovcnt, const size_t total_packet_size) {
    const ssize_t ret_value = t64f_xlat_interrupt__writev(context->packet_write_fd, iov, iovcnt);

    if(ret_value < 0)
        t64f_log__thread_crash(context->thread_id, true, "An error occurred while sending a packet!");

    if(((size_t) ret_value) != total_packet_size)
        t64f_log__thread_crash(context->thread_id, false, "Only a part of the packet could be sent out (sent = %zu, total packet size = %zu)!", (size_t) ret_value, total_packet_size);
}
