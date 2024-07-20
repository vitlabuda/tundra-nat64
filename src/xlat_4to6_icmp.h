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

#pragma once
#include"tundra.h"


typedef struct __attribute__((aligned(64))) xlat_4to6_icmp__out_icmpv6_message_data {
    uint8_t message_start_64b[64] __attribute__((aligned(64))); // 56 bytes ought to be enough, but since the code accessing the array is quite complicated, 64 bytes are there to prevent accidental overflows...
    const uint8_t *message_end_ptr; // Points to a part of 'ctx->in_packet_buffer' --> must not be modified!
    size_t message_start_size_m8; // Must be a multiple of 8!!!
    size_t message_end_size;
} xlat_4to6_icmp__out_icmpv6_message_data;


extern bool xlat_4to6_icmp__translate_icmpv4_to_icmpv6(tundra__thread_ctx *const ctx, const uint8_t *in_packet_payload_ptr, const size_t in_packet_payload_size, const struct ipv6hdr *out_packet_ipv6_header_ptr, xlat_4to6_icmp__out_icmpv6_message_data *const out_message_data);
