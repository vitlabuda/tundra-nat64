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

#ifndef _T64I_XLAT_6TO4_ICMP_H
#define _T64I_XLAT_6TO4_ICMP_H

#include"t64_tundra.h"


typedef struct {
    uint8_t message_start_36b[36]; // 32 bytes ought to be enough, but since the code accessing the array is quite complicated and bug-prone, 36 bytes are there to prevent accidental overflows...
    const uint8_t *nullable_message_end_ptr; // Points to a part of 'context->in_packet_buffer' --> must not be modified!
    size_t message_start_size_m8u; // Must be a multiple of 8 unless 'message_end_ptr' is NULL!
    size_t zeroable_message_end_size;
} t64ts_xlat_6to4_icmp__out_icmpv4_message_data;


extern bool t64f_xlat_6to4_icmp__translate_icmpv6_to_icmpv4(t64ts_tundra__xlat_thread_context *context, const uint8_t *in_packet_payload_ptr, const size_t in_packet_payload_size, t64ts_xlat_6to4_icmp__out_icmpv4_message_data *out_message_data);


#endif // _T64I_XLAT_6TO4_ICMP_H
