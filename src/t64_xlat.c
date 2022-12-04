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
#include"t64_xlat.h"

#include"t64_signal.h"
#include"t64_xlat_io.h"
#include"t64_xlat_4to6.h"
#include"t64_xlat_6to4.h"


static void _t64f_xlat__prepare_packet_struct_for_new_packet(t64ts_tundra__packet *packet_struct);
static void _t64f_xlat__translate_packet(t64ts_tundra__xlat_thread_context *context);


void *t64f_xlat__thread_run(void *arg) {
    t64ts_tundra__xlat_thread_context *context = (t64ts_tundra__xlat_thread_context *) arg;

    while(t64f_signal__should_this_thread_continue_running()) {
        _t64f_xlat__prepare_packet_struct_for_new_packet(&context->in_packet);
        _t64f_xlat__prepare_packet_struct_for_new_packet(&context->out_packet);
        _t64f_xlat__prepare_packet_struct_for_new_packet(&context->tmp_packet);

        t64f_xlat_io__receive_packet_into_in_packet(context);

        _t64f_xlat__translate_packet(context);
    }

    return NULL;
}

// This function is not really necessary - it just tries to prevent some kinds of undefined behaviour in case the packet translation algorithms are programmed incorrectly.
static void _t64f_xlat__prepare_packet_struct_for_new_packet(t64ts_tundra__packet *packet_struct) {
    packet_struct->packet_size = 0;
    packet_struct->payload_raw = NULL;
    packet_struct->payload_size = 0;
    packet_struct->ipv6_fragment_header = NULL;
    packet_struct->ipv6_carried_protocol_field = NULL;
}

static void _t64f_xlat__translate_packet(t64ts_tundra__xlat_thread_context *context) {
    if(context->in_packet.packet_size < 20)
        return;

    if(context->in_packet.packet_ipv4hdr->version == 4)
        t64f_xlat_4to6__handle_packet(context);
    else if(context->in_packet.packet_ipv4hdr->version == 6)
        t64f_xlat_6to4__handle_packet(context);
}
