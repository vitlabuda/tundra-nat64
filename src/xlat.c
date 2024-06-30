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
#include"xlat.h"

#include"signals.h"
#include"xlat_io.h"
#include"xlat_4to6.h"
#include"xlat_6to4.h"


static void _translate_packet(tundra__thread_ctx *const ctx);


void *xlat__run_thread(void *arg) {
    tundra__thread_ctx *const ctx = (tundra__thread_ctx *const) arg;

    while(signals__should_this_thread_keep_running()) {
        xlat_io__recv_packet_into_in_packet_buffer(ctx);

        _translate_packet(ctx);
    }

    return NULL;
}

static void _translate_packet(tundra__thread_ctx *const ctx) {
    if(ctx->in_packet_size < 20)
        return;

    const uint8_t ip_version = (*ctx->in_packet_buffer) >> 4;
    if(ip_version == 4)
        xlat_4to6__handle_packet(ctx);
    else if(ip_version == 6)
        xlat_6to4__handle_packet(ctx);
}
