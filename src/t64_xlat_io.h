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

#ifndef _T64I_XLAT_IO_H
#define _T64I_XLAT_IO_H

#include"t64_tundra.h"


extern bool t64f_xlat_io__receive_packet_into_in_packet(t64ts_tundra__xlat_thread_context *context);
extern void t64f_xlat_io__possibly_fragment_and_send_ipv4_out_packet(t64ts_tundra__xlat_thread_context *context);
extern void t64f_xlat_io__send_specified_ipv4_packet(t64ts_tundra__xlat_thread_context *context, t64ts_tundra__packet *ipv4_packet);
extern void t64f_xlat_io__possibly_fragment_and_send_ipv6_out_packet(t64ts_tundra__xlat_thread_context *context);
extern void t64f_xlat_io__send_specified_ipv6_packet(t64ts_tundra__xlat_thread_context *context, t64ts_tundra__packet *ipv6_packet);


#endif // _T64I_XLAT_IO_H
