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
#include"xlat_addr.h"

#include"log.h"
#include"xlat_addr_nat64.h"
#include"xlat_addr_clat.h"
#include"xlat_addr_siit.h"
#include"xlat_addr_external.h"


bool xlat_addr__translate_4to6_addr_for_main_packet(tundra__thread_ctx *const ctx, const uint8_t *in_src_ipv4, const uint8_t *in_dst_ipv4, uint8_t *out_src_ipv6, uint8_t *out_dst_ipv6) {
    // It would be possible to decide which function to use beforehand and then call it indirectly using a function
    //  pointer, but indirect function calls are usually slow (since they cannot be optimized by the compiler).
    switch(ctx->config->addressing_mode) {
        case TUNDRA__ADDRESSING_MODE_NAT64:
            return xlat_addr_nat64__translate_4to6_addr_for_main_packet(ctx, in_src_ipv4, in_dst_ipv4, out_src_ipv6, out_dst_ipv6);

        case TUNDRA__ADDRESSING_MODE_CLAT:
            return xlat_addr_clat__translate_4to6_addr_for_main_packet(ctx, in_src_ipv4, in_dst_ipv4, out_src_ipv6, out_dst_ipv6);

        case TUNDRA__ADDRESSING_MODE_SIIT:
            return xlat_addr_siit__translate_4to6_addr_for_main_packet(ctx, in_src_ipv4, in_dst_ipv4, out_src_ipv6, out_dst_ipv6);

        case TUNDRA__ADDRESSING_MODE_EXTERNAL:
            return xlat_addr_external__translate_4to6_addr_for_main_packet(ctx, in_src_ipv4, in_dst_ipv4, out_src_ipv6, out_dst_ipv6);

        default:
            log__thread_crash_invalid_internal_state(ctx->thread_id, "Invalid addressing mode");
    }
}

bool xlat_addr__translate_4to6_addr_for_icmp_error_packet(tundra__thread_ctx *const ctx, const uint8_t *in_src_ipv4, const uint8_t *in_dst_ipv4, uint8_t *out_src_ipv6, uint8_t *out_dst_ipv6) {
    // It would be possible to decide which function to use beforehand and then call it indirectly using a function
    //  pointer, but indirect function calls are usually slow (since they cannot be optimized by the compiler).
    switch(ctx->config->addressing_mode) {
        case TUNDRA__ADDRESSING_MODE_NAT64:
            return xlat_addr_nat64__translate_4to6_addr_for_icmp_error_packet(ctx, in_src_ipv4, in_dst_ipv4, out_src_ipv6, out_dst_ipv6);

        case TUNDRA__ADDRESSING_MODE_CLAT:
            return xlat_addr_clat__translate_4to6_addr_for_icmp_error_packet(ctx, in_src_ipv4, in_dst_ipv4, out_src_ipv6, out_dst_ipv6);

        case TUNDRA__ADDRESSING_MODE_SIIT:
            return xlat_addr_siit__translate_4to6_addr_for_icmp_error_packet(ctx, in_src_ipv4, in_dst_ipv4, out_src_ipv6, out_dst_ipv6);

        case TUNDRA__ADDRESSING_MODE_EXTERNAL:
            return xlat_addr_external__translate_4to6_addr_for_icmp_error_packet(ctx, in_src_ipv4, in_dst_ipv4, out_src_ipv6, out_dst_ipv6);

        default:
            log__thread_crash_invalid_internal_state(ctx->thread_id, "Invalid addressing mode");
    }
}

bool xlat_addr__translate_6to4_addr_for_main_packet(tundra__thread_ctx *const ctx, const uint8_t *in_src_ipv6, const uint8_t *in_dst_ipv6, uint8_t *out_src_ipv4, uint8_t *out_dst_ipv4) {
    // It would be possible to decide which function to use beforehand and then call it indirectly using a function
    //  pointer, but indirect function calls are usually slow (since they cannot be optimized by the compiler).
    switch(ctx->config->addressing_mode) {
        case TUNDRA__ADDRESSING_MODE_NAT64:
            return xlat_addr_nat64__translate_6to4_addr_for_main_packet(ctx, in_src_ipv6, in_dst_ipv6, out_src_ipv4, out_dst_ipv4);

        case TUNDRA__ADDRESSING_MODE_CLAT:
            return xlat_addr_clat__translate_6to4_addr_for_main_packet(ctx, in_src_ipv6, in_dst_ipv6, out_src_ipv4, out_dst_ipv4);

        case TUNDRA__ADDRESSING_MODE_SIIT:
            return xlat_addr_siit__translate_6to4_addr_for_main_packet(ctx, in_src_ipv6, in_dst_ipv6, out_src_ipv4, out_dst_ipv4);

        case TUNDRA__ADDRESSING_MODE_EXTERNAL:
            return xlat_addr_external__translate_6to4_addr_for_main_packet(ctx, in_src_ipv6, in_dst_ipv6, out_src_ipv4, out_dst_ipv4);

        default:
            log__thread_crash_invalid_internal_state(ctx->thread_id, "Invalid addressing mode");
    }
}

bool xlat_addr__translate_6to4_addr_for_icmp_error_packet(tundra__thread_ctx *const ctx, const uint8_t *in_src_ipv6, const uint8_t *in_dst_ipv6, uint8_t *out_src_ipv4, uint8_t *out_dst_ipv4) {
    // It would be possible to decide which function to use beforehand and then call it indirectly using a function
    //  pointer, but indirect function calls are usually slow (since they cannot be optimized by the compiler).
    switch(ctx->config->addressing_mode) {
        case TUNDRA__ADDRESSING_MODE_NAT64:
            return xlat_addr_nat64__translate_6to4_addr_for_icmp_error_packet(ctx, in_src_ipv6, in_dst_ipv6, out_src_ipv4, out_dst_ipv4);

        case TUNDRA__ADDRESSING_MODE_CLAT:
            return xlat_addr_clat__translate_6to4_addr_for_icmp_error_packet(ctx, in_src_ipv6, in_dst_ipv6, out_src_ipv4, out_dst_ipv4);

        case TUNDRA__ADDRESSING_MODE_SIIT:
            return xlat_addr_siit__translate_6to4_addr_for_icmp_error_packet(ctx, in_src_ipv6, in_dst_ipv6, out_src_ipv4, out_dst_ipv4);

        case TUNDRA__ADDRESSING_MODE_EXTERNAL:
            return xlat_addr_external__translate_6to4_addr_for_icmp_error_packet(ctx, in_src_ipv6, in_dst_ipv6, out_src_ipv4, out_dst_ipv4);

        default:
            log__thread_crash_invalid_internal_state(ctx->thread_id, "Invalid addressing mode");
    }
}
