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
#include"t64_utils_xlat_addr.h"

#include"t64_utils.h"
#include"t64_utils_ip.h"


static bool _t64f_utils_xlat_addr__nat64_clat_siit__check_embeddability_of_ipv4_into_prefix(const t64ts_tundra__xlat_thread_context *context, const uint8_t *ipv4);


bool t64f_utils_xlat_addr__nat64_clat__perform_6to4_translator_ip_translation(const t64ts_tundra__xlat_thread_context *context, const uint8_t *in_ipv6, uint8_t *out_ipv4) {
    if(!T64M_UTILS_IP__IPV6_ADDRESSES_EQUAL(in_ipv6, context->configuration->addressing_nat64_clat_ipv6))
        return false;

    memcpy(out_ipv4, context->configuration->addressing_nat64_clat_ipv4, 4);

    return true;
}

bool t64f_utils_xlat_addr__nat64_clat__perform_4to6_translator_ip_translation(const t64ts_tundra__xlat_thread_context *context, const uint8_t *in_ipv4, uint8_t *out_ipv6) {
    if(!T64M_UTILS_IP__IPV4_ADDRESSES_EQUAL(in_ipv4, context->configuration->addressing_nat64_clat_ipv4))
        return false;

    memcpy(out_ipv6, context->configuration->addressing_nat64_clat_ipv6, 16);

    return true;
}

bool t64f_utils_xlat_addr__nat64_clat__perform_6to4_prefix_translation_for_main_packet(const t64ts_tundra__xlat_thread_context *context, const uint8_t *in_ipv6, uint8_t *out_ipv4) {
    if(T64M_UTILS_IP__IPV6_ADDRESSES_EQUAL(in_ipv6, context->configuration->addressing_nat64_clat_ipv6))
        return false;

    if(!t64f_utils_xlat_addr__siit__perform_6to4_prefix_translation_for_main_packet(context, in_ipv6, out_ipv4))
        return false;

    if(T64M_UTILS_IP__IPV4_ADDRESSES_EQUAL(out_ipv4, context->configuration->addressing_nat64_clat_ipv4))
        return false;

    return true;
}

bool t64f_utils_xlat_addr__nat64_clat__perform_4to6_prefix_translation_for_main_packet(const t64ts_tundra__xlat_thread_context *context, const uint8_t *in_ipv4, uint8_t *out_ipv6) {
    if(T64M_UTILS_IP__IPV4_ADDRESSES_EQUAL(in_ipv4, context->configuration->addressing_nat64_clat_ipv4))
        return false;

    if(!t64f_utils_xlat_addr__siit__perform_4to6_prefix_translation_for_main_packet(context, in_ipv4, out_ipv6))
        return false;

    if(T64M_UTILS_IP__IPV6_ADDRESSES_EQUAL(out_ipv6, context->configuration->addressing_nat64_clat_ipv6))
        return false;

    return true;
}

bool t64f_utils_xlat_addr__siit__perform_6to4_prefix_translation_for_main_packet(const t64ts_tundra__xlat_thread_context *context, const uint8_t *in_ipv6, uint8_t *out_ipv4) {
    if(T64M_UTILS_IP__IPV6_ADDRESSES_EQUAL(in_ipv6, context->configuration->router_ipv6))
        return false;

    if(!T64M_UTILS__MEMORY_EQUAL(in_ipv6, context->configuration->addressing_nat64_clat_siit_prefix, 12))
        return false;

    if(!_t64f_utils_xlat_addr__nat64_clat_siit__check_embeddability_of_ipv4_into_prefix(context, in_ipv6 + 12))
        return false;

    memcpy(out_ipv4, in_ipv6 + 12, 4);

    return true;
}

bool t64f_utils_xlat_addr__siit__perform_4to6_prefix_translation_for_main_packet(const t64ts_tundra__xlat_thread_context *context, const uint8_t *in_ipv4, uint8_t *out_ipv6) {
    if(!_t64f_utils_xlat_addr__nat64_clat_siit__check_embeddability_of_ipv4_into_prefix(context, in_ipv4))
        return false;

    memcpy(out_ipv6, context->configuration->addressing_nat64_clat_siit_prefix, 12);
    memcpy(out_ipv6 + 12, in_ipv4, 4);

    if(T64M_UTILS_IP__IPV6_ADDRESSES_EQUAL(out_ipv6, context->configuration->router_ipv6))
        return false;

    return true;
}

bool t64f_utils_xlat_addr__nat64_clat_siit__perform_6to4_prefix_translation_for_icmp_error_packet(const t64ts_tundra__xlat_thread_context *context, const uint8_t *in_ipv6, uint8_t *out_ipv4) {
    if(!T64M_UTILS__MEMORY_EQUAL(in_ipv6, context->configuration->addressing_nat64_clat_siit_prefix, 12))
        return false;

    // For debugging purposes, illegal addresses (such as 127.0.0.1) inside ICMP packets are translated normally.
    memcpy(out_ipv4, in_ipv6 + 12, 4);

    return true;
}

void t64f_utils_xlat_addr__nat64_clat_siit__perform_4to6_prefix_translation_for_icmp_error_packet(const t64ts_tundra__xlat_thread_context *context, const uint8_t *in_ipv4, uint8_t *out_ipv6) {
    // For debugging purposes, illegal addresses (such as 127.0.0.1) inside ICMP packets are translated normally.
    memcpy(out_ipv6, context->configuration->addressing_nat64_clat_siit_prefix, 12);
    memcpy(out_ipv6 + 12, in_ipv4, 4);
}

static bool _t64f_utils_xlat_addr__nat64_clat_siit__check_embeddability_of_ipv4_into_prefix(const t64ts_tundra__xlat_thread_context *context, const uint8_t *ipv4_address) {
    if(T64M_UTILS_IP__IPV4_ADDRESSES_EQUAL(ipv4_address, context->configuration->router_ipv4))
        return false; // Packets from/to the router are not translated

    if(context->configuration->addressing_nat64_clat_siit_allow_translation_of_private_ips) {
        if(t64f_utils_ip__is_ipv4_address_unusable(ipv4_address))
            return false;
    } else {
        if(t64f_utils_ip__is_ipv4_address_unusable_or_private(ipv4_address))
            return false;
    }

    return true;
}
