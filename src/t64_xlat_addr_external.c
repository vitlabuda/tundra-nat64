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

#include"t64_tundra.h"
#include"t64_xlat_addr_external.h"

#include"t64_utils.h"
#include"t64_utils_ip.h"
#include"t64_log.h"
#include"t64_conf_file.h"
#include"t64_router_ipv4.h"
#include"t64_router_ipv6.h"
#include"t64_xlat_interrupt.h"


#define _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_MAGIC_BYTE ((uint8_t) 0x54)
#define _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_VERSION ((uint8_t) 1)

// These values could be put inside an enum, but since their main purpose is to be put as integers into messages, it
//  seems to me that defining them this way is more appropriate.
#define _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_TYPE_4TO6_MAIN_PACKET ((uint8_t) 1)
#define _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_TYPE_4TO6_ICMP_ERROR_PACKET ((uint8_t) 2)
#define _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_TYPE_6TO4_MAIN_PACKET ((uint8_t) 3)
#define _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_TYPE_6TO4_ICMP_ERROR_PACKET ((uint8_t) 4)


static bool _t64f_xlat_addr_external__perform_external_address_translation(t64ts_tundra__xlat_thread_context *context, const uint8_t message_type, const uint8_t *in_src_ip, const uint8_t *in_dst_ip, uint8_t *out_src_ip, uint8_t *out_dst_ip, uint8_t *out_cache_lifetime);
static bool _t64f_xlat_addr_external__construct_and_send_request_message_to_external_translation_fd(t64ts_tundra__xlat_thread_context *context, t64ts_tundra__external_addr_xlat_message *message_buf, const uint8_t message_type, const uint32_t message_identifier, const uint8_t *in_src_ip, const uint8_t *in_dst_ip);
static bool _t64f_xlat_addr_external__receive_and_parse_response_message_from_external_translation_fd(t64ts_tundra__xlat_thread_context *context, t64ts_tundra__external_addr_xlat_message *message_buf, const uint8_t message_type, const uint32_t message_identifier, uint8_t *out_src_ip, uint8_t *out_dst_ip, uint8_t *out_cache_lifetime);
static bool _t64f_xlat_addr_external__ensure_external_translation_fds_are_open(t64ts_tundra__xlat_thread_context *context);
static void _t64f_xlat_addr_external__close_external_translation_fds_if_necessary(t64ts_tundra__xlat_thread_context *context);
static int _t64f_xlat_addr_external__open_external_translation_socket(const int family, const int protocol, const struct sockaddr *address, const socklen_t address_length, const struct timeval *timeout);
static bool _t64f_xlat_addr_external__receive_message_from_external_translation_fd(t64ts_tundra__xlat_thread_context *context, t64ts_tundra__external_addr_xlat_message *message_buf);
static bool _t64f_xlat_addr_external__send_message_to_external_translation_fd(t64ts_tundra__xlat_thread_context *context, const t64ts_tundra__external_addr_xlat_message *message_buf);
static bool _t64f_xlat_addr_external__attempt_to_perform_4to6_address_translation_using_cache(const t64ts_tundra__external_addr_xlat_cache_entry *cache, const size_t cache_size, const uint8_t *in_src_ipv4, const uint8_t *in_dst_ipv4, uint8_t *out_src_ipv6, uint8_t *out_dst_ipv6);
static bool _t64f_xlat_addr_external__attempt_to_perform_6to4_address_translation_using_cache(const t64ts_tundra__external_addr_xlat_cache_entry *cache, const size_t cache_size, const uint8_t *in_src_ipv6, const uint8_t *in_dst_ipv6, uint8_t *out_src_ipv4, uint8_t *out_dst_ipv4);
static void _t64f_xlat_addr_external__save_4to6_address_mapping_to_cache(t64ts_tundra__external_addr_xlat_cache_entry *cache, const size_t cache_size, const uint8_t *in_src_ipv4, const uint8_t *in_dst_ipv4, const uint8_t *out_src_ipv6, const uint8_t *out_dst_ipv6, const time_t cache_lifetime);
static void _t64f_xlat_addr_external__save_6to4_address_mapping_to_cache(t64ts_tundra__external_addr_xlat_cache_entry *cache, const size_t cache_size, const uint8_t *in_src_ipv6, const uint8_t *in_dst_ipv6, const uint8_t *out_src_ipv4, const uint8_t *out_dst_ipv4, const time_t cache_lifetime);
static void _t64f_xlat_addr_external__save_address_mapping_to_target_cache_entry(t64ts_tundra__external_addr_xlat_cache_entry *target_entry, const uint8_t *src_ipv4, const uint8_t *dst_ipv4, const uint8_t *src_ipv6, const uint8_t *dst_ipv6, const time_t cache_lifetime);
static inline size_t _t64f_xlat_addr_external__compute_cache_hash_from_in_ipv4_address_pair(const uint32_t *in_src_ipv4, const uint32_t *in_dst_ipv4, const size_t cache_size);
static inline size_t _t64f_xlat_addr_external__compute_cache_hash_from_in_ipv6_address_pair(const uint64_t *in_src_ipv6, const uint64_t *in_dst_ipv6, const size_t cache_size);
static inline time_t _t64f_xlat_addr_external__get_current_timestamp_in_seconds(void);


bool t64f_xlat_addr_external__perform_4to6_address_translation_for_main_packet(t64ts_tundra__xlat_thread_context *context, const uint8_t *in_src_ipv4, const uint8_t *in_dst_ipv4, uint8_t *out_src_ipv6, uint8_t *out_dst_ipv6) {
    if(_t64f_xlat_addr_external__attempt_to_perform_4to6_address_translation_using_cache(
        context->external_addr_xlat_state->address_cache_4to6_main_packet,
        context->configuration->addressing_external_cache_size_main_addresses,
        in_src_ipv4, in_dst_ipv4, out_src_ipv6, out_dst_ipv6
    )) return true;

    uint8_t cache_lifetime = 0;
    if(!_t64f_xlat_addr_external__perform_external_address_translation(context, _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_TYPE_4TO6_MAIN_PACKET, in_src_ipv4, in_dst_ipv4, out_src_ipv6, out_dst_ipv6, &cache_lifetime))
        return false;

    _t64f_xlat_addr_external__save_4to6_address_mapping_to_cache(
        context->external_addr_xlat_state->address_cache_4to6_main_packet,
        context->configuration->addressing_external_cache_size_main_addresses,
        in_src_ipv4, in_dst_ipv4, out_src_ipv6, out_dst_ipv6,
        (time_t) cache_lifetime
    );

    return true;
}

bool t64f_xlat_addr_external__perform_4to6_address_translation_for_icmp_error_packet(t64ts_tundra__xlat_thread_context *context, const uint8_t *in_src_ipv4, const uint8_t *in_dst_ipv4, uint8_t *out_src_ipv6, uint8_t *out_dst_ipv6) {
    if(_t64f_xlat_addr_external__attempt_to_perform_4to6_address_translation_using_cache(
        context->external_addr_xlat_state->address_cache_4to6_icmp_error_packet,
        context->configuration->addressing_external_cache_size_icmp_error_addresses,
        in_src_ipv4, in_dst_ipv4, out_src_ipv6, out_dst_ipv6
    )) return true;

    uint8_t cache_lifetime = 0;
    if(!_t64f_xlat_addr_external__perform_external_address_translation(context, _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_TYPE_4TO6_ICMP_ERROR_PACKET, in_src_ipv4, in_dst_ipv4, out_src_ipv6, out_dst_ipv6, &cache_lifetime))
        return false;

    _t64f_xlat_addr_external__save_4to6_address_mapping_to_cache(
        context->external_addr_xlat_state->address_cache_4to6_icmp_error_packet,
        context->configuration->addressing_external_cache_size_icmp_error_addresses,
        in_src_ipv4, in_dst_ipv4, out_src_ipv6, out_dst_ipv6,
        (time_t) cache_lifetime
    );

    return true;
}

bool t64f_xlat_addr_external__perform_6to4_address_translation_for_main_packet(t64ts_tundra__xlat_thread_context *context, const uint8_t *in_src_ipv6, const uint8_t *in_dst_ipv6, uint8_t *out_src_ipv4, uint8_t *out_dst_ipv4) {
    if(_t64f_xlat_addr_external__attempt_to_perform_6to4_address_translation_using_cache(
        context->external_addr_xlat_state->address_cache_6to4_main_packet,
        context->configuration->addressing_external_cache_size_main_addresses,
        in_src_ipv6, in_dst_ipv6, out_src_ipv4, out_dst_ipv4
    )) return true;

    uint8_t cache_lifetime = 0;
    if(!_t64f_xlat_addr_external__perform_external_address_translation(context, _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_TYPE_6TO4_MAIN_PACKET, in_src_ipv6, in_dst_ipv6, out_src_ipv4, out_dst_ipv4, &cache_lifetime))
        return false;

    _t64f_xlat_addr_external__save_6to4_address_mapping_to_cache(
        context->external_addr_xlat_state->address_cache_6to4_main_packet,
        context->configuration->addressing_external_cache_size_main_addresses,
        in_src_ipv6, in_dst_ipv6, out_src_ipv4, out_dst_ipv4,
        (time_t) cache_lifetime
    );

    return true;
}

bool t64f_xlat_addr_external__perform_6to4_address_translation_for_icmp_error_packet(t64ts_tundra__xlat_thread_context *context, const uint8_t *in_src_ipv6, const uint8_t *in_dst_ipv6, uint8_t *out_src_ipv4, uint8_t *out_dst_ipv4) {
    if(_t64f_xlat_addr_external__attempt_to_perform_6to4_address_translation_using_cache(
        context->external_addr_xlat_state->address_cache_6to4_icmp_error_packet,
        context->configuration->addressing_external_cache_size_icmp_error_addresses,
        in_src_ipv6, in_dst_ipv6, out_src_ipv4, out_dst_ipv4
    )) return true;

    uint8_t cache_lifetime = 0;
    if(!_t64f_xlat_addr_external__perform_external_address_translation(context, _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_TYPE_6TO4_ICMP_ERROR_PACKET, in_src_ipv6, in_dst_ipv6, out_src_ipv4, out_dst_ipv4, &cache_lifetime))
        return false;

    _t64f_xlat_addr_external__save_6to4_address_mapping_to_cache(
        context->external_addr_xlat_state->address_cache_6to4_icmp_error_packet,
        context->configuration->addressing_external_cache_size_icmp_error_addresses,
        in_src_ipv6, in_dst_ipv6, out_src_ipv4, out_dst_ipv4,
        (time_t) cache_lifetime
    );

    return true;
}

static bool _t64f_xlat_addr_external__perform_external_address_translation(t64ts_tundra__xlat_thread_context *context, const uint8_t message_type, const uint8_t *in_src_ip, const uint8_t *in_dst_ip, uint8_t *out_src_ip, uint8_t *out_dst_ip, uint8_t *out_cache_lifetime) {
    if(!_t64f_xlat_addr_external__ensure_external_translation_fds_are_open(context))
        return false;

    const uint32_t message_identifier = htonl(context->external_addr_xlat_state->message_identifier);
    context->external_addr_xlat_state->message_identifier++; // htonl() may be a macro

    t64ts_tundra__external_addr_xlat_message message;

    if(!_t64f_xlat_addr_external__construct_and_send_request_message_to_external_translation_fd(context, &message, message_type, message_identifier, in_src_ip, in_dst_ip))
        return false;

    return _t64f_xlat_addr_external__receive_and_parse_response_message_from_external_translation_fd(context, &message, message_type, message_identifier, out_src_ip, out_dst_ip, out_cache_lifetime);
}

static bool _t64f_xlat_addr_external__construct_and_send_request_message_to_external_translation_fd(t64ts_tundra__xlat_thread_context *context, t64ts_tundra__external_addr_xlat_message *message_buf, const uint8_t message_type, const uint32_t message_identifier, const uint8_t *in_src_ip, const uint8_t *in_dst_ip) {
    T64M_UTILS__MEMORY_ZERO_OUT(message_buf, sizeof(t64ts_tundra__external_addr_xlat_message));  // Fields which are not further modified will be set to 0

    message_buf->magic_byte = _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_MAGIC_BYTE;
    message_buf->version = _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_VERSION;
    message_buf->message_type = message_type;
    message_buf->message_identifier = message_identifier;

    switch(message_type) {
        case _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_TYPE_4TO6_MAIN_PACKET:  // The fall-through is intentional!
            if(
                t64f_utils_ip__is_ipv4_address_unusable(in_src_ip) || T64M_UTILS_IP__IPV4_ADDRESSES_EQUAL(in_src_ip, context->configuration->router_ipv4) ||
                t64f_utils_ip__is_ipv4_address_unusable(in_dst_ip) || T64M_UTILS_IP__IPV4_ADDRESSES_EQUAL(in_dst_ip, context->configuration->router_ipv4)
            ) return false;
            __attribute__((fallthrough));

        case _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_TYPE_4TO6_ICMP_ERROR_PACKET:
            memcpy(message_buf->src_ip, in_src_ip, 4);
            memcpy(message_buf->dst_ip, in_dst_ip, 4);
            break;

        case _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_TYPE_6TO4_MAIN_PACKET:  // The fall-through is intentional!
            if(
                t64f_utils_ip__is_ipv6_address_unusable(in_src_ip) || T64M_UTILS_IP__IPV6_ADDRESSES_EQUAL(in_src_ip, context->configuration->router_ipv6) ||
                t64f_utils_ip__is_ipv6_address_unusable(in_dst_ip) || T64M_UTILS_IP__IPV6_ADDRESSES_EQUAL(in_dst_ip, context->configuration->router_ipv6)
            ) return false;
            __attribute__((fallthrough));

        case _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_TYPE_6TO4_ICMP_ERROR_PACKET:
            memcpy(message_buf->src_ip, in_src_ip, 16);
            memcpy(message_buf->dst_ip, in_dst_ip, 16);
            break;

        default:
            t64f_log__thread_crash_invalid_internal_state(context->thread_id, "Invalid message type");
    }

    return _t64f_xlat_addr_external__send_message_to_external_translation_fd(context, message_buf);
}

static bool _t64f_xlat_addr_external__receive_and_parse_response_message_from_external_translation_fd(t64ts_tundra__xlat_thread_context *context, t64ts_tundra__external_addr_xlat_message *message_buf, const uint8_t message_type, const uint32_t message_identifier, uint8_t *out_src_ip, uint8_t *out_dst_ip, uint8_t *out_cache_lifetime) {
    /*
     * The protocol specification states that if a value of a field in certain types of messages is not explicitly
     * defined in it (e.g. what addresses should the IP address fields contain in case of an erroneous 'response'
     * message), the field must be zeroed out. However, this implementation does not check this requirement as of now,
     * since it does not need to (it does not access the fields in these "undefined" cases). This behaviour might,
     * however, change in a future version of this program, so it is not a good idea to rely on it.
     */

    if(!_t64f_xlat_addr_external__receive_message_from_external_translation_fd(context, message_buf))
        return false;

    if(message_buf->magic_byte != _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_MAGIC_BYTE || message_buf->version != _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_VERSION || message_buf->message_identifier != message_identifier) {
        _t64f_xlat_addr_external__close_external_translation_fds_if_necessary(context);
        return false;
    }

    if(message_buf->message_type == (message_type + 224)) {  // Bits set: response, error, ICMP
        switch(message_type) {
            case _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_TYPE_4TO6_MAIN_PACKET:
                t64f_router_ipv4__send_icmpv4_destination_host_unreachable_message_to_in_ipv4_packet_source_host(context);
                return false;

            case _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_TYPE_6TO4_MAIN_PACKET:
                t64f_router_ipv6__send_icmpv6_address_unreachable_message_to_in_ipv6_packet_source_host(context);
                return false;

            case _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_TYPE_4TO6_ICMP_ERROR_PACKET:
            case _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_TYPE_6TO4_ICMP_ERROR_PACKET:
                // These message types signify that the addresses of a partial packet inside an ICMP error message's
                //  body are being translated, and since ICMPv4 Destination Host Unreachable / ICMPv6 Address
                //  Unreachable signify that the main (outer) packet's addresses are those in error, it would be a
                //  mistake to send them in this case
                _t64f_xlat_addr_external__close_external_translation_fds_if_necessary(context);
                return false;

            default:
                t64f_log__thread_crash_invalid_internal_state(context->thread_id, "Invalid message type");
        }
    }

    if(message_buf->message_type == (message_type + 192)) {  // Bits set: response, error
        return false;
    }

    if(message_buf->message_type == (message_type + 128)) {  // Bits set: response
        switch(message_type) {
            case _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_TYPE_4TO6_MAIN_PACKET:  // The fall-through is intentional!
                if(
                    t64f_utils_ip__is_ipv6_address_unusable(message_buf->src_ip) || T64M_UTILS_IP__IPV6_ADDRESSES_EQUAL(message_buf->src_ip, context->configuration->router_ipv6) ||
                    t64f_utils_ip__is_ipv6_address_unusable(message_buf->dst_ip) || T64M_UTILS_IP__IPV6_ADDRESSES_EQUAL(message_buf->dst_ip, context->configuration->router_ipv6)
                ) return false;
                __attribute__((fallthrough));

            case _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_TYPE_4TO6_ICMP_ERROR_PACKET:
                memcpy(out_src_ip, message_buf->src_ip, 16);
                memcpy(out_dst_ip, message_buf->dst_ip, 16);
                break;

            case _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_TYPE_6TO4_MAIN_PACKET:  // The fall-through is intentional!
                if(
                    t64f_utils_ip__is_ipv4_address_unusable(message_buf->src_ip) || T64M_UTILS_IP__IPV4_ADDRESSES_EQUAL(message_buf->src_ip, context->configuration->router_ipv4) ||
                    t64f_utils_ip__is_ipv4_address_unusable(message_buf->dst_ip) || T64M_UTILS_IP__IPV4_ADDRESSES_EQUAL(message_buf->dst_ip, context->configuration->router_ipv4)
                ) return false;
                __attribute__((fallthrough));

            case _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_TYPE_6TO4_ICMP_ERROR_PACKET:
                if(!T64M_UTILS__MEMORY_EQUAL(((uint8_t *) message_buf->src_ip) + 4, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12) || !T64M_UTILS__MEMORY_EQUAL(((uint8_t *) message_buf->dst_ip) + 4, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12)) {
                    _t64f_xlat_addr_external__close_external_translation_fds_if_necessary(context);
                    return false;
                }
                memcpy(out_src_ip, message_buf->src_ip, 4);
                memcpy(out_dst_ip, message_buf->dst_ip, 4);
                break;

            default:
                t64f_log__thread_crash_invalid_internal_state(context->thread_id, "Invalid message type");
        }

        *out_cache_lifetime = message_buf->cache_lifetime;
        return true;
    }

    _t64f_xlat_addr_external__close_external_translation_fds_if_necessary(context);
    return false;
}

static bool _t64f_xlat_addr_external__ensure_external_translation_fds_are_open(t64ts_tundra__xlat_thread_context *context) {
    if(context->external_addr_xlat_state->read_fd >= 0 && context->external_addr_xlat_state->write_fd >= 0)
        return true;

    // Since at least one of the file descriptors is not open, it is necessary to acquire a pair of new ones (after any
    //  leftover file descriptors have been closed)
    _t64f_xlat_addr_external__close_external_translation_fds_if_necessary(context);

    switch(context->configuration->addressing_external_transport) {
        case T64TE_TUNDRA__ADDRESSING_EXTERNAL_TRANSPORT_INHERITED_FDS:
            // If the inherited file descriptors fail, there is no way of obtaining new ones, and the only option is
            //  to crash the program
            t64f_log__thread_crash(context->thread_id, false, "At least one of the inherited file descriptors for the '"T64C_CONF_FILE__ADDRESSING_EXTERNAL_TRANSPORT_INHERITED_FDS"' transport of the '"T64C_CONF_FILE__ADDRESSING_MODE_EXTERNAL"' addressing mode failed!");

        case T64TE_TUNDRA__ADDRESSING_EXTERNAL_TRANSPORT_UNIX:
            {
                const int socket_fd = _t64f_xlat_addr_external__open_external_translation_socket(AF_UNIX, 0, (const struct sockaddr *) &context->configuration->addressing_external_unix_socket_info, (const socklen_t) sizeof(struct sockaddr_un), (const struct timeval *) &context->configuration->addressing_external_unix_tcp_timeout);
                if(socket_fd >= 0) {
                    context->external_addr_xlat_state->read_fd = context->external_addr_xlat_state->write_fd = socket_fd;
                    return true;
                }
            }
            break;

        case T64TE_TUNDRA__ADDRESSING_EXTERNAL_TRANSPORT_TCP:
            for(struct addrinfo *current_addrinfo = context->configuration->addressing_external_tcp_socket_info; current_addrinfo != NULL; current_addrinfo = current_addrinfo->ai_next) {
                const int socket_fd = _t64f_xlat_addr_external__open_external_translation_socket(current_addrinfo->ai_family, IPPROTO_TCP, (const struct sockaddr *) current_addrinfo->ai_addr, (const socklen_t) current_addrinfo->ai_addrlen, (const struct timeval *) &context->configuration->addressing_external_unix_tcp_timeout);
                if(socket_fd >= 0) {
                    context->external_addr_xlat_state->read_fd = context->external_addr_xlat_state->write_fd = socket_fd;
                    return true;
                }
            }
            break;

        default:
            t64f_log__thread_crash_invalid_internal_state(context->thread_id, "Invalid addressing external transport");
    }

    return false;
}

static void _t64f_xlat_addr_external__close_external_translation_fds_if_necessary(t64ts_tundra__xlat_thread_context *context) {
    if(context->external_addr_xlat_state->read_fd >= 0)
        t64f_xlat_interrupt__close(context->external_addr_xlat_state->read_fd);
    if(context->external_addr_xlat_state->write_fd >= 0 && context->external_addr_xlat_state->write_fd != context->external_addr_xlat_state->read_fd)
        t64f_xlat_interrupt__close(context->external_addr_xlat_state->write_fd);

    context->external_addr_xlat_state->read_fd = context->external_addr_xlat_state->write_fd = -1;
}

static int _t64f_xlat_addr_external__open_external_translation_socket(const int family, const int protocol, const struct sockaddr *address, const socklen_t address_length, const struct timeval *timeout) {
    const int socket_fd = socket(family, SOCK_STREAM, protocol);
    if(socket_fd < 0)
        return -1;

    if(
        (t64f_xlat_interrupt__connect(socket_fd, address, address_length, true) < 0) ||
        (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, timeout, sizeof(struct timeval)) < 0) ||
        (setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, timeout, sizeof(struct timeval)) < 0)
    ) {
        t64f_xlat_interrupt__close(socket_fd);
        return -1;
    }

    return socket_fd;
}

static bool _t64f_xlat_addr_external__receive_message_from_external_translation_fd(t64ts_tundra__xlat_thread_context *context, t64ts_tundra__external_addr_xlat_message *message_buf) {
    uint8_t *current_ptr = (uint8_t *) message_buf;
    ssize_t remaining_bytes = sizeof(t64ts_tundra__external_addr_xlat_message);

    while(remaining_bytes > 0) {
        const ssize_t return_value = t64f_xlat_interrupt__read(context->external_addr_xlat_state->read_fd, current_ptr, (size_t) remaining_bytes);

        if(return_value < 1) {
            _t64f_xlat_addr_external__close_external_translation_fds_if_necessary(context);
            return false;
        }

        current_ptr += return_value;
        remaining_bytes -= return_value;
    }

    return true;
}

static bool _t64f_xlat_addr_external__send_message_to_external_translation_fd(t64ts_tundra__xlat_thread_context *context, const t64ts_tundra__external_addr_xlat_message *message_buf) {
    const uint8_t *current_ptr = (const uint8_t *) message_buf;
    ssize_t remaining_bytes = sizeof(t64ts_tundra__external_addr_xlat_message);

    while(remaining_bytes > 0) {
        const ssize_t return_value = t64f_xlat_interrupt__write(context->external_addr_xlat_state->write_fd, current_ptr, (size_t) remaining_bytes);

        if(return_value < 1) {
            _t64f_xlat_addr_external__close_external_translation_fds_if_necessary(context);
            return false;
        }

        current_ptr += return_value;
        remaining_bytes -= return_value;
    }

    return true;
}

static bool _t64f_xlat_addr_external__attempt_to_perform_4to6_address_translation_using_cache(const t64ts_tundra__external_addr_xlat_cache_entry *cache, const size_t cache_size, const uint8_t *in_src_ipv4, const uint8_t *in_dst_ipv4, uint8_t *out_src_ipv6, uint8_t *out_dst_ipv6) {
    if(cache_size <= 0)
        return false;

    // The cache is a simple hash map
    const t64ts_tundra__external_addr_xlat_cache_entry *target_entry = (cache + _t64f_xlat_addr_external__compute_cache_hash_from_in_ipv4_address_pair((const uint32_t *) in_src_ipv4, (const uint32_t *) in_dst_ipv4, cache_size));

    if(
        !T64M_UTILS_IP__IPV4_ADDRESSES_EQUAL(in_src_ipv4, target_entry->src_ipv4) ||
        !T64M_UTILS_IP__IPV4_ADDRESSES_EQUAL(in_dst_ipv4, target_entry->dst_ipv4) ||
        (target_entry->expiration_timestamp <= 0)  // '0' signifies that the cache entry is unused
    ) return false;

    const time_t current_timestamp = _t64f_xlat_addr_external__get_current_timestamp_in_seconds();
    if(current_timestamp <= 0 || current_timestamp >= target_entry->expiration_timestamp)
        return false;

    memcpy(out_src_ipv6, target_entry->src_ipv6, 16);
    memcpy(out_dst_ipv6, target_entry->dst_ipv6, 16);

    return true;
}

static bool _t64f_xlat_addr_external__attempt_to_perform_6to4_address_translation_using_cache(const t64ts_tundra__external_addr_xlat_cache_entry *cache, const size_t cache_size, const uint8_t *in_src_ipv6, const uint8_t *in_dst_ipv6, uint8_t *out_src_ipv4, uint8_t *out_dst_ipv4) {
    if(cache_size <= 0)
        return false;

    // The cache is a simple hash map
    const t64ts_tundra__external_addr_xlat_cache_entry *target_entry = (cache + _t64f_xlat_addr_external__compute_cache_hash_from_in_ipv6_address_pair((const uint64_t *) in_src_ipv6, (const uint64_t *) in_dst_ipv6, cache_size));

    if(
        !T64M_UTILS_IP__IPV6_ADDRESSES_EQUAL(in_src_ipv6, target_entry->src_ipv6) ||
        !T64M_UTILS_IP__IPV6_ADDRESSES_EQUAL(in_dst_ipv6, target_entry->dst_ipv6) ||
        (target_entry->expiration_timestamp <= 0)  // '0' signifies that the cache entry is unused
    ) return false;

    const time_t current_timestamp = _t64f_xlat_addr_external__get_current_timestamp_in_seconds();
    if(current_timestamp <= 0 || current_timestamp >= target_entry->expiration_timestamp)
        return false;

    memcpy(out_src_ipv4, target_entry->src_ipv4, 4);
    memcpy(out_dst_ipv4, target_entry->dst_ipv4, 4);

    return true;
}

static void _t64f_xlat_addr_external__save_4to6_address_mapping_to_cache(t64ts_tundra__external_addr_xlat_cache_entry *cache, const size_t cache_size, const uint8_t *in_src_ipv4, const uint8_t *in_dst_ipv4, const uint8_t *out_src_ipv6, const uint8_t *out_dst_ipv6, const time_t cache_lifetime) {
    if(cache_size <= 0)
        return;

    // The cache is a simple hash map
    t64ts_tundra__external_addr_xlat_cache_entry *target_entry = (cache + _t64f_xlat_addr_external__compute_cache_hash_from_in_ipv4_address_pair((const uint32_t *) in_src_ipv4, (const uint32_t *) in_dst_ipv4, cache_size));

    _t64f_xlat_addr_external__save_address_mapping_to_target_cache_entry(target_entry, in_src_ipv4, in_dst_ipv4, out_src_ipv6, out_dst_ipv6, cache_lifetime);
}

static void _t64f_xlat_addr_external__save_6to4_address_mapping_to_cache(t64ts_tundra__external_addr_xlat_cache_entry *cache, const size_t cache_size, const uint8_t *in_src_ipv6, const uint8_t *in_dst_ipv6, const uint8_t *out_src_ipv4, const uint8_t *out_dst_ipv4, const time_t cache_lifetime) {
    if(cache_size <= 0)
        return;

    // The cache is a simple hash map
    t64ts_tundra__external_addr_xlat_cache_entry *target_entry = (cache + _t64f_xlat_addr_external__compute_cache_hash_from_in_ipv6_address_pair((const uint64_t *) in_src_ipv6, (const uint64_t *) in_dst_ipv6, cache_size));

    _t64f_xlat_addr_external__save_address_mapping_to_target_cache_entry(target_entry, out_src_ipv4, out_dst_ipv4, in_src_ipv6, in_dst_ipv6, cache_lifetime);
}

static void _t64f_xlat_addr_external__save_address_mapping_to_target_cache_entry(t64ts_tundra__external_addr_xlat_cache_entry *target_entry, const uint8_t *src_ipv4, const uint8_t *dst_ipv4, const uint8_t *src_ipv6, const uint8_t *dst_ipv6, const time_t cache_lifetime) {
    if(cache_lifetime == 0)  // '0' means "do not cache"
        return;

    const time_t current_timestamp = _t64f_xlat_addr_external__get_current_timestamp_in_seconds();
    if(current_timestamp <= 0)
        return;

    // This may overwrite an existing cache entry
    target_entry->expiration_timestamp = (current_timestamp + cache_lifetime);
    memcpy(target_entry->src_ipv4, src_ipv4, 4);
    memcpy(target_entry->dst_ipv4, dst_ipv4, 4);
    memcpy(target_entry->src_ipv6, src_ipv6, 16);
    memcpy(target_entry->dst_ipv6, dst_ipv6, 16);
}

static inline size_t _t64f_xlat_addr_external__compute_cache_hash_from_in_ipv4_address_pair(const uint32_t *in_src_ipv4, const uint32_t *in_dst_ipv4, const size_t cache_size) {
    return (((size_t) ((*in_src_ipv4) + (*in_dst_ipv4))) % cache_size);
}

static inline size_t _t64f_xlat_addr_external__compute_cache_hash_from_in_ipv6_address_pair(const uint64_t *in_src_ipv6, const uint64_t *in_dst_ipv6, const size_t cache_size) {
    return (((size_t) (in_src_ipv6[0] + in_src_ipv6[1] + in_dst_ipv6[0] + in_dst_ipv6[1])) % cache_size);
}

static inline time_t _t64f_xlat_addr_external__get_current_timestamp_in_seconds(void) {
    struct timespec time_specification;
    T64M_UTILS__MEMORY_ZERO_OUT(&time_specification, sizeof(struct timespec));

    if(clock_gettime(CLOCK_MONOTONIC_RAW, &time_specification) < 0)
        return 0;

    return time_specification.tv_sec;
}


#undef _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_MAGIC_BYTE
#undef _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_VERSION

#undef _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_TYPE_4TO6_MAIN_PACKET
#undef _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_TYPE_4TO6_ICMP_ERROR_PACKET
#undef _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_TYPE_6TO4_MAIN_PACKET
#undef _T64C_XLAT_ADDR_EXTERNAL__MESSAGE_TYPE_6TO4_ICMP_ERROR_PACKET
