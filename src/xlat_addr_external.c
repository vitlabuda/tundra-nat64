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
#include"xlat_addr_external.h"

#include"utils.h"
#include"utils_ip.h"
#include"log.h"
#include"router_ipv4.h"
#include"router_ipv6.h"
#include"xlat_interrupt.h"


#define _MESSAGE_MAGIC_BYTE ((uint8_t) 0x54)
#define _MESSAGE_VERSION ((uint8_t) 1)

// These values could be put inside an enum, but since their main purpose is to be put as integers into messages, it
//  seems to me that defining them this way is more appropriate.
#define _MESSAGE_TYPE_4TO6_MAIN_PACKET ((uint8_t) 1)
#define _MESSAGE_TYPE_4TO6_ICMP_ERROR_PACKET ((uint8_t) 2)
#define _MESSAGE_TYPE_6TO4_MAIN_PACKET ((uint8_t) 3)
#define _MESSAGE_TYPE_6TO4_ICMP_ERROR_PACKET ((uint8_t) 4)


static bool _do_external_address_translation(tundra__thread_ctx *const ctx, const uint8_t message_type, const uint8_t *in_src_ip, const uint8_t *in_dst_ip, uint8_t *out_src_ip, uint8_t *out_dst_ip, uint8_t *out_cache_lifetime);
static bool _construct_and_send_request_to_fd(tundra__thread_ctx *const ctx, tundra__external_addr_xlat_message *message_buf, const uint8_t message_type, const uint32_t message_identifier, const uint8_t *in_src_ip, const uint8_t *in_dst_ip);
static bool _recv_and_parse_response_from_fd(tundra__thread_ctx *const ctx, tundra__external_addr_xlat_message *message_buf, const uint8_t message_type, const uint32_t message_identifier, uint8_t *out_src_ip, uint8_t *out_dst_ip, uint8_t *out_cache_lifetime);
static bool _ensure_fds_are_open(tundra__thread_ctx *const ctx);
static void _close_fds_if_necessary(tundra__thread_ctx *const ctx);
static int _open_socket(const int family, const int protocol, const struct sockaddr *address, const socklen_t address_length, const struct timeval *timeout);
static bool _recv_message_from_fd(tundra__thread_ctx *const ctx, tundra__external_addr_xlat_message *message_buf);
static bool _send_message_to_fd(tundra__thread_ctx *const ctx, const tundra__external_addr_xlat_message *message_buf);
static bool _try_doing_4to6_addr_translation_using_cache(const tundra__external_addr_xlat_cache_entry *cache, const size_t cache_size, const uint8_t *in_src_ipv4, const uint8_t *in_dst_ipv4, uint8_t *out_src_ipv6, uint8_t *out_dst_ipv6);
static bool _try_doing_6to4_addr_translation_using_cache(const tundra__external_addr_xlat_cache_entry *cache, const size_t cache_size, const uint8_t *in_src_ipv6, const uint8_t *in_dst_ipv6, uint8_t *out_src_ipv4, uint8_t *out_dst_ipv4);
static void _save_4to6_addr_mapping_to_cache(tundra__external_addr_xlat_cache_entry *cache, const size_t cache_size, const uint8_t *in_src_ipv4, const uint8_t *in_dst_ipv4, const uint8_t *out_src_ipv6, const uint8_t *out_dst_ipv6, const time_t cache_lifetime);
static void _save_6to4_addr_mapping_to_cache(tundra__external_addr_xlat_cache_entry *cache, const size_t cache_size, const uint8_t *in_src_ipv6, const uint8_t *in_dst_ipv6, const uint8_t *out_src_ipv4, const uint8_t *out_dst_ipv4, const time_t cache_lifetime);
static void _save_addr_mapping_to_target_cache_entry(tundra__external_addr_xlat_cache_entry *target_entry, const uint8_t *src_ipv4, const uint8_t *dst_ipv4, const uint8_t *src_ipv6, const uint8_t *dst_ipv6, const time_t cache_lifetime);
static inline size_t _get_hash_from_in_ipv4_addr_pair(const uint32_t *in_src_ipv4, const uint32_t *in_dst_ipv4, const size_t cache_size);
static inline size_t _get_hash_from_in_ipv6_addr_pair(const uint64_t *in_src_ipv6, const uint64_t *in_dst_ipv6, const size_t cache_size);
static inline time_t _get_current_timestamp(void);


bool xlat_addr_external__translate_4to6_addr_for_main_packet(tundra__thread_ctx *const ctx, const uint8_t *in_src_ipv4, const uint8_t *in_dst_ipv4, uint8_t *out_src_ipv6, uint8_t *out_dst_ipv6) {
    if(_try_doing_4to6_addr_translation_using_cache(
        ctx->external_addr_xlat_state->cache_4to6_main_packet,
        ctx->config->addressing_external_cache_size_main_addresses,
        in_src_ipv4, in_dst_ipv4, out_src_ipv6, out_dst_ipv6
    )) return true;

    uint8_t cache_lifetime = 0;
    if(!_do_external_address_translation(ctx, _MESSAGE_TYPE_4TO6_MAIN_PACKET, in_src_ipv4, in_dst_ipv4, out_src_ipv6, out_dst_ipv6, &cache_lifetime))
        return false;

    _save_4to6_addr_mapping_to_cache(
        ctx->external_addr_xlat_state->cache_4to6_main_packet,
        ctx->config->addressing_external_cache_size_main_addresses,
        in_src_ipv4, in_dst_ipv4, out_src_ipv6, out_dst_ipv6,
        (time_t) cache_lifetime
    );

    return true;
}

bool xlat_addr_external__translate_4to6_addr_for_icmp_error_packet(tundra__thread_ctx *const ctx, const uint8_t *in_src_ipv4, const uint8_t *in_dst_ipv4, uint8_t *out_src_ipv6, uint8_t *out_dst_ipv6) {
    if(_try_doing_4to6_addr_translation_using_cache(
        ctx->external_addr_xlat_state->cache_4to6_icmp_error_packet,
        ctx->config->addressing_external_cache_size_icmp_error_addresses,
        in_src_ipv4, in_dst_ipv4, out_src_ipv6, out_dst_ipv6
    )) return true;

    uint8_t cache_lifetime = 0;
    if(!_do_external_address_translation(ctx, _MESSAGE_TYPE_4TO6_ICMP_ERROR_PACKET, in_src_ipv4, in_dst_ipv4, out_src_ipv6, out_dst_ipv6, &cache_lifetime))
        return false;

    _save_4to6_addr_mapping_to_cache(
        ctx->external_addr_xlat_state->cache_4to6_icmp_error_packet,
        ctx->config->addressing_external_cache_size_icmp_error_addresses,
        in_src_ipv4, in_dst_ipv4, out_src_ipv6, out_dst_ipv6,
        (time_t) cache_lifetime
    );

    return true;
}

bool xlat_addr_external__translate_6to4_addr_for_main_packet(tundra__thread_ctx *const ctx, const uint8_t *in_src_ipv6, const uint8_t *in_dst_ipv6, uint8_t *out_src_ipv4, uint8_t *out_dst_ipv4) {
    if(_try_doing_6to4_addr_translation_using_cache(
        ctx->external_addr_xlat_state->cache_6to4_main_packet,
        ctx->config->addressing_external_cache_size_main_addresses,
        in_src_ipv6, in_dst_ipv6, out_src_ipv4, out_dst_ipv4
    )) return true;

    uint8_t cache_lifetime = 0;
    if(!_do_external_address_translation(ctx, _MESSAGE_TYPE_6TO4_MAIN_PACKET, in_src_ipv6, in_dst_ipv6, out_src_ipv4, out_dst_ipv4, &cache_lifetime))
        return false;

    _save_6to4_addr_mapping_to_cache(
        ctx->external_addr_xlat_state->cache_6to4_main_packet,
        ctx->config->addressing_external_cache_size_main_addresses,
        in_src_ipv6, in_dst_ipv6, out_src_ipv4, out_dst_ipv4,
        (time_t) cache_lifetime
    );

    return true;
}

bool xlat_addr_external__translate_6to4_addr_for_icmp_error_packet(tundra__thread_ctx *const ctx, const uint8_t *in_src_ipv6, const uint8_t *in_dst_ipv6, uint8_t *out_src_ipv4, uint8_t *out_dst_ipv4) {
    if(_try_doing_6to4_addr_translation_using_cache(
        ctx->external_addr_xlat_state->cache_6to4_icmp_error_packet,
        ctx->config->addressing_external_cache_size_icmp_error_addresses,
        in_src_ipv6, in_dst_ipv6, out_src_ipv4, out_dst_ipv4
    )) return true;

    uint8_t cache_lifetime = 0;
    if(!_do_external_address_translation(ctx, _MESSAGE_TYPE_6TO4_ICMP_ERROR_PACKET, in_src_ipv6, in_dst_ipv6, out_src_ipv4, out_dst_ipv4, &cache_lifetime))
        return false;

    _save_6to4_addr_mapping_to_cache(
        ctx->external_addr_xlat_state->cache_6to4_icmp_error_packet,
        ctx->config->addressing_external_cache_size_icmp_error_addresses,
        in_src_ipv6, in_dst_ipv6, out_src_ipv4, out_dst_ipv4,
        (time_t) cache_lifetime
    );

    return true;
}

static bool _do_external_address_translation(tundra__thread_ctx *const ctx, const uint8_t message_type, const uint8_t *in_src_ip, const uint8_t *in_dst_ip, uint8_t *out_src_ip, uint8_t *out_dst_ip, uint8_t *out_cache_lifetime) {
    if(!_ensure_fds_are_open(ctx))
        return false;

    const uint32_t message_identifier = htonl(ctx->external_addr_xlat_state->message_identifier);
    ctx->external_addr_xlat_state->message_identifier++; // htonl() may be a macro

    tundra__external_addr_xlat_message message;

    if(!_construct_and_send_request_to_fd(ctx, &message, message_type, message_identifier, in_src_ip, in_dst_ip))
        return false;

    return _recv_and_parse_response_from_fd(ctx, &message, message_type, message_identifier, out_src_ip, out_dst_ip, out_cache_lifetime);
}

static bool _construct_and_send_request_to_fd(tundra__thread_ctx *const ctx, tundra__external_addr_xlat_message *message_buf, const uint8_t message_type, const uint32_t message_identifier, const uint8_t *in_src_ip, const uint8_t *in_dst_ip) {
    UTILS__MEM_ZERO_OUT(message_buf, sizeof(tundra__external_addr_xlat_message));  // Fields which are not further modified will be set to 0

    message_buf->magic_byte = _MESSAGE_MAGIC_BYTE;
    message_buf->version = _MESSAGE_VERSION;
    message_buf->message_type = message_type;
    message_buf->message_identifier = message_identifier;

    switch(message_type) {
        case _MESSAGE_TYPE_4TO6_MAIN_PACKET:  // The fall-through is intentional!
            if(
                utils_ip__is_ipv4_addr_unusable(in_src_ip) || UTILS_IP__IPV4_ADDR_EQ(in_src_ip, ctx->config->router_ipv4) ||
                utils_ip__is_ipv4_addr_unusable(in_dst_ip) || UTILS_IP__IPV4_ADDR_EQ(in_dst_ip, ctx->config->router_ipv4)
            ) return false;
            __attribute__((fallthrough));

        case _MESSAGE_TYPE_4TO6_ICMP_ERROR_PACKET:
            memcpy(message_buf->src_ip, in_src_ip, 4);
            memcpy(message_buf->dst_ip, in_dst_ip, 4);
            break;

        case _MESSAGE_TYPE_6TO4_MAIN_PACKET:  // The fall-through is intentional!
            if(
                utils_ip__is_ipv6_addr_unusable(in_src_ip) || UTILS_IP__IPV6_ADDR_EQ(in_src_ip, ctx->config->router_ipv6) ||
                utils_ip__is_ipv6_addr_unusable(in_dst_ip) || UTILS_IP__IPV6_ADDR_EQ(in_dst_ip, ctx->config->router_ipv6)
            ) return false;
            __attribute__((fallthrough));

        case _MESSAGE_TYPE_6TO4_ICMP_ERROR_PACKET:
            memcpy(message_buf->src_ip, in_src_ip, 16);
            memcpy(message_buf->dst_ip, in_dst_ip, 16);
            break;

        default:
            log__thread_crash_invalid_internal_state(ctx->thread_id, "Invalid message type");
    }

    return _send_message_to_fd(ctx, message_buf);
}

static bool _recv_and_parse_response_from_fd(tundra__thread_ctx *const ctx, tundra__external_addr_xlat_message *message_buf, const uint8_t message_type, const uint32_t message_identifier, uint8_t *out_src_ip, uint8_t *out_dst_ip, uint8_t *out_cache_lifetime) {
    /*
     * The protocol specification states that if a value of a field in certain types of messages is not explicitly
     * defined in it (e.g. what addresses should the IP address fields contain in case of an erroneous 'response'
     * message), the field must be zeroed out. However, this implementation does not check this requirement as of now,
     * since it does not need to (it does not access the fields in these "undefined" cases). This behaviour might,
     * however, change in a future version of this program, so it is not a good idea to rely on it.
     */

    if(!_recv_message_from_fd(ctx, message_buf))
        return false;

    if(message_buf->magic_byte != _MESSAGE_MAGIC_BYTE || message_buf->version != _MESSAGE_VERSION || message_buf->message_identifier != message_identifier) {
        _close_fds_if_necessary(ctx);
        return false;
    }

    if(message_buf->message_type == (message_type + 224)) {  // Bits set: response, error, ICMP
        switch(message_type) {
            case _MESSAGE_TYPE_4TO6_MAIN_PACKET:
                router_ipv4__send_dest_host_unreachable_to_in_ipv4_packet_src(ctx);
                return false;

            case _MESSAGE_TYPE_6TO4_MAIN_PACKET:
                router_ipv6__send_address_unreachable_to_in_ipv6_packet_src(ctx);
                return false;

            case _MESSAGE_TYPE_4TO6_ICMP_ERROR_PACKET:
            case _MESSAGE_TYPE_6TO4_ICMP_ERROR_PACKET:
                // These message types signify that the addresses of a partial packet inside an ICMP error message's
                //  body are being translated, and since ICMPv4 Destination Host Unreachable / ICMPv6 Address
                //  Unreachable signify that the main (outer) packet's addresses are those in error, it would be a
                //  mistake to send them in this case
                _close_fds_if_necessary(ctx);
                return false;

            default:
                log__thread_crash_invalid_internal_state(ctx->thread_id, "Invalid message type");
        }
    }

    if(message_buf->message_type == (message_type + 192)) {  // Bits set: response, error
        return false;
    }

    if(message_buf->message_type == (message_type + 128)) {  // Bits set: response
        switch(message_type) {
            case _MESSAGE_TYPE_4TO6_MAIN_PACKET:  // The fall-through is intentional!
                if(
                    utils_ip__is_ipv6_addr_unusable(message_buf->src_ip) || UTILS_IP__IPV6_ADDR_EQ(message_buf->src_ip, ctx->config->router_ipv6) ||
                    utils_ip__is_ipv6_addr_unusable(message_buf->dst_ip) || UTILS_IP__IPV6_ADDR_EQ(message_buf->dst_ip, ctx->config->router_ipv6)
                ) return false;
                __attribute__((fallthrough));

            case _MESSAGE_TYPE_4TO6_ICMP_ERROR_PACKET:
                memcpy(out_src_ip, message_buf->src_ip, 16);
                memcpy(out_dst_ip, message_buf->dst_ip, 16);
                break;

            case _MESSAGE_TYPE_6TO4_MAIN_PACKET:  // The fall-through is intentional!
                if(
                    utils_ip__is_ipv4_addr_unusable(message_buf->src_ip) || UTILS_IP__IPV4_ADDR_EQ(message_buf->src_ip, ctx->config->router_ipv4) ||
                    utils_ip__is_ipv4_addr_unusable(message_buf->dst_ip) || UTILS_IP__IPV4_ADDR_EQ(message_buf->dst_ip, ctx->config->router_ipv4)
                ) return false;
                __attribute__((fallthrough));

            case _MESSAGE_TYPE_6TO4_ICMP_ERROR_PACKET:
                if(!UTILS__MEM_EQ(((uint8_t *) message_buf->src_ip) + 4, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12) || !UTILS__MEM_EQ(((uint8_t *) message_buf->dst_ip) + 4, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12)) {
                    _close_fds_if_necessary(ctx);
                    return false;
                }
                memcpy(out_src_ip, message_buf->src_ip, 4);
                memcpy(out_dst_ip, message_buf->dst_ip, 4);
                break;

            default:
                log__thread_crash_invalid_internal_state(ctx->thread_id, "Invalid message type");
        }

        *out_cache_lifetime = message_buf->cache_lifetime;
        return true;
    }

    _close_fds_if_necessary(ctx);
    return false;
}

static bool _ensure_fds_are_open(tundra__thread_ctx *const ctx) {
    if(ctx->external_addr_xlat_state->read_fd >= 0 && ctx->external_addr_xlat_state->write_fd >= 0)
        return true;

    // Since at least one of the file descriptors is not open, it is necessary to acquire a pair of new ones (after any
    //  leftover file descriptors have been closed)
    _close_fds_if_necessary(ctx);

    switch(ctx->config->addressing_external_transport) {
        case TUNDRA__ADDRESSING_EXTERNAL_TRANSPORT_INHERITED_FDS:
            // If the inherited file descriptors fail, there is no way of obtaining new ones, and the only option is
            //  to crash the program
            log__thread_crash(ctx->thread_id, false, "At least one of the inherited file descriptors for the 'inherited-fds' transport of the 'external' addressing mode failed!");

        case TUNDRA__ADDRESSING_EXTERNAL_TRANSPORT_UNIX:
            {
                const int socket_fd = _open_socket(AF_UNIX, 0, (const struct sockaddr *) &ctx->config->addressing_external_unix_socket_info, (const socklen_t) sizeof(struct sockaddr_un), (const struct timeval *) &ctx->config->addressing_external_unix_tcp_timeout);
                if(socket_fd >= 0) {
                    ctx->external_addr_xlat_state->read_fd = ctx->external_addr_xlat_state->write_fd = socket_fd;
                    return true;
                }
            }
            break;

        case TUNDRA__ADDRESSING_EXTERNAL_TRANSPORT_TCP:
            for(struct addrinfo *current_addrinfo = ctx->config->addressing_external_tcp_socket_info; current_addrinfo != NULL; current_addrinfo = current_addrinfo->ai_next) {
                const int socket_fd = _open_socket(current_addrinfo->ai_family, IPPROTO_TCP, (const struct sockaddr *) current_addrinfo->ai_addr, (const socklen_t) current_addrinfo->ai_addrlen, (const struct timeval *) &ctx->config->addressing_external_unix_tcp_timeout);
                if(socket_fd >= 0) {
                    ctx->external_addr_xlat_state->read_fd = ctx->external_addr_xlat_state->write_fd = socket_fd;
                    return true;
                }
            }
            break;

        case TUNDRA__ADDRESSING_EXTERNAL_TRANSPORT_NONE:
        default:
            log__thread_crash_invalid_internal_state(ctx->thread_id, "Invalid addressing external transport");
    }

    return false;
}

static void _close_fds_if_necessary(tundra__thread_ctx *const ctx) {
    if(ctx->external_addr_xlat_state->read_fd >= 0)
        xlat_interrupt__close(ctx->external_addr_xlat_state->read_fd);

    if(ctx->external_addr_xlat_state->write_fd >= 0 && ctx->external_addr_xlat_state->write_fd != ctx->external_addr_xlat_state->read_fd)
        xlat_interrupt__close(ctx->external_addr_xlat_state->write_fd);

    ctx->external_addr_xlat_state->read_fd = ctx->external_addr_xlat_state->write_fd = -1;
}

static int _open_socket(const int family, const int protocol, const struct sockaddr *address, const socklen_t address_length, const struct timeval *timeout) {
    const int socket_fd = socket(family, SOCK_STREAM, protocol);
    if(socket_fd < 0)
        return -1;

    if(
        (xlat_interrupt__connect(socket_fd, address, address_length, true) < 0) ||
        (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, timeout, sizeof(struct timeval)) < 0) ||
        (setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, timeout, sizeof(struct timeval)) < 0)
    ) {
        xlat_interrupt__close(socket_fd);
        return -1;
    }

    return socket_fd;
}

static bool _recv_message_from_fd(tundra__thread_ctx *const ctx, tundra__external_addr_xlat_message *message_buf) {
    uint8_t *current_ptr = (uint8_t *) message_buf;
    ssize_t remaining_bytes = sizeof(tundra__external_addr_xlat_message);

    while(remaining_bytes > 0) {
        const ssize_t return_value = xlat_interrupt__read(ctx->external_addr_xlat_state->read_fd, current_ptr, (size_t) remaining_bytes);

        if(return_value < 1) {
            _close_fds_if_necessary(ctx);
            return false;
        }

        current_ptr += return_value;
        remaining_bytes -= return_value;
    }

    return true;
}

static bool _send_message_to_fd(tundra__thread_ctx *const ctx, const tundra__external_addr_xlat_message *message_buf) {
    const uint8_t *current_ptr = (const uint8_t *) message_buf;
    ssize_t remaining_bytes = sizeof(tundra__external_addr_xlat_message);

    while(remaining_bytes > 0) {
        const ssize_t return_value = xlat_interrupt__write(ctx->external_addr_xlat_state->write_fd, current_ptr, (size_t) remaining_bytes);

        if(return_value < 1) {
            _close_fds_if_necessary(ctx);
            return false;
        }

        current_ptr += return_value;
        remaining_bytes -= return_value;
    }

    return true;
}

static bool _try_doing_4to6_addr_translation_using_cache(const tundra__external_addr_xlat_cache_entry *cache, const size_t cache_size, const uint8_t *in_src_ipv4, const uint8_t *in_dst_ipv4, uint8_t *out_src_ipv6, uint8_t *out_dst_ipv6) {
    if(cache_size <= 0)
        return false;

    // The cache is a simple hash map
    const tundra__external_addr_xlat_cache_entry *target_entry = (cache + _get_hash_from_in_ipv4_addr_pair((const uint32_t *) in_src_ipv4, (const uint32_t *) in_dst_ipv4, cache_size));

    if(
        !UTILS_IP__IPV4_ADDR_EQ(in_src_ipv4, target_entry->src_ipv4) ||
        !UTILS_IP__IPV4_ADDR_EQ(in_dst_ipv4, target_entry->dst_ipv4) ||
        (target_entry->expiration_timestamp <= 0)  // '0' signifies that the cache entry is unused
    ) return false;

    const time_t current_timestamp = _get_current_timestamp();
    if(current_timestamp <= 0 || current_timestamp >= target_entry->expiration_timestamp)
        return false;

    memcpy(out_src_ipv6, target_entry->src_ipv6, 16);
    memcpy(out_dst_ipv6, target_entry->dst_ipv6, 16);

    return true;
}

static bool _try_doing_6to4_addr_translation_using_cache(const tundra__external_addr_xlat_cache_entry *cache, const size_t cache_size, const uint8_t *in_src_ipv6, const uint8_t *in_dst_ipv6, uint8_t *out_src_ipv4, uint8_t *out_dst_ipv4) {
    if(cache_size <= 0)
        return false;

    // The cache is a simple hash map
    const tundra__external_addr_xlat_cache_entry *target_entry = (cache + _get_hash_from_in_ipv6_addr_pair((const uint64_t *) in_src_ipv6, (const uint64_t *) in_dst_ipv6, cache_size));

    if(
        !UTILS_IP__IPV6_ADDR_EQ(in_src_ipv6, target_entry->src_ipv6) ||
        !UTILS_IP__IPV6_ADDR_EQ(in_dst_ipv6, target_entry->dst_ipv6) ||
        (target_entry->expiration_timestamp <= 0)  // '0' signifies that the cache entry is unused
    ) return false;

    const time_t current_timestamp = _get_current_timestamp();
    if(current_timestamp <= 0 || current_timestamp >= target_entry->expiration_timestamp)
        return false;

    memcpy(out_src_ipv4, target_entry->src_ipv4, 4);
    memcpy(out_dst_ipv4, target_entry->dst_ipv4, 4);

    return true;
}

static void _save_4to6_addr_mapping_to_cache(tundra__external_addr_xlat_cache_entry *cache, const size_t cache_size, const uint8_t *in_src_ipv4, const uint8_t *in_dst_ipv4, const uint8_t *out_src_ipv6, const uint8_t *out_dst_ipv6, const time_t cache_lifetime) {
    if(cache_size <= 0)
        return;

    // The cache is a simple hash map
    tundra__external_addr_xlat_cache_entry *target_entry = (cache + _get_hash_from_in_ipv4_addr_pair((const uint32_t *) in_src_ipv4, (const uint32_t *) in_dst_ipv4, cache_size));

    _save_addr_mapping_to_target_cache_entry(target_entry, in_src_ipv4, in_dst_ipv4, out_src_ipv6, out_dst_ipv6, cache_lifetime);
}

static void _save_6to4_addr_mapping_to_cache(tundra__external_addr_xlat_cache_entry *cache, const size_t cache_size, const uint8_t *in_src_ipv6, const uint8_t *in_dst_ipv6, const uint8_t *out_src_ipv4, const uint8_t *out_dst_ipv4, const time_t cache_lifetime) {
    if(cache_size <= 0)
        return;

    // The cache is a simple hash map
    tundra__external_addr_xlat_cache_entry *target_entry = (cache + _get_hash_from_in_ipv6_addr_pair((const uint64_t *) in_src_ipv6, (const uint64_t *) in_dst_ipv6, cache_size));

    _save_addr_mapping_to_target_cache_entry(target_entry, out_src_ipv4, out_dst_ipv4, in_src_ipv6, in_dst_ipv6, cache_lifetime);
}

static void _save_addr_mapping_to_target_cache_entry(tundra__external_addr_xlat_cache_entry *target_entry, const uint8_t *src_ipv4, const uint8_t *dst_ipv4, const uint8_t *src_ipv6, const uint8_t *dst_ipv6, const time_t cache_lifetime) {
    if(cache_lifetime == 0)  // '0' means "do not cache"
        return;

    const time_t current_timestamp = _get_current_timestamp();
    if(current_timestamp <= 0)
        return;

    // This may overwrite an existing cache entry
    target_entry->expiration_timestamp = (current_timestamp + cache_lifetime);
    memcpy(target_entry->src_ipv4, src_ipv4, 4);
    memcpy(target_entry->dst_ipv4, dst_ipv4, 4);
    memcpy(target_entry->src_ipv6, src_ipv6, 16);
    memcpy(target_entry->dst_ipv6, dst_ipv6, 16);
}

static inline size_t _get_hash_from_in_ipv4_addr_pair(const uint32_t *in_src_ipv4, const uint32_t *in_dst_ipv4, const size_t cache_size) {
    return (((size_t) ((*in_src_ipv4) + (*in_dst_ipv4))) % cache_size);
}

static inline size_t _get_hash_from_in_ipv6_addr_pair(const uint64_t *in_src_ipv6, const uint64_t *in_dst_ipv6, const size_t cache_size) {
    return (((size_t) (in_src_ipv6[0] + in_src_ipv6[1] + in_dst_ipv6[0] + in_dst_ipv6[1])) % cache_size);
}

static inline time_t _get_current_timestamp(void) {
    struct timespec time_specification;
    UTILS__MEM_ZERO_OUT(&time_specification, sizeof(struct timespec));

    if(clock_gettime(CLOCK_MONOTONIC_RAW, &time_specification) < 0)
        return 0;

    return time_specification.tv_sec;
}


#undef _MESSAGE_MAGIC_BYTE
#undef _MESSAGE_VERSION

#undef _MESSAGE_TYPE_4TO6_MAIN_PACKET
#undef _MESSAGE_TYPE_4TO6_ICMP_ERROR_PACKET
#undef _MESSAGE_TYPE_6TO4_MAIN_PACKET
#undef _MESSAGE_TYPE_6TO4_ICMP_ERROR_PACKET
