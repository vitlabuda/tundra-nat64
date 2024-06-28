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
#include"t64_conf_rfc7050.h"

#include"t64_utils.h"
#include"t64_utils_ip.h"
#include"t64_log.h"


#define _T64C_CONF_RFC7050__DNS_NAME "ipv4only.arpa."
#define _T64C_CONF_RFC7050__TARGET_IPV4_1 "\xc0\x00\x00\xaa" // 192.0.0.170
#define _T64C_CONF_RFC7050__TARGET_IPV4_2 "\xc0\x00\x00\xab" // 192.0.0.171
#define _T64C_CONF_RFC7050__RETRY_INTERVAL_SECONDS ((unsigned int) 3)


static void _t64f_conf_rfc7050__print_info_log_message_on_start(void);
static void _t64f_conf_rfc7050__print_info_log_message_on_finish(const uint8_t *found_ipv6_prefix);


void t64f_conf_rfc7050__autodiscover_addressing_prefix_using_ipv4only_arpa(uint8_t *destination) {
    struct addrinfo hints;
    T64M_UTILS__MEMORY_ZERO_OUT(&hints, sizeof(struct addrinfo));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;

    _t64f_conf_rfc7050__print_info_log_message_on_start();

    for(;;) {
        struct addrinfo *results;
        if(getaddrinfo(_T64C_CONF_RFC7050__DNS_NAME, NULL, (const struct addrinfo *) &hints, &results) != 0) {
            sleep(_T64C_CONF_RFC7050__RETRY_INTERVAL_SECONDS);
            continue;
        }

        for(struct addrinfo *current_result = results; current_result != NULL; current_result = current_result->ai_next) {
            if(current_result->ai_family != AF_INET6 || current_result->ai_addrlen != sizeof(struct sockaddr_in6) || current_result->ai_addr->sa_family != AF_INET6)
                continue;

            const uint8_t *ipv6_address = (const uint8_t *) (((struct sockaddr_in6 *) current_result->ai_addr)->sin6_addr.s6_addr);
            if(T64M_UTILS_IP__IPV4_ADDRESSES_EQUAL(ipv6_address + 12, _T64C_CONF_RFC7050__TARGET_IPV4_1) || T64M_UTILS_IP__IPV4_ADDRESSES_EQUAL(ipv6_address + 12, _T64C_CONF_RFC7050__TARGET_IPV4_2)) {
                memcpy(destination, ipv6_address, 12);
                T64M_UTILS__MEMORY_ZERO_OUT(destination + 12, 4);
                freeaddrinfo(results);
                _t64f_conf_rfc7050__print_info_log_message_on_finish(destination);
                return;
            }
        }

        freeaddrinfo(results);
        sleep(_T64C_CONF_RFC7050__RETRY_INTERVAL_SECONDS);
    }
}

static void _t64f_conf_rfc7050__print_info_log_message_on_start(void) {
    // For future extension.
    t64f_log__info("[RFC 7050] Trying to auto-discover a translation prefix - waiting until a DNS query for '"_T64C_CONF_RFC7050__DNS_NAME"' returns a sensible result...");
}

static void _t64f_conf_rfc7050__print_info_log_message_on_finish(const uint8_t *found_ipv6_prefix) {
    struct in6_addr address_struct;
    T64M_UTILS__MEMORY_ZERO_OUT(&address_struct, sizeof(struct in6_addr));
    memcpy(address_struct.s6_addr, found_ipv6_prefix, 16);

    char found_ipv6_prefix_string[INET6_ADDRSTRLEN] = {'\0'};
    if(inet_ntop(AF_INET6, &address_struct, found_ipv6_prefix_string, INET6_ADDRSTRLEN) == NULL)
        t64f_log__crash(true, "[RFC 7050] Failed to convert the auto-discovered translation prefix from binary to string form!");

    t64f_log__info("[RFC 7050] The translation prefix '%s/96' has been auto-discovered!", found_ipv6_prefix_string);
}


#undef _T64C_CONF_RFC7050__DNS_NAME
#undef _T64C_CONF_RFC7050__TARGET_IPV4_1
#undef _T64C_CONF_RFC7050__TARGET_IPV4_2
#undef _T64C_CONF_RFC7050__RETRY_INTERVAL_SECONDS
