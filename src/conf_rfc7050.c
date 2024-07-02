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
#include"conf_rfc7050.h"

#include"utils.h"
#include"utils_ip.h"
#include"log.h"


#define _IPV4ONLY_DNS_NAME "ipv4only.arpa."
#define _TARGET_IPV4_1 "\xc0\x00\x00\xaa" // 192.0.0.170
#define _TARGET_IPV4_2 "\xc0\x00\x00\xab" // 192.0.0.171
#define _RETRY_INTERVAL_SECONDS ((unsigned int) 3)
#define _LOG_MESSAGE_BANNER "RFC 7050"


static void _print_start_info_message(void);
static void _print_finish_info_message(const uint8_t *found_ipv6_prefix);


void conf_rfc7050__autodiscover_ipv6_prefix(uint8_t *destination) {
    struct addrinfo hints;
    UTILS__MEM_ZERO_OUT(&hints, sizeof(struct addrinfo));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;

    _print_start_info_message();

    for(;;) {
        struct addrinfo *results;
        if(getaddrinfo(_IPV4ONLY_DNS_NAME, NULL, (const struct addrinfo *) &hints, &results) != 0) {
            sleep(_RETRY_INTERVAL_SECONDS);
            continue;
        }

        for(struct addrinfo *current_result = results; current_result != NULL; current_result = current_result->ai_next) {
            if(current_result->ai_family != AF_INET6 || current_result->ai_addrlen != sizeof(struct sockaddr_in6) || current_result->ai_addr->sa_family != AF_INET6)
                continue;

            const struct sockaddr_in6 *addr_struct = (const struct sockaddr_in6 *) (current_result->ai_addr);
            const uint8_t *ipv6_address = (const uint8_t *) (addr_struct->sin6_addr.s6_addr);
            if(UTILS_IP__IPV4_ADDR_EQ(ipv6_address + 12, _TARGET_IPV4_1) || UTILS_IP__IPV4_ADDR_EQ(ipv6_address + 12, _TARGET_IPV4_2)) {
                memcpy(destination, ipv6_address, 12);
                UTILS__MEM_ZERO_OUT(destination + 12, 4);

                freeaddrinfo(results);
                _print_finish_info_message(destination);

                return;
            }
        }

        freeaddrinfo(results);
        sleep(_RETRY_INTERVAL_SECONDS);
    }
}

static void _print_start_info_message(void) {
    // For future extension and code consistency.
    log__info("["_LOG_MESSAGE_BANNER"] Trying to auto-discover a translation prefix - waiting until a DNS query for '"_IPV4ONLY_DNS_NAME"' returns a sensible result...");
}

static void _print_finish_info_message(const uint8_t *found_ipv6_prefix) {
    struct in6_addr address_struct;
    UTILS__MEM_ZERO_OUT(&address_struct, sizeof(struct in6_addr));
    memcpy(address_struct.s6_addr, found_ipv6_prefix, 16);

    char found_ipv6_prefix_string[INET6_ADDRSTRLEN] = {'\0'};
    if(inet_ntop(AF_INET6, &address_struct, found_ipv6_prefix_string, INET6_ADDRSTRLEN) == NULL)
        log__crash(true, "["_LOG_MESSAGE_BANNER"] Failed to convert the auto-discovered translation prefix from binary to string form!");

    log__info("["_LOG_MESSAGE_BANNER"] The translation prefix '%s/96' has been auto-discovered!", found_ipv6_prefix_string);
}


#undef _IPV4ONLY_DNS_NAME
#undef _TARGET_IPV4_1
#undef _TARGET_IPV4_2
#undef _RETRY_INTERVAL_SECONDS
#undef _LOG_MESSAGE_BANNER
