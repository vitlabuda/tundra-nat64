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
#include"conf_file.h"

#include"utils.h"
#include"utils_ip.h"
#include"log.h"
#include"conf_file_load.h"
#include"conf_rfc7050.h"


static tundra__conf_file *_parse_config_file(conf_file_load__conf_entry **entries);
static void _parse_program_config(conf_file_load__conf_entry **entries, tundra__conf_file *const file_config);
static void _parse_io_config(conf_file_load__conf_entry **entries, tundra__conf_file *const file_config);
static void _parse_io_tun_config(conf_file_load__conf_entry **entries, tundra__conf_file *const file_config);
static void _parse_router_config(conf_file_load__conf_entry **entries, tundra__conf_file *const file_config);
static void _parse_addressing_config(conf_file_load__conf_entry **entries, tundra__conf_file *const file_config);
static void _parse_addressing_nat64_clat_config(conf_file_load__conf_entry **entries, tundra__conf_file *const file_config);
static void _parse_addressing_nat64_clat_siit_config(conf_file_load__conf_entry **entries, tundra__conf_file *const file_config);
static void _parse_addressing_external_config(conf_file_load__conf_entry **entries, tundra__conf_file *const file_config);
static void _parse_addressing_external_unix_config(conf_file_load__conf_entry **entries, tundra__conf_file *const file_config);
static void _parse_addressing_external_tcp_config(conf_file_load__conf_entry **entries, tundra__conf_file *const file_config);
static void _parse_addressing_external_unix_tcp_config(conf_file_load__conf_entry **entries, tundra__conf_file *const file_config);
static void _parse_translator_config(conf_file_load__conf_entry **entries, tundra__conf_file *const file_config);
static uid_t _get_uid_by_username(const char *const username);
static gid_t _get_gid_by_groupname(const char *const groupname);
static tundra__io_mode _get_io_mode_from_string(const char *const io_mode_string);
static tundra__addressing_mode _get_addressing_mode_from_string(const char *const addressing_mode_string);
static tundra__addressing_external_transport _get_addressing_external_transport_from_string(const char *const addressing_external_transport_string);
static uint64_t _get_fallback_translator_threads(void);


tundra__conf_file *conf_file__read_and_parse_config_file(const char *const filepath) {
    conf_file_load__conf_entry **entries = conf_file_load__read_config_file(filepath);

    tundra__conf_file *const file_config = _parse_config_file(entries);

    conf_file_load__free_config_file(entries);

    return file_config;
}

static tundra__conf_file *_parse_config_file(conf_file_load__conf_entry **entries) {
    tundra__conf_file *const file_config = utils__alloc_zeroed_out_memory(1, sizeof(tundra__conf_file));

    _parse_program_config(entries, file_config);
    _parse_io_config(entries, file_config);
    _parse_router_config(entries, file_config);
    _parse_addressing_config(entries, file_config);
    _parse_translator_config(entries, file_config);

    return file_config;
}

static void _parse_program_config(conf_file_load__conf_entry **entries, tundra__conf_file *const file_config) {
    // --- program.translator_threads ---
    file_config->program_translator_threads = (size_t) conf_file_load__find_integer(
        entries, "program.translator_threads", 1, TUNDRA__MAX_XLAT_THREADS, &_get_fallback_translator_threads
    );

    // --- program.privilege_drop_user ---
    {
        const char *const username = conf_file_load__find_string(
            entries, "program.privilege_drop_user", CONF_FILE_LOAD__FIND_STRING_NO_MAX_CHARS, false
        );
        if(UTILS__STR_EMPTY(username)) {
            file_config->program_privilege_drop_user_perform = false;
            file_config->program_privilege_drop_user_uid = 0; // Not used
        } else {
            file_config->program_privilege_drop_user_perform = true;
            file_config->program_privilege_drop_user_uid = _get_uid_by_username(username);
        }
    }

    // --- program.privilege_drop_group ---
    {
        const char *const groupname = conf_file_load__find_string(
            entries, "program.privilege_drop_group", CONF_FILE_LOAD__FIND_STRING_NO_MAX_CHARS, false
        );
        if(UTILS__STR_EMPTY(groupname)) {
            file_config->program_privilege_drop_group_perform = false;
            file_config->program_privilege_drop_group_gid = 0; // Not used
        } else {
            file_config->program_privilege_drop_group_perform = true;
            file_config->program_privilege_drop_group_gid = _get_gid_by_groupname(groupname);
        }
    }
}

static void _parse_io_config(conf_file_load__conf_entry **entries, tundra__conf_file *const file_config) {
    // --- io.mode ---
    file_config->io_mode = _get_io_mode_from_string(
        conf_file_load__find_string(entries, "io.mode", CONF_FILE_LOAD__FIND_STRING_NO_MAX_CHARS, false)
    );

    if(file_config->io_mode == TUNDRA__IO_MODE_TUN) {
        _parse_io_tun_config(entries, file_config);
    } else {
        file_config->io_tun_device_path = NULL; // Not used
        file_config->io_tun_interface_name = NULL; // Not used
        file_config->io_tun_owner_user_set = false; // Not used
        file_config->io_tun_owner_user_uid = 0; // Not used
        file_config->io_tun_owner_group_set = false; // Not used
        file_config->io_tun_owner_group_gid = 0; // Not used
        file_config->io_tun_multi_queue = false; // Not used
    }
}

static void _parse_io_tun_config(conf_file_load__conf_entry **entries, tundra__conf_file *const file_config) {
    // --- io.tun.device_path ---
    {
        const char *const tun_device_path = conf_file_load__find_string(entries, "io.tun.device_path", PATH_MAX - 1, false);
        file_config->io_tun_device_path = utils__duplicate_string(
            (UTILS__STR_EMPTY(tun_device_path)) ? TUNDRA__DEFAULT_TUN_DEVICE_PATH : tun_device_path
        );
    }

    // --- io.tun.interface_name ---
    file_config->io_tun_interface_name = utils__duplicate_string(
        conf_file_load__find_string(entries, "io.tun.interface_name", IFNAMSIZ - 1, true)
    );

    // --- io.tun.owner_user ---
    {
        const char *const owner_username = conf_file_load__find_string(
            entries, "io.tun.owner_user", CONF_FILE_LOAD__FIND_STRING_NO_MAX_CHARS, false
        );
        if(UTILS__STR_EMPTY(owner_username)) {
            file_config->io_tun_owner_user_set = false;
            file_config->io_tun_owner_user_uid = 0; // Not used
        } else {
            file_config->io_tun_owner_user_set = true;
            file_config->io_tun_owner_user_uid = _get_uid_by_username(owner_username);
        }
    }

    // --- io.tun.owner_group ---
    {
        const char *const owner_groupname = conf_file_load__find_string(
            entries, "io.tun.owner_group", CONF_FILE_LOAD__FIND_STRING_NO_MAX_CHARS, false
        );
        if(UTILS__STR_EMPTY(owner_groupname)) {
            file_config->io_tun_owner_group_set = false;
            file_config->io_tun_owner_group_gid = 0; // Not used
        } else {
            file_config->io_tun_owner_group_set = true;
            file_config->io_tun_owner_group_gid = _get_gid_by_groupname(owner_groupname);
        }
    }

    // --- io.tun.multi_queue ---
    file_config->io_tun_multi_queue = conf_file_load__find_boolean(entries, "io.tun.multi_queue", NULL);
}

static void _parse_router_config(conf_file_load__conf_entry **entries, tundra__conf_file *const file_config) {
    // --- router.ipv4 ---
    conf_file_load__find_ipv4_address(entries, "router.ipv4", file_config->router_ipv4, NULL);

    // --- router.ipv6 ---
    conf_file_load__find_ipv6_address(entries, "router.ipv6", file_config->router_ipv6, NULL);

    // --- router.generated_packet_ttl ---
    file_config->router_generated_packet_ttl = (uint8_t) conf_file_load__find_integer(
        entries, "router.generated_packet_ttl", TUNDRA__MIN_GENERATED_PACKET_TTL, TUNDRA__MAX_GENERATED_PACKET_TTL, NULL
    );
}

static void _parse_addressing_config(conf_file_load__conf_entry **entries, tundra__conf_file *const file_config) {
    // --- addressing.mode ---
    file_config->addressing_mode = _get_addressing_mode_from_string(
        conf_file_load__find_string(entries, "addressing.mode", CONF_FILE_LOAD__FIND_STRING_NO_MAX_CHARS, false)
    );

    _parse_addressing_nat64_clat_config(entries, file_config);
    _parse_addressing_nat64_clat_siit_config(entries, file_config);
    _parse_addressing_external_config(entries, file_config);
    _parse_addressing_external_unix_config(entries, file_config);
    _parse_addressing_external_tcp_config(entries, file_config);
    _parse_addressing_external_unix_tcp_config(entries, file_config);
}

static void _parse_addressing_nat64_clat_config(conf_file_load__conf_entry **entries, tundra__conf_file *const file_config) {
    if(file_config->addressing_mode == TUNDRA__ADDRESSING_MODE_NAT64 || file_config->addressing_mode == TUNDRA__ADDRESSING_MODE_CLAT) {
        // --- addressing.nat64_clat.ipv4 ---
        conf_file_load__find_ipv4_address(entries, "addressing.nat64_clat.ipv4", file_config->addressing_nat64_clat_ipv4, NULL);
        if(UTILS_IP__IPV4_ADDR_EQ(file_config->addressing_nat64_clat_ipv4, file_config->router_ipv4))
            log__crash(false, "'addressing.nat64_clat.ipv4' must not be the same as 'router.ipv4'!");

        // --- addressing.nat64_clat.ipv6 ---
        conf_file_load__find_ipv6_address(entries, "addressing.nat64_clat.ipv6", file_config->addressing_nat64_clat_ipv6, NULL);
        if(UTILS_IP__IPV6_ADDR_EQ(file_config->addressing_nat64_clat_ipv6, file_config->router_ipv6))
            log__crash(false, "'addressing.nat64_clat.ipv6' must not be the same as 'router.ipv6'!");

    } else {
        UTILS__MEM_ZERO_OUT(file_config->addressing_nat64_clat_ipv4, 4);
        UTILS__MEM_ZERO_OUT(file_config->addressing_nat64_clat_ipv6, 16);
    }
}

static void _parse_addressing_nat64_clat_siit_config(conf_file_load__conf_entry **entries, tundra__conf_file *const file_config) {
    if(file_config->addressing_mode == TUNDRA__ADDRESSING_MODE_NAT64 || file_config->addressing_mode == TUNDRA__ADDRESSING_MODE_CLAT || file_config->addressing_mode == TUNDRA__ADDRESSING_MODE_SIIT) {
        // --- addressing.nat64_clat_siit.prefix ---
        conf_file_load__find_ipv6_prefix(
            entries, "addressing.nat64_clat_siit.prefix", file_config->addressing_nat64_clat_siit_prefix, &conf_rfc7050__autodiscover_ipv6_prefix
        );

        // --- addressing.nat64_clat_siit.allow_translation_of_private_ips ---
        file_config->addressing_nat64_clat_siit_allow_translation_of_private_ips = conf_file_load__find_boolean(
            entries, "addressing.nat64_clat_siit.allow_translation_of_private_ips", NULL
        );
    } else {
        UTILS__MEM_ZERO_OUT(file_config->addressing_nat64_clat_siit_prefix, 16);
        file_config->addressing_nat64_clat_siit_allow_translation_of_private_ips = false;
    }
}

static void _parse_addressing_external_config(conf_file_load__conf_entry **entries, tundra__conf_file *const file_config) {
    if(file_config->addressing_mode == TUNDRA__ADDRESSING_MODE_EXTERNAL) {
        // --- addressing.external.transport ---
        file_config->addressing_external_transport = _get_addressing_external_transport_from_string(
            conf_file_load__find_string(entries, "addressing.external.transport", CONF_FILE_LOAD__FIND_STRING_NO_MAX_CHARS, false)
        );

        // --- addressing.external.cache_size.main_addresses ---
        file_config->addressing_external_cache_size_main_addresses = (size_t) conf_file_load__find_integer(
            entries, "addressing.external.cache_size.main_addresses", 0, TUNDRA__MAX_ADDRESSING_EXTERNAL_CACHE_SIZE, NULL
        );

        // --- addressing.external.cache_size.icmp_error_addresses ---
        file_config->addressing_external_cache_size_icmp_error_addresses = (size_t) conf_file_load__find_integer(
            entries, "addressing.external.cache_size.icmp_error_addresses", 0, TUNDRA__MAX_ADDRESSING_EXTERNAL_CACHE_SIZE, NULL
        );
    } else {
        file_config->addressing_external_transport = TUNDRA__ADDRESSING_EXTERNAL_TRANSPORT_NONE;
        file_config->addressing_external_cache_size_main_addresses = 0;
        file_config->addressing_external_cache_size_icmp_error_addresses = 0;
    }
}

static void _parse_addressing_external_unix_config(conf_file_load__conf_entry **entries, tundra__conf_file *const file_config) {
    UTILS__MEM_ZERO_OUT(&file_config->addressing_external_unix_socket_info, sizeof(struct sockaddr_un));

    if(file_config->addressing_mode == TUNDRA__ADDRESSING_MODE_EXTERNAL && file_config->addressing_external_transport == TUNDRA__ADDRESSING_EXTERNAL_TRANSPORT_UNIX) {
        // --- addressing.external.unix.path ---
        file_config->addressing_external_unix_socket_info.sun_family = AF_UNIX;
        strcpy(
            file_config->addressing_external_unix_socket_info.sun_path,
            conf_file_load__find_string(entries, "addressing.external.unix.path", sizeof(file_config->addressing_external_unix_socket_info.sun_path) - 1, true)
        );
    }
}

static void _parse_addressing_external_tcp_config(conf_file_load__conf_entry **entries, tundra__conf_file *const file_config) {
    if(file_config->addressing_mode == TUNDRA__ADDRESSING_MODE_EXTERNAL && file_config->addressing_external_transport == TUNDRA__ADDRESSING_EXTERNAL_TRANSPORT_TCP) {
        // --- addressing.external.tcp.host ---
        const char *const host = conf_file_load__find_string(
            entries, "addressing.external.tcp.host", CONF_FILE_LOAD__FIND_STRING_NO_MAX_CHARS, true
        );

        // --- addressing.external.tcp.port ---
        const char *const port = conf_file_load__find_string(
            entries, "addressing.external.tcp.port", CONF_FILE_LOAD__FIND_STRING_NO_MAX_CHARS, true
        );

        struct addrinfo hints;
        UTILS__MEM_ZERO_OUT(&hints, sizeof(struct addrinfo));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        const int gai_return_value = getaddrinfo(host, port, (const struct addrinfo *) &hints, &file_config->addressing_external_tcp_socket_info);
        if(gai_return_value != 0)
            log__crash(false, "Failed to resolve the external TCP host ('%s') or port ('%s') using getaddrinfo(): %s", host, port, gai_strerror(gai_return_value));

        if(file_config->addressing_external_tcp_socket_info == NULL)
            log__crash(false, "Even though getaddrinfo() was successful, it saved NULL into the \"result\" variable!");

    } else {
        file_config->addressing_external_tcp_socket_info = NULL;
    }
}

static void _parse_addressing_external_unix_tcp_config(conf_file_load__conf_entry **entries, tundra__conf_file *const file_config) {
    UTILS__MEM_ZERO_OUT(&file_config->addressing_external_unix_tcp_timeout, sizeof(struct timeval));

    if(file_config->addressing_mode == TUNDRA__ADDRESSING_MODE_EXTERNAL && (file_config->addressing_external_transport == TUNDRA__ADDRESSING_EXTERNAL_TRANSPORT_UNIX || file_config->addressing_external_transport == TUNDRA__ADDRESSING_EXTERNAL_TRANSPORT_TCP)) {
        // --- addressing.external.unix_tcp.timeout_milliseconds ---
        uint64_t timeout_milliseconds = conf_file_load__find_integer(
            entries, "addressing.external.unix_tcp.timeout_milliseconds", TUNDRA__MIN_TIMEOUT_MILLISECONDS, TUNDRA__MAX_TIMEOUT_MILLISECONDS, NULL
        );

        file_config->addressing_external_unix_tcp_timeout.tv_sec = (time_t) (timeout_milliseconds / 1000);
        file_config->addressing_external_unix_tcp_timeout.tv_usec = (suseconds_t) ((timeout_milliseconds % 1000) * 1000);
    }
}

static void _parse_translator_config(conf_file_load__conf_entry **entries, tundra__conf_file *const file_config) {
    // --- translator.ipv4.outbound_mtu ---
    file_config->translator_ipv4_outbound_mtu = (size_t) conf_file_load__find_integer(entries, "translator.ipv4.outbound_mtu", TUNDRA__MIN_MTU_IPV4, TUNDRA__MAX_MTU_IPV4, NULL);

    // --- translator.ipv6.outbound_mtu ---
    file_config->translator_ipv6_outbound_mtu = (size_t) conf_file_load__find_integer(entries, "translator.ipv6.outbound_mtu", TUNDRA__MIN_MTU_IPV6, TUNDRA__MAX_MTU_IPV6, NULL);


    // --- translator.6to4.copy_dscp_and_ecn ---
    file_config->translator_6to4_copy_dscp_and_ecn = conf_file_load__find_boolean(entries, "translator.6to4.copy_dscp_and_ecn", NULL);

    // --- translator.4to6.copy_dscp_and_ecn ---
    file_config->translator_4to6_copy_dscp_and_ecn = conf_file_load__find_boolean(entries, "translator.4to6.copy_dscp_and_ecn", NULL);
}

static uid_t _get_uid_by_username(const char *const username) {
    struct passwd *passwd_entry = getpwnam(username);
    if(passwd_entry == NULL)
        log__crash(false, "A user named '%s' could not be found!", username);

    return passwd_entry->pw_uid;
}

static gid_t _get_gid_by_groupname(const char *const groupname) {
    struct group *group_entry = getgrnam(groupname);
    if(group_entry == NULL)
        log__crash(false, "A group named '%s' could not be found!", groupname);

    return group_entry->gr_gid;
}

static tundra__io_mode _get_io_mode_from_string(const char *const io_mode_string) {
    if(UTILS__STR_EQ(io_mode_string, "inherited-fds"))
        return TUNDRA__IO_MODE_INHERITED_FDS;

    if(UTILS__STR_EQ(io_mode_string, "tun"))
        return TUNDRA__IO_MODE_TUN;

    log__crash(false, "Invalid I/O mode string: '%s'", io_mode_string);
}

static tundra__addressing_mode _get_addressing_mode_from_string(const char *const addressing_mode_string) {
    if(UTILS__STR_EQ(addressing_mode_string, "nat64"))
        return TUNDRA__ADDRESSING_MODE_NAT64;

    if(UTILS__STR_EQ(addressing_mode_string, "clat"))
        return TUNDRA__ADDRESSING_MODE_CLAT;

    if(UTILS__STR_EQ(addressing_mode_string, "siit"))
        return TUNDRA__ADDRESSING_MODE_SIIT;

    if(UTILS__STR_EQ(addressing_mode_string, "external"))
        return TUNDRA__ADDRESSING_MODE_EXTERNAL;

    log__crash(false, "Invalid addressing mode string: '%s'", addressing_mode_string);
}

static tundra__addressing_external_transport _get_addressing_external_transport_from_string(const char *const addressing_external_transport_string) {
    if(UTILS__STR_EQ(addressing_external_transport_string, "inherited-fds"))
        return TUNDRA__ADDRESSING_EXTERNAL_TRANSPORT_INHERITED_FDS;

    if(UTILS__STR_EQ(addressing_external_transport_string, "unix"))
        return TUNDRA__ADDRESSING_EXTERNAL_TRANSPORT_UNIX;

    if(UTILS__STR_EQ(addressing_external_transport_string, "tcp"))
        return TUNDRA__ADDRESSING_EXTERNAL_TRANSPORT_TCP;

    log__crash(false, "Invalid addressing external transport string: '%s'", addressing_external_transport_string);
}

static uint64_t _get_fallback_translator_threads(void) {
    return (uint64_t) get_nprocs();  // Cannot fail
}

void conf_file__free_parsed_config_file(tundra__conf_file *const file_config) {
    if(file_config->io_tun_device_path != NULL)
        utils__free_memory(file_config->io_tun_device_path);

    if(file_config->io_tun_interface_name != NULL)
        utils__free_memory(file_config->io_tun_interface_name);

    if(file_config->addressing_external_tcp_socket_info != NULL)
        freeaddrinfo(file_config->addressing_external_tcp_socket_info);

    utils__free_memory(file_config);
}
