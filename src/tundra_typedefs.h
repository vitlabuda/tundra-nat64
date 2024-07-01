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

#pragma once



// ---------------------------------------------------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------------------------------------------------

typedef enum tundra__operation_mode {
    TUNDRA__OPERATION_MODE_TRANSLATE,
    TUNDRA__OPERATION_MODE_MKTUN,
    TUNDRA__OPERATION_MODE_RMTUN,
    TUNDRA__OPERATION_MODE_VALIDATE_CONFIG
} tundra__operation_mode;

typedef enum tundra__io_mode {
    TUNDRA__IO_MODE_INHERITED_FDS,
    TUNDRA__IO_MODE_TUN
} tundra__io_mode;

typedef enum tundra__addressing_mode {
    TUNDRA__ADDRESSING_MODE_NAT64,
    TUNDRA__ADDRESSING_MODE_CLAT,
    TUNDRA__ADDRESSING_MODE_SIIT,
    TUNDRA__ADDRESSING_MODE_EXTERNAL
} tundra__addressing_mode;

typedef enum tundra__addressing_external_transport {
    TUNDRA__ADDRESSING_EXTERNAL_TRANSPORT_NONE,
    TUNDRA__ADDRESSING_EXTERNAL_TRANSPORT_INHERITED_FDS,
    TUNDRA__ADDRESSING_EXTERNAL_TRANSPORT_UNIX,
    TUNDRA__ADDRESSING_EXTERNAL_TRANSPORT_TCP
} tundra__addressing_external_transport;

typedef struct tundra__conf_cmdline {
    char *config_file_path; // Cannot be NULL - contains either command-line-provided filepath, or TUNDRA__DEFAULT_CONFIG_FILE_PATH
    char *io_inherited_fds; // NULL if no 'io-inherited-fds' are specified via command-line options
    char *addressing_external_inherited_fds;  // NULL if no 'addressing-external-inherited-fds' are specified via command-line options
    tundra__operation_mode mode_of_operation;
} tundra__conf_cmdline;

typedef struct tundra__conf_file {
    // The items are ordered in a way to reduce struct padding as much as possible, which is the reason why they seem to be in a "somewhat random order".
    struct sockaddr_un addressing_external_unix_socket_info;
    uint8_t addressing_nat64_clat_siit_prefix[16];
    uint8_t addressing_nat64_clat_ipv6[16];
    uint8_t router_ipv6[16];
    struct timeval addressing_external_unix_tcp_timeout;
    char *io_tun_device_path; // NULL if io_mode != TUN; Cannot be empty - contains either the config-file-provided TUN device path, or TUNDRA__DEFAULT_TUN_DEVICE_PATH
    char *io_tun_interface_name; // NULL if io_mode != TUN; Cannot be empty
    struct addrinfo *addressing_external_tcp_socket_info; // Not NULL if addressing_mode == EXTERNAL && addressing_external_transport == TCP
    size_t program_translator_threads; // Between 1 and TUNDRA__MAX_XLAT_THREADS (including)
    size_t addressing_external_cache_size_main_addresses;
    size_t addressing_external_cache_size_icmp_error_addresses;
    size_t translator_ipv4_outbound_mtu;
    size_t translator_ipv6_outbound_mtu;
    uint8_t addressing_nat64_clat_ipv4[4];
    uint8_t router_ipv4[4];
    uid_t program_privilege_drop_user_uid; // Must not be accessed if program_privilege_drop_user_perform == false
    uid_t io_tun_owner_user_uid; // Must not be accessed if io_mode != TUN or if io_tun_owner_user_set == false
    gid_t program_privilege_drop_group_gid; // Must not be accessed if program_privilege_drop_group_perform == false
    gid_t io_tun_owner_group_gid; // Must not be accessed if io_mode != TUN or if io_tun_owner_group_set == false
    tundra__io_mode io_mode;
    tundra__addressing_mode addressing_mode;
    tundra__addressing_external_transport addressing_external_transport;
    uint8_t router_generated_packet_ttl;
    bool program_privilege_drop_user_perform;
    bool program_privilege_drop_group_perform;
    bool io_tun_owner_user_set; // Must not be accessed if io_mode != TUN
    bool io_tun_owner_group_set; // Must not be accessed if io_mode != TUN
    bool io_tun_multi_queue; // Must not be accessed if io_mode != TUN
    bool addressing_nat64_clat_siit_allow_translation_of_private_ips;
    bool translator_6to4_copy_dscp_and_ecn;
    bool translator_4to6_copy_dscp_and_ecn;
} tundra__conf_file;



// ---------------------------------------------------------------------------------------------------------------------
// External address translation
// ---------------------------------------------------------------------------------------------------------------------

typedef struct tundra__external_addr_xlat_cache_entry {
    uint8_t src_ipv6[16];
    uint8_t dst_ipv6[16];
    time_t expiration_timestamp;
    uint8_t src_ipv4[4];
    uint8_t dst_ipv4[4];
} tundra__external_addr_xlat_cache_entry;

typedef struct tundra__external_addr_xlat_state {
    tundra__external_addr_xlat_cache_entry *cache_4to6_main_packet;
    tundra__external_addr_xlat_cache_entry *cache_4to6_icmp_error_packet;
    tundra__external_addr_xlat_cache_entry *cache_6to4_main_packet;
    tundra__external_addr_xlat_cache_entry *cache_6to4_icmp_error_packet;
    int read_fd;
    int write_fd;
    uint32_t message_identifier;
} tundra__external_addr_xlat_state;

typedef struct __attribute__((__packed__)) tundra__external_addr_xlat_message {
    uint8_t magic_byte;
    uint8_t version;
    uint8_t message_type;
    uint8_t cache_lifetime;
    uint32_t message_identifier;
    uint8_t src_ip[16];
    uint8_t dst_ip[16];
} tundra__external_addr_xlat_message;  // SIZE: 40 bytes



// ---------------------------------------------------------------------------------------------------------------------
// Thread context
// ---------------------------------------------------------------------------------------------------------------------

typedef struct tundra__thread_ctx {
    uint8_t *in_packet_buffer; // Not modified during the translation process.
    const tundra__conf_file *config;
    tundra__external_addr_xlat_state *external_addr_xlat_state;
    size_t in_packet_size; // Not modified during the translation process.
    size_t thread_id;
    pthread_t thread;
    int packet_read_fd;
    int packet_write_fd;
    uint32_t frag_id_ipv6;
    uint16_t frag_id_ipv4;
    bool joined;
} tundra__thread_ctx;



// ---------------------------------------------------------------------------------------------------------------------
// Miscellaneous
// ---------------------------------------------------------------------------------------------------------------------

// While structs for other network data structures that are processed during translation (struct iphdr, struct ipv6hdr,
// struct udphdr, struct tcphdr, ...) are available in Linux's standard C library's header files, a struct for the IPv6
// fragmentation header is missing (at least as of now), so Tundra has to define it itself.
typedef struct __attribute__((__packed__)) tundra__ipv6_frag_header {
    uint8_t next_header;
    uint8_t reserved;
    uint16_t offset_and_flags;
    uint16_t identification[2];
} tundra__ipv6_frag_header;  // SIZE: 8 bytes
