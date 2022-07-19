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

#ifndef _T64I_TUNDRA_TYPEDEFS_H
#define _T64I_TUNDRA_TYPEDEFS_H


typedef enum {
    T64TE_TUNDRA__XLAT_STATUS_CONTINUE_TRANSLATION,
    T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION
} t64te_tundra__xlat_status;


// ---------------------------------------------------------------------------------------------------------------------


typedef enum {
    T64TE_TUNDRA__OPERATION_MODE_TRANSLATE,
    T64TE_TUNDRA__OPERATION_MODE_MKTUN,
    T64TE_TUNDRA__OPERATION_MODE_RMTUN,
    T64TE_TUNDRA__OPERATION_MODE_VALIDATE_CONFIG,
    T64TE_TUNDRA__OPERATION_MODE_PRINT_CONFIG
} t64te_tundra__operation_mode;

typedef enum {
    T64TE_TUNDRA__IO_MODE_INHERITED_FDS,
    T64TE_TUNDRA__IO_MODE_TUN
} t64te_tundra__io_mode;

typedef enum {
    T64TE_TUNDRA__TRANSLATOR_MODE_NAT64,
    T64TE_TUNDRA__TRANSLATOR_MODE_CLAT,
    T64TE_TUNDRA__TRANSLATOR_MODE_SIIT
} t64te_tundra__translator_mode;

typedef struct {
    char *config_file_path; // Cannot be NULL - contains either command-line-provided filepath, or T64C_TUNDRA_DEFAULT_CONFIG_FILE_PATH
    char *inherited_fds; // Is NULL, when no inherited-fds are specified via command-line options
    t64te_tundra__operation_mode mode_of_operation;
} t64ts_tundra__conf_cmdline;

typedef struct {
    char *key;
    char *value;
} t64ts_tundra__conf_file_entry;

typedef struct {
    // The items are ordered in a way to reduce struct padding as much as possible, which is the reason why they seem to be in a "somewhat random order".
    uint8_t translator_nat64_clat_siit_prefix[16];
    uint8_t translator_nat64_clat_ipv6[16];
    uint8_t router_ipv6[16];
    char *program_chroot_dir; // Cannot be NULL, but can be empty (= no chroot should be performed)
    char *io_tun_device_path; // NULL if io_mode != TUN; Cannot be empty - contains either the config-file-provided TUN device path, or T64C_TUNDRA_DEFAULT_TUN_DEVICE_PATH
    char *io_tun_interface_name; // NULL if io_mode != TUN; Cannot be empty
    size_t program_translator_threads; // Between 1 and T64C_TUNDRA__MAX_TRANSLATOR_THREADS (including)
    size_t translator_ipv4_outbound_mtu;
    size_t translator_ipv6_outbound_mtu;
    uint8_t translator_nat64_clat_ipv4[4];
    uint8_t router_ipv4[4];
    uid_t program_privilege_drop_user_uid; // Must not be accessed if program_privilege_drop_user_perform == false
    uid_t io_tun_owner_user_uid; // Must not be accessed if io_mode != TUN or if io_tun_owner_user_set == false
    gid_t program_privilege_drop_group_gid; // Must not be accessed if program_privilege_drop_group_perform == false
    gid_t io_tun_owner_group_gid; // Must not be accessed if io_mode != TUN or if io_tun_owner_group_set == false
    t64te_tundra__io_mode io_mode;
    t64te_tundra__translator_mode translator_mode;
    bool program_privilege_drop_user_perform;
    bool program_privilege_drop_group_perform;
    bool io_tun_owner_user_set; // Must not be accessed if io_mode != TUN
    bool io_tun_owner_group_set; // Must not be accessed if io_mode != TUN
    bool translator_nat64_clat_siit_allow_translation_of_private_ips;
    bool translator_6to4_copy_dscp_and_ecn;
    bool translator_4to6_copy_dscp_and_ecn;
} t64ts_tundra__conf_file;


// ---------------------------------------------------------------------------------------------------------------------


typedef struct __attribute__((__packed__)) {
    uint8_t next_header;
    uint8_t reserved;
    uint16_t offset_and_flags;
    uint16_t identification[2];
} t64ts_tundra__ipv6_fragment_header;

typedef struct {
    union __attribute__((__packed__)) {
        // This pointer (it is a union) does not change after it is allocated, and it must be freed!
        uint8_t *packet_raw;
        struct iphdr *packet_ipv4hdr;
        struct ipv6hdr *packet_ipv6hdr;
    };
    union __attribute__((__packed__)) {
        // This pointer (it is a union) changes for every individual packet, and it points to the same dynamically-allocated memory block as 'packet_raw'!
        uint8_t *payload_raw;
        struct icmphdr *payload_icmpv4hdr;
        struct icmp6hdr *payload_icmpv6hdr;
        struct tcphdr *payload_tcphdr;
        struct udphdr *payload_udphdr;
    };
    t64ts_tundra__ipv6_fragment_header *ipv6_fragment_header; // NULL if the packet is an unfragmented IPv6 packet (not used with IPv4 packets - the contents are undefined).
    uint8_t *ipv6_carried_protocol_field; // Not used with IPv4 packets - the contents are undefined.
    size_t packet_size;
    size_t payload_size;
} t64ts_tundra__packet;

typedef struct {
    t64ts_tundra__packet in_packet;
    t64ts_tundra__packet out_packet;
    t64ts_tundra__packet tmp_packet;
    pthread_t thread;
    const t64ts_tundra__conf_file *configuration;
    size_t thread_id;
    int termination_pipe_read_fd;
    int packet_read_fd;
    int packet_write_fd;
    uint32_t fragment_identifier_ipv6;
    uint16_t fragment_identifier_ipv4;
} t64ts_tundra__xlat_thread_context;


#endif // _T64I_TUNDRA_TYPEDEFS_H
