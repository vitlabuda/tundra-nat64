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
#include"t64_opmode_print_config.h"

#include"t64_utils.h"
#include"t64_log.h"
#include"t64_conf_cmdline.h"
#include"t64_conf_file.h"


// This macro helps with reducing the resulting executable's size...
#define _T64M_OPMODE_PRINT_CONFIG__STRINGIFY(to_str) #to_str

#define _T64C_OPMODE_PRINT_CONFIG__NULL_REPRESENTATION "<not specified>"
#define _T64C_OPMODE_PRINT_CONFIG__EMPTY_STRING_REPRESENTATION "<empty>"
#define _T64C_OPMODE_PRINT_CONFIG__TRUE_BOOLEAN_REPRESENTATION "<yes>"
#define _T64C_OPMODE_PRINT_CONFIG__FALSE_BOOLEAN_REPRESENTATION "<no>"


static void _t64f_opmode_print_config__print_compile_time_config(void);
static void _t64f_opmode_print_config__print_command_line_config(const t64ts_tundra__conf_cmdline *cmdline_configuration);
static void _t64f_opmode_print_config__print_file_config(const t64ts_tundra__conf_file *file_configuration);
static const char *_t64f_opmode_print_config__get_printable_representation_of_string(const char *string);
static const char *_t64f_opmode_print_config__get_printable_representation_of_boolean(const bool boolean_value);
static char *_t64f_opmode_print_config__get_printable_representation_of_ipv4_address(const uint8_t *ipv4_address, char *out_string_buf);
static char *_t64f_opmode_print_config__get_printable_representation_of_ipv6_address(const uint8_t *ipv6_address, char *out_string_buf);
static const char *_t64f_opmode_print_config__get_string_representation_of_operation_mode(const t64te_tundra__operation_mode mode_of_operation);
static const char *_t64f_opmode_print_config__get_string_representation_of_io_mode(const t64te_tundra__io_mode io_mode);
static const char *_t64f_opmode_print_config__get_string_representation_of_translator_mode(const t64te_tundra__translator_mode translator_mode);


void t64f_opmode_print_config__run(const t64ts_tundra__conf_cmdline *cmdline_configuration, const t64ts_tundra__conf_file *file_configuration) {
    printf("\n");

    _t64f_opmode_print_config__print_compile_time_config(); // Compile-time configuration
    printf("\n\n\n");
    _t64f_opmode_print_config__print_command_line_config(cmdline_configuration); // Command-line configuration
    printf("\n\n\n");
    _t64f_opmode_print_config__print_file_config(file_configuration); // File configuration

    printf("\n");
    fflush(stdout);
}

static void _t64f_opmode_print_config__print_compile_time_config(void) {
    printf("Compile-time configuration:\n");

    printf("* %s = %s\n", _T64M_OPMODE_PRINT_CONFIG__STRINGIFY(T64C_TUNDRA__DEFAULT_CONFIG_FILE_PATH), _t64f_opmode_print_config__get_printable_representation_of_string(T64C_TUNDRA__DEFAULT_CONFIG_FILE_PATH));
    printf("* %s = %s\n", _T64M_OPMODE_PRINT_CONFIG__STRINGIFY(T64C_TUNDRA__DEFAULT_TUN_DEVICE_PATH), _t64f_opmode_print_config__get_printable_representation_of_string(T64C_TUNDRA__DEFAULT_TUN_DEVICE_PATH));
    printf("* %s = %s\n", _T64M_OPMODE_PRINT_CONFIG__STRINGIFY(T64C_TUNDRA__WORKING_DIRECTORY), _t64f_opmode_print_config__get_printable_representation_of_string(T64C_TUNDRA__WORKING_DIRECTORY));
    printf("* %s = %zu\n", _T64M_OPMODE_PRINT_CONFIG__STRINGIFY(T64C_TUNDRA__MAX_TRANSLATOR_THREADS), T64C_TUNDRA__MAX_TRANSLATOR_THREADS);
    printf("* %s = %u\n", _T64M_OPMODE_PRINT_CONFIG__STRINGIFY(T64C_TUNDRA__TRANSLATOR_THREAD_MONITOR_INTERVAL), T64C_TUNDRA__TRANSLATOR_THREAD_MONITOR_INTERVAL);

    printf("\n");

    printf("* %s = %zu\n", _T64M_OPMODE_PRINT_CONFIG__STRINGIFY(T64C_TUNDRA__MAX_PACKET_SIZE), T64C_TUNDRA__MAX_PACKET_SIZE);
    printf("* %s = %zu\n", _T64M_OPMODE_PRINT_CONFIG__STRINGIFY(T64C_TUNDRA__MINIMUM_MTU_IPV4), T64C_TUNDRA__MINIMUM_MTU_IPV4);
    printf("* %s = %zu\n", _T64M_OPMODE_PRINT_CONFIG__STRINGIFY(T64C_TUNDRA__MINIMUM_MTU_IPV6), T64C_TUNDRA__MINIMUM_MTU_IPV6);
    printf("* %s = %zu\n", _T64M_OPMODE_PRINT_CONFIG__STRINGIFY(T64C_TUNDRA__MAXIMUM_MTU_IPV4), T64C_TUNDRA__MAXIMUM_MTU_IPV4);
    printf("* %s = %zu\n", _T64M_OPMODE_PRINT_CONFIG__STRINGIFY(T64C_TUNDRA__MAXIMUM_MTU_IPV6), T64C_TUNDRA__MAXIMUM_MTU_IPV6);
    printf("* %s = %"PRIu8"\n", _T64M_OPMODE_PRINT_CONFIG__STRINGIFY(T64C_TUNDRA__GENERATED_PACKET_TTL), T64C_TUNDRA__GENERATED_PACKET_TTL);

    printf("\n");

    printf("* %s = %d\n", _T64M_OPMODE_PRINT_CONFIG__STRINGIFY(T64C_TUNDRA__EXIT_CODE_SUCCESS), T64C_TUNDRA__EXIT_CODE_SUCCESS);
    printf("* %s = %d\n", _T64M_OPMODE_PRINT_CONFIG__STRINGIFY(T64C_TUNDRA__EXIT_CODE_CRASH), T64C_TUNDRA__EXIT_CODE_CRASH);
    printf("* %s = %d\n", _T64M_OPMODE_PRINT_CONFIG__STRINGIFY(T64C_TUNDRA__EXIT_CODE_MUTEX_FAILURE), T64C_TUNDRA__EXIT_CODE_MUTEX_FAILURE);
    printf("* %s = %d\n", _T64M_OPMODE_PRINT_CONFIG__STRINGIFY(T64C_TUNDRA__EXIT_CODE_INVALID_COMPILE_TIME_CONFIG), T64C_TUNDRA__EXIT_CODE_INVALID_COMPILE_TIME_CONFIG);
}

static void _t64f_opmode_print_config__print_command_line_config(const t64ts_tundra__conf_cmdline *cmdline_configuration) {
    printf("Command-line configuration:\n");

    printf("* --%s = %s\n", T64C_CONF_CMDLINE__LONGOPT_CONFIG_FILE, _t64f_opmode_print_config__get_printable_representation_of_string(cmdline_configuration->config_file_path));
    printf("* --%s = %s\n", T64C_CONF_CMDLINE__LONGOPT_INHERITED_FDS, _t64f_opmode_print_config__get_printable_representation_of_string(cmdline_configuration->inherited_fds));
    printf("* Mode of operation = %s\n", _t64f_opmode_print_config__get_string_representation_of_operation_mode(cmdline_configuration->mode_of_operation));
}

static void _t64f_opmode_print_config__print_file_config(const t64ts_tundra__conf_file *file_configuration) {
    char string_ip_address_buf[INET6_ADDRSTRLEN] = {'\0'};

    printf("File configuration:\n");



    // program.*
    printf("* %s = %zu\n", T64C_CONF_FILE__OPTION_KEY_PROGRAM_TRANSLATOR_THREADS, file_configuration->program_translator_threads);
    printf("* %s = %s\n", T64C_CONF_FILE__OPTION_KEY_PROGRAM_CHROOT_DIR, _t64f_opmode_print_config__get_printable_representation_of_string(file_configuration->program_chroot_dir));
    if(file_configuration->program_privilege_drop_user_perform)
        printf("* %s = %s (UID: %"PRIdMAX")\n", T64C_CONF_FILE__OPTION_KEY_PROGRAM_PRIVILEGE_DROP_USER, _T64C_OPMODE_PRINT_CONFIG__TRUE_BOOLEAN_REPRESENTATION, (intmax_t) file_configuration->program_privilege_drop_user_uid);
    else
        printf("* %s = %s\n", T64C_CONF_FILE__OPTION_KEY_PROGRAM_PRIVILEGE_DROP_USER, _T64C_OPMODE_PRINT_CONFIG__FALSE_BOOLEAN_REPRESENTATION);
    if(file_configuration->program_privilege_drop_group_perform)
        printf("* %s = %s (GID: %"PRIdMAX")\n", T64C_CONF_FILE__OPTION_KEY_PROGRAM_PRIVILEGE_DROP_GROUP, _T64C_OPMODE_PRINT_CONFIG__TRUE_BOOLEAN_REPRESENTATION, (intmax_t) file_configuration->program_privilege_drop_group_gid);
    else
        printf("* %s = %s\n", T64C_CONF_FILE__OPTION_KEY_PROGRAM_PRIVILEGE_DROP_GROUP, _T64C_OPMODE_PRINT_CONFIG__FALSE_BOOLEAN_REPRESENTATION);

    printf("\n");



    // io.*
    printf("* %s = %s\n", T64C_CONF_FILE__OPTION_KEY_IO_MODE, _t64f_opmode_print_config__get_string_representation_of_io_mode(file_configuration->io_mode));

    if(file_configuration->io_mode == T64TE_TUNDRA__IO_MODE_TUN) {
        printf("* %s = %s\n", T64C_CONF_FILE__OPTION_KEY_IO_TUN_DEVICE_PATH, _t64f_opmode_print_config__get_printable_representation_of_string(file_configuration->io_tun_device_path));
        printf("* %s = %s\n", T64C_CONF_FILE__OPTION_KEY_IO_TUN_INTERFACE_NAME, _t64f_opmode_print_config__get_printable_representation_of_string(file_configuration->io_tun_interface_name));
        if(file_configuration->io_tun_owner_user_set)
            printf("* %s = %s (UID: %"PRIdMAX")\n", T64C_CONF_FILE__OPTION_KEY_IO_TUN_OWNER_USER, _T64C_OPMODE_PRINT_CONFIG__TRUE_BOOLEAN_REPRESENTATION, (intmax_t) file_configuration->io_tun_owner_user_uid);
        else
            printf("* %s = %s\n", T64C_CONF_FILE__OPTION_KEY_IO_TUN_OWNER_USER, _T64C_OPMODE_PRINT_CONFIG__FALSE_BOOLEAN_REPRESENTATION);
        if(file_configuration->io_tun_owner_group_set)
            printf("* %s = %s (GID: %"PRIdMAX")\n", T64C_CONF_FILE__OPTION_KEY_IO_TUN_OWNER_GROUP, _T64C_OPMODE_PRINT_CONFIG__TRUE_BOOLEAN_REPRESENTATION, (intmax_t) file_configuration->io_tun_owner_group_gid);
        else
            printf("* %s = %s\n", T64C_CONF_FILE__OPTION_KEY_IO_TUN_OWNER_GROUP, _T64C_OPMODE_PRINT_CONFIG__FALSE_BOOLEAN_REPRESENTATION);
    }

    printf("\n");



    // translator.*
    printf("* %s = %s\n", T64C_CONF_FILE__OPTION_KEY_TRANSLATOR_MODE, _t64f_opmode_print_config__get_string_representation_of_translator_mode(file_configuration->translator_mode));

    switch(file_configuration->translator_mode) {
        case T64TE_TUNDRA__TRANSLATOR_MODE_NAT64: case T64TE_TUNDRA__TRANSLATOR_MODE_CLAT:
            printf("* %s = %s\n", T64C_CONF_FILE__OPTION_KEY_TRANSLATOR_NAT64_CLAT_IPV4, _t64f_opmode_print_config__get_printable_representation_of_ipv4_address(file_configuration->translator_nat64_clat_ipv4, string_ip_address_buf));
            printf("* %s = %s\n", T64C_CONF_FILE__OPTION_KEY_TRANSLATOR_NAT64_CLAT_IPV6, _t64f_opmode_print_config__get_printable_representation_of_ipv6_address(file_configuration->translator_nat64_clat_ipv6, string_ip_address_buf));
            printf("* %s = %s/96\n", T64C_CONF_FILE__OPTION_KEY_TRANSLATOR_NAT64_CLAT_SIIT_PREFIX, _t64f_opmode_print_config__get_printable_representation_of_ipv6_address(file_configuration->translator_nat64_clat_siit_prefix, string_ip_address_buf));
            printf("* %s = %s\n", T64C_CONF_FILE__OPTION_KEY_TRANSLATOR_NAT64_CLAT_SIIT_ALLOW_TRANSLATION_OF_PRIVATE_IPS, _t64f_opmode_print_config__get_printable_representation_of_boolean(file_configuration->translator_nat64_clat_siit_allow_translation_of_private_ips));
            break;

        case T64TE_TUNDRA__TRANSLATOR_MODE_SIIT:
            printf("* %s = %s/96\n", T64C_CONF_FILE__OPTION_KEY_TRANSLATOR_NAT64_CLAT_SIIT_PREFIX, _t64f_opmode_print_config__get_printable_representation_of_ipv6_address(file_configuration->translator_nat64_clat_siit_prefix, string_ip_address_buf));
            printf("* %s = %s\n", T64C_CONF_FILE__OPTION_KEY_TRANSLATOR_NAT64_CLAT_SIIT_ALLOW_TRANSLATION_OF_PRIVATE_IPS, _t64f_opmode_print_config__get_printable_representation_of_boolean(file_configuration->translator_nat64_clat_siit_allow_translation_of_private_ips));
            break;

        default:
            t64f_log__crash_invalid_internal_state("Invalid translator mode");
    }

    printf("* %s = %zu\n", T64C_CONF_FILE__OPTION_KEY_TRANSLATOR_IPV4_OUTBOUND_MTU, file_configuration->translator_ipv4_outbound_mtu);
    printf("* %s = %zu\n", T64C_CONF_FILE__OPTION_KEY_TRANSLATOR_IPV6_OUTBOUND_MTU, file_configuration->translator_ipv6_outbound_mtu);

    printf("* %s = %s\n", T64C_CONF_FILE__OPTION_KEY_TRANSLATOR_6TO4_COPY_DSCP_AND_ECN, _t64f_opmode_print_config__get_printable_representation_of_boolean(file_configuration->translator_6to4_copy_dscp_and_ecn));
    printf("* %s = %s\n", T64C_CONF_FILE__OPTION_KEY_TRANSLATOR_4TO6_COPY_DSCP_AND_ECN, _t64f_opmode_print_config__get_printable_representation_of_boolean(file_configuration->translator_4to6_copy_dscp_and_ecn));

    printf("\n");



    // router.*
    printf("* %s = %s\n", T64C_CONF_FILE__OPTION_KEY_ROUTER_IPV4, _t64f_opmode_print_config__get_printable_representation_of_ipv4_address(file_configuration->router_ipv4, string_ip_address_buf));
    printf("* %s = %s\n", T64C_CONF_FILE__OPTION_KEY_ROUTER_IPV6, _t64f_opmode_print_config__get_printable_representation_of_ipv6_address(file_configuration->router_ipv6, string_ip_address_buf));
}

static const char *_t64f_opmode_print_config__get_printable_representation_of_string(const char *string) {
    if(string == NULL)
        return _T64C_OPMODE_PRINT_CONFIG__NULL_REPRESENTATION;

    if(T64M_UTILS__STRING_EMPTY(string))
        return _T64C_OPMODE_PRINT_CONFIG__EMPTY_STRING_REPRESENTATION;

    return string;
}

static const char *_t64f_opmode_print_config__get_printable_representation_of_boolean(const bool boolean_value) {
    return (boolean_value ? _T64C_OPMODE_PRINT_CONFIG__TRUE_BOOLEAN_REPRESENTATION : _T64C_OPMODE_PRINT_CONFIG__FALSE_BOOLEAN_REPRESENTATION);
}

static char *_t64f_opmode_print_config__get_printable_representation_of_ipv4_address(const uint8_t *ipv4_address, char *out_string_buf) {
    struct in_addr address4;
    T64M_UTILS__MEMORY_CLEAR(&address4, 1, sizeof(struct in_addr));
    memcpy(&address4.s_addr, ipv4_address, 4);

    if(inet_ntop(AF_INET, &address4, out_string_buf, INET_ADDRSTRLEN) == NULL)
        t64f_log__crash(true, "Failed to convert an IPv4 address from binary to string form!");

    return out_string_buf;
}

static char *_t64f_opmode_print_config__get_printable_representation_of_ipv6_address(const uint8_t *ipv6_address, char *out_string_buf) {
    struct in6_addr address6;
    T64M_UTILS__MEMORY_CLEAR(&address6, 1, sizeof(struct in6_addr));
    memcpy(address6.s6_addr, ipv6_address, 16);

    if(inet_ntop(AF_INET6, &address6, out_string_buf, INET6_ADDRSTRLEN) == NULL)
        t64f_log__crash(true, "Failed to convert an IPv6 address from binary to string form!");

    return out_string_buf;
}

static const char *_t64f_opmode_print_config__get_string_representation_of_operation_mode(const t64te_tundra__operation_mode mode_of_operation) {
    switch(mode_of_operation) {
        case T64TE_TUNDRA__OPERATION_MODE_TRANSLATE:
            return T64C_CONF_CMDLINE__OPMODE_TRANSLATE;

        case T64TE_TUNDRA__OPERATION_MODE_MKTUN:
            return T64C_CONF_CMDLINE__OPMODE_MKTUN;

        case T64TE_TUNDRA__OPERATION_MODE_RMTUN:
            return T64C_CONF_CMDLINE__OPMODE_RMTUN;

        case T64TE_TUNDRA__OPERATION_MODE_VALIDATE_CONFIG:
            return T64C_CONF_CMDLINE__OPMODE_VALIDATE_CONFIG;

        case T64TE_TUNDRA__OPERATION_MODE_PRINT_CONFIG:
            return T64C_CONF_CMDLINE__OPMODE_PRINT_CONFIG;

        default:
            t64f_log__crash_invalid_internal_state("Invalid mode of operation");
    }
}

static const char *_t64f_opmode_print_config__get_string_representation_of_io_mode(const t64te_tundra__io_mode io_mode) {
    switch(io_mode) {
        case T64TE_TUNDRA__IO_MODE_INHERITED_FDS:
            return T64C_CONF_FILE__IO_MODE_INHERITED_FDS;

        case T64TE_TUNDRA__IO_MODE_TUN:
            return T64C_CONF_FILE__IO_MODE_TUN;

        default:
            t64f_log__crash_invalid_internal_state("Invalid I/O mode");
    }
}

static const char *_t64f_opmode_print_config__get_string_representation_of_translator_mode(const t64te_tundra__translator_mode translator_mode) {
    switch(translator_mode) {
        case T64TE_TUNDRA__TRANSLATOR_MODE_NAT64:
            return T64C_CONF_FILE__TRANSLATOR_MODE_NAT64;

        case T64TE_TUNDRA__TRANSLATOR_MODE_CLAT:
            return T64C_CONF_FILE__TRANSLATOR_MODE_CLAT;

        case T64TE_TUNDRA__TRANSLATOR_MODE_SIIT:
            return T64C_CONF_FILE__TRANSLATOR_MODE_SIIT;

        default:
            t64f_log__crash_invalid_internal_state("Invalid translator mode");
    }
}


#undef _T64M_OPMODE_PRINT_CONFIG__STRINGIFY

#undef _T64C_OPMODE_PRINT_CONFIG__NULL_REPRESENTATION
#undef _T64C_OPMODE_PRINT_CONFIG__EMPTY_STRING_REPRESENTATION
#undef _T64C_OPMODE_PRINT_CONFIG__TRUE_BOOLEAN_REPRESENTATION
#undef _T64C_OPMODE_PRINT_CONFIG__FALSE_BOOLEAN_REPRESENTATION
