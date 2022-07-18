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
#include"t64_conf_file.h"

#include"t64_utils.h"
#include"t64_log.h"
#include"t64_conf_file_load.h"


static t64ts_tundra__conf_file *_t64fa_conf_file__parse_configuration_file(t64ts_tundra__conf_file_entry **config_file_entries);
static void _t64fa_conf_file__parse_program_configuration_entries(t64ts_tundra__conf_file_entry **config_file_entries, t64ts_tundra__conf_file *file_configuration);
static void _t64fa_conf_file__parse_io_configuration_entries(t64ts_tundra__conf_file_entry **config_file_entries, t64ts_tundra__conf_file *file_configuration);
static void _t64fa_conf_file__parse_io_tun_configuration_entries(t64ts_tundra__conf_file_entry **config_file_entries, t64ts_tundra__conf_file *file_configuration);
static void _t64f_conf_file__parse_router_configuration_entries(t64ts_tundra__conf_file_entry **config_file_entries, t64ts_tundra__conf_file *file_configuration);
static void _t64f_conf_file__parse_translator_configuration_entries(t64ts_tundra__conf_file_entry **config_file_entries, t64ts_tundra__conf_file *file_configuration);
static void _t64f_conf_file__parse_translator_nat64_clat_configuration_entries(t64ts_tundra__conf_file_entry **config_file_entries, t64ts_tundra__conf_file *file_configuration);
static void _t64f_conf_file__parse_translator_nat64_clat_siit_configuration_entries(t64ts_tundra__conf_file_entry **config_file_entries, t64ts_tundra__conf_file *file_configuration);
static uid_t _t64f_conf_file__get_uid_by_username(const char *username);
static gid_t _t64f_conf_file__get_gid_by_groupname(const char *groupname);
static t64te_tundra__io_mode _t64f_conf_file__determine_io_mode_from_string(const char *io_mode_string);
static t64te_tundra__translator_mode _t64f_conf_file__determine_translator_mode_from_string(const char *translator_mode_string);


t64ts_tundra__conf_file *t64fa_conf_file__read_and_parse_configuration_file(const char *filepath) {
    t64ts_tundra__conf_file_entry **config_file_entries = t64fa_conf_file_load__read_configuration_file(filepath);

    t64ts_tundra__conf_file *file_configuration = _t64fa_conf_file__parse_configuration_file(config_file_entries);

    t64f_conf_file_load__free_configuration_file(config_file_entries);

    return file_configuration;
}

static t64ts_tundra__conf_file *_t64fa_conf_file__parse_configuration_file(t64ts_tundra__conf_file_entry **config_file_entries) {
    t64ts_tundra__conf_file *file_configuration = t64fa_utils__allocate_memory(1, sizeof(t64ts_tundra__conf_file));

    _t64fa_conf_file__parse_program_configuration_entries(config_file_entries, file_configuration);
    _t64fa_conf_file__parse_io_configuration_entries(config_file_entries, file_configuration);
    _t64f_conf_file__parse_router_configuration_entries(config_file_entries, file_configuration);
    _t64f_conf_file__parse_translator_configuration_entries(config_file_entries, file_configuration);

    return file_configuration;
}

static void _t64fa_conf_file__parse_program_configuration_entries(t64ts_tundra__conf_file_entry **config_file_entries, t64ts_tundra__conf_file *file_configuration) {
    // --- program.translator_threads ---
    file_configuration->program_translator_threads = (size_t) t64f_conf_file_load__find_uint64(config_file_entries, T64C_CONF_FILE__OPTION_KEY_PROGRAM_TRANSLATOR_THREADS, 0, T64C_TUNDRA__MAX_TRANSLATOR_THREADS);
    if(file_configuration->program_translator_threads == 0)
        file_configuration->program_translator_threads = (size_t) get_nprocs(); // Cannot fail

    // --- program.chroot_dir ---
    file_configuration->program_chroot_dir = t64fa_utils__duplicate_string(
        t64f_conf_file_load__find_string(config_file_entries, T64C_CONF_FILE__OPTION_KEY_PROGRAM_CHROOT_DIR, PATH_MAX - 1, false)
    );

    // --- program.privilege_drop_user ---
    {
        const char *username = t64f_conf_file_load__find_string(config_file_entries, T64C_CONF_FILE__OPTION_KEY_PROGRAM_PRIVILEGE_DROP_USER, T64C_CONF_FILE_LOAD__FIND_STRING_NO_MAX_CHARACTERS, false);
        if(T64M_UTILS__STRING_EMPTY(username)) {
            file_configuration->program_privilege_drop_user_perform = false;
            file_configuration->program_privilege_drop_user_uid = 0; // Not used
        } else {
            file_configuration->program_privilege_drop_user_perform = true;
            file_configuration->program_privilege_drop_user_uid = _t64f_conf_file__get_uid_by_username(username);
        }
    }

    // --- program.privilege_drop_group ---
    {
        const char *groupname = t64f_conf_file_load__find_string(config_file_entries, T64C_CONF_FILE__OPTION_KEY_PROGRAM_PRIVILEGE_DROP_GROUP, T64C_CONF_FILE_LOAD__FIND_STRING_NO_MAX_CHARACTERS, false);
        if(T64M_UTILS__STRING_EMPTY(groupname)) {
            file_configuration->program_privilege_drop_group_perform = false;
            file_configuration->program_privilege_drop_group_gid = 0; // Not used
        } else {
            file_configuration->program_privilege_drop_group_perform = true;
            file_configuration->program_privilege_drop_group_gid = _t64f_conf_file__get_gid_by_groupname(groupname);
        }
    }
}

static void _t64fa_conf_file__parse_io_configuration_entries(t64ts_tundra__conf_file_entry **config_file_entries, t64ts_tundra__conf_file *file_configuration) {
    // --- io.mode ---
    file_configuration->io_mode = _t64f_conf_file__determine_io_mode_from_string(
        t64f_conf_file_load__find_string(config_file_entries, T64C_CONF_FILE__OPTION_KEY_IO_MODE, T64C_CONF_FILE_LOAD__FIND_STRING_NO_MAX_CHARACTERS, false)
    );

    if(file_configuration->io_mode == T64TE_TUNDRA__IO_MODE_TUN) {
        _t64fa_conf_file__parse_io_tun_configuration_entries(config_file_entries, file_configuration);
    } else {
        file_configuration->io_tun_device_path = NULL; // Not used
        file_configuration->io_tun_interface_name = NULL; // Not used
        file_configuration->io_tun_owner_user_set = false; // Not used
        file_configuration->io_tun_owner_user_uid = 0; // Not used
        file_configuration->io_tun_owner_group_set = false; // Not used
        file_configuration->io_tun_owner_group_gid = 0; // Not used
    }
}

static void _t64fa_conf_file__parse_io_tun_configuration_entries(t64ts_tundra__conf_file_entry **config_file_entries, t64ts_tundra__conf_file *file_configuration) {
    // --- io.tun.device_path ---
    {
        const char *tun_device_path = t64f_conf_file_load__find_string(config_file_entries, T64C_CONF_FILE__OPTION_KEY_IO_TUN_DEVICE_PATH, PATH_MAX - 1, false);
        file_configuration->io_tun_device_path = t64fa_utils__duplicate_string(
            (T64M_UTILS__STRING_EMPTY(tun_device_path)) ? T64C_TUNDRA__DEFAULT_TUN_DEVICE_PATH : tun_device_path
        );
    }

    // --- io.tun.interface_name ---
    file_configuration->io_tun_interface_name = t64fa_utils__duplicate_string(
        t64f_conf_file_load__find_string(config_file_entries, T64C_CONF_FILE__OPTION_KEY_IO_TUN_INTERFACE_NAME, IFNAMSIZ - 1, true)
    );

    // --- io.tun.owner_user ---
    {
        const char *owner_username = t64f_conf_file_load__find_string(config_file_entries, T64C_CONF_FILE__OPTION_KEY_IO_TUN_OWNER_USER, T64C_CONF_FILE_LOAD__FIND_STRING_NO_MAX_CHARACTERS, false);
        if(T64M_UTILS__STRING_EMPTY(owner_username)) {
            file_configuration->io_tun_owner_user_set = false;
            file_configuration->io_tun_owner_user_uid = 0; // Not used
        } else {
            file_configuration->io_tun_owner_user_set = true;
            file_configuration->io_tun_owner_user_uid = _t64f_conf_file__get_uid_by_username(owner_username);
        }
    }

    // --- io.tun.owner_group ---
    {
        const char *owner_groupname = t64f_conf_file_load__find_string(config_file_entries, T64C_CONF_FILE__OPTION_KEY_IO_TUN_OWNER_GROUP, T64C_CONF_FILE_LOAD__FIND_STRING_NO_MAX_CHARACTERS, false);
        if(T64M_UTILS__STRING_EMPTY(owner_groupname)) {
            file_configuration->io_tun_owner_group_set = false;
            file_configuration->io_tun_owner_group_gid = 0; // Not used
        } else {
            file_configuration->io_tun_owner_group_set = true;
            file_configuration->io_tun_owner_group_gid = _t64f_conf_file__get_gid_by_groupname(owner_groupname);
        }
    }
}

static void _t64f_conf_file__parse_router_configuration_entries(t64ts_tundra__conf_file_entry **config_file_entries, t64ts_tundra__conf_file *file_configuration) {
    // --- router.ipv4 ---
    t64f_conf_file_load__find_ipv4_address(config_file_entries, T64C_CONF_FILE__OPTION_KEY_ROUTER_IPV4, file_configuration->router_ipv4);

    // --- router.ipv6 ---
    t64f_conf_file_load__find_ipv6_address(config_file_entries, T64C_CONF_FILE__OPTION_KEY_ROUTER_IPV6, file_configuration->router_ipv6);
}

static void _t64f_conf_file__parse_translator_configuration_entries(t64ts_tundra__conf_file_entry **config_file_entries, t64ts_tundra__conf_file *file_configuration) {
    // --- translator.mode ---
    file_configuration->translator_mode = _t64f_conf_file__determine_translator_mode_from_string(
        t64f_conf_file_load__find_string(config_file_entries, T64C_CONF_FILE__OPTION_KEY_TRANSLATOR_MODE, T64C_CONF_FILE_LOAD__FIND_STRING_NO_MAX_CHARACTERS, false)
    );

    _t64f_conf_file__parse_translator_nat64_clat_configuration_entries(config_file_entries, file_configuration);
    _t64f_conf_file__parse_translator_nat64_clat_siit_configuration_entries(config_file_entries, file_configuration);

    // --- translator.ipv4.outbound_mtu ---
    file_configuration->translator_ipv4_outbound_mtu = (size_t) t64f_conf_file_load__find_uint64(config_file_entries, T64C_CONF_FILE__OPTION_KEY_TRANSLATOR_IPV4_OUTBOUND_MTU, T64C_TUNDRA__MINIMUM_MTU_IPV4, T64C_TUNDRA__MAXIMUM_MTU_IPV4);

    // --- translator.ipv6.outbound_mtu ---
    file_configuration->translator_ipv6_outbound_mtu = (size_t) t64f_conf_file_load__find_uint64(config_file_entries, T64C_CONF_FILE__OPTION_KEY_TRANSLATOR_IPV6_OUTBOUND_MTU, T64C_TUNDRA__MINIMUM_MTU_IPV6, T64C_TUNDRA__MAXIMUM_MTU_IPV6);


    // --- translator.6to4.copy_dscp_and_ecn ---
    file_configuration->translator_6to4_copy_dscp_and_ecn = t64f_conf_file_load__find_boolean(config_file_entries, T64C_CONF_FILE__OPTION_KEY_TRANSLATOR_6TO4_COPY_DSCP_AND_ECN);

    // --- translator.4to6.copy_dscp_and_ecn ---
    file_configuration->translator_4to6_copy_dscp_and_ecn = t64f_conf_file_load__find_boolean(config_file_entries, T64C_CONF_FILE__OPTION_KEY_TRANSLATOR_4TO6_COPY_DSCP_AND_ECN);
}

static void _t64f_conf_file__parse_translator_nat64_clat_configuration_entries(t64ts_tundra__conf_file_entry **config_file_entries, t64ts_tundra__conf_file *file_configuration) {
    if(file_configuration->translator_mode == T64TE_TUNDRA__TRANSLATOR_MODE_NAT64 || file_configuration->translator_mode == T64TE_TUNDRA__TRANSLATOR_MODE_CLAT) {
        // --- translator.nat64_clat.ipv4 ---
        t64f_conf_file_load__find_ipv4_address(config_file_entries, T64C_CONF_FILE__OPTION_KEY_TRANSLATOR_NAT64_CLAT_IPV4, file_configuration->translator_nat64_clat_ipv4);
        if(T64M_UTILS__MEMORY_EQUAL(file_configuration->translator_nat64_clat_ipv4, file_configuration->router_ipv4, 4))
            t64f_log__crash(false, "'%s' must not be the same as '%s'!", T64C_CONF_FILE__OPTION_KEY_TRANSLATOR_NAT64_CLAT_IPV4, T64C_CONF_FILE__OPTION_KEY_ROUTER_IPV4);

        // --- translator.nat64_clat.ipv6 ---
        t64f_conf_file_load__find_ipv6_address(config_file_entries, T64C_CONF_FILE__OPTION_KEY_TRANSLATOR_NAT64_CLAT_IPV6, file_configuration->translator_nat64_clat_ipv6);
        if(T64M_UTILS__MEMORY_EQUAL(file_configuration->translator_nat64_clat_ipv6, file_configuration->router_ipv6, 16))
            t64f_log__crash(false, "'%s' must not be the same as '%s'!", T64C_CONF_FILE__OPTION_KEY_TRANSLATOR_NAT64_CLAT_IPV6, T64C_CONF_FILE__OPTION_KEY_ROUTER_IPV6);
    } else {
        T64M_UTILS__MEMORY_CLEAR(file_configuration->translator_nat64_clat_ipv4, 4, 1);
        T64M_UTILS__MEMORY_CLEAR(file_configuration->translator_nat64_clat_ipv6, 16, 1);
    }
}

static void _t64f_conf_file__parse_translator_nat64_clat_siit_configuration_entries(t64ts_tundra__conf_file_entry **config_file_entries, t64ts_tundra__conf_file *file_configuration) {
    if(file_configuration->translator_mode == T64TE_TUNDRA__TRANSLATOR_MODE_NAT64 || file_configuration->translator_mode == T64TE_TUNDRA__TRANSLATOR_MODE_CLAT || file_configuration->translator_mode == T64TE_TUNDRA__TRANSLATOR_MODE_SIIT) {
        // --- translator.nat64_clat_siit.prefix ---
        t64f_conf_file_load__find_ipv6_prefix(config_file_entries, T64C_CONF_FILE__OPTION_KEY_TRANSLATOR_NAT64_CLAT_SIIT_PREFIX, file_configuration->translator_nat64_clat_siit_prefix);

        // --- translator.nat64_clat_siit.allow_translation_of_private_ips ---
        file_configuration->translator_nat64_clat_siit_allow_translation_of_private_ips = t64f_conf_file_load__find_boolean(config_file_entries, T64C_CONF_FILE__OPTION_KEY_TRANSLATOR_NAT64_CLAT_SIIT_ALLOW_TRANSLATION_OF_PRIVATE_IPS);
    } else {
        T64M_UTILS__MEMORY_CLEAR(file_configuration->translator_nat64_clat_siit_prefix, 16, 1);
        file_configuration->translator_nat64_clat_siit_allow_translation_of_private_ips = false;
    }
}

static uid_t _t64f_conf_file__get_uid_by_username(const char *username) {
    struct passwd *passwd_entry = getpwnam(username);
    if(passwd_entry == NULL)
        t64f_log__crash(false, "A user named '%s' could not be found!", username);

    return passwd_entry->pw_uid;
}

static gid_t _t64f_conf_file__get_gid_by_groupname(const char *groupname) {
    struct group *group_entry = getgrnam(groupname);
    if(group_entry == NULL)
        t64f_log__crash(false, "A group named '%s' could not be found!", groupname);

    return group_entry->gr_gid;
}

static t64te_tundra__io_mode _t64f_conf_file__determine_io_mode_from_string(const char *io_mode_string) {
    if(T64M_UTILS__STRINGS_EQUAL(io_mode_string, T64C_CONF_FILE__IO_MODE_INHERITED_FDS))
        return T64TE_TUNDRA__IO_MODE_INHERITED_FDS;

    if(T64M_UTILS__STRINGS_EQUAL(io_mode_string, T64C_CONF_FILE__IO_MODE_TUN))
        return T64TE_TUNDRA__IO_MODE_TUN;

    t64f_log__crash(false, "Invalid I/O mode string: '%s'", io_mode_string);
}

static t64te_tundra__translator_mode _t64f_conf_file__determine_translator_mode_from_string(const char *translator_mode_string) {
    if(T64M_UTILS__STRINGS_EQUAL(translator_mode_string, T64C_CONF_FILE__TRANSLATOR_MODE_NAT64))
        return T64TE_TUNDRA__TRANSLATOR_MODE_NAT64;

    if(T64M_UTILS__STRINGS_EQUAL(translator_mode_string, T64C_CONF_FILE__TRANSLATOR_MODE_CLAT))
        return T64TE_TUNDRA__TRANSLATOR_MODE_CLAT;

    if(T64M_UTILS__STRINGS_EQUAL(translator_mode_string, T64C_CONF_FILE__TRANSLATOR_MODE_SIIT))
        return T64TE_TUNDRA__TRANSLATOR_MODE_SIIT;

    t64f_log__crash(false, "Invalid translator mode string: '%s'", translator_mode_string);
}

void t64f_conf_file__free_parsed_configuration_file(t64ts_tundra__conf_file *file_configuration) {
    t64f_utils__free_memory(file_configuration->program_chroot_dir);

    if(file_configuration->io_tun_device_path != NULL)
        t64f_utils__free_memory(file_configuration->io_tun_device_path);
    if(file_configuration->io_tun_interface_name != NULL)
        t64f_utils__free_memory(file_configuration->io_tun_interface_name);

    t64f_utils__free_memory(file_configuration);
}
