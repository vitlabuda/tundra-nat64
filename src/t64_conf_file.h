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

#ifndef _T64I_CONF_FILE_H
#define _T64I_CONF_FILE_H

#include"t64_tundra.h"


#define T64C_CONF_FILE__OPTION_KEY_PROGRAM_TRANSLATOR_THREADS "program.translator_threads"
#define T64C_CONF_FILE__OPTION_KEY_PROGRAM_CHROOT_DIR "program.chroot_dir"
#define T64C_CONF_FILE__OPTION_KEY_PROGRAM_PRIVILEGE_DROP_USER "program.privilege_drop_user"
#define T64C_CONF_FILE__OPTION_KEY_PROGRAM_PRIVILEGE_DROP_GROUP "program.privilege_drop_group"

#define T64C_CONF_FILE__OPTION_KEY_IO_MODE "io.mode"
#define T64C_CONF_FILE__OPTION_KEY_IO_TUN_DEVICE_PATH "io.tun.device_path"
#define T64C_CONF_FILE__OPTION_KEY_IO_TUN_INTERFACE_NAME "io.tun.interface_name"
#define T64C_CONF_FILE__OPTION_KEY_IO_TUN_OWNER_USER "io.tun.owner_user"
#define T64C_CONF_FILE__OPTION_KEY_IO_TUN_OWNER_GROUP "io.tun.owner_group"

#define T64C_CONF_FILE__OPTION_KEY_ROUTER_IPV4 "router.ipv4"
#define T64C_CONF_FILE__OPTION_KEY_ROUTER_IPV6 "router.ipv6"
#define T64C_CONF_FILE__OPTION_KEY_ROUTER_GENERATED_PACKET_TTL "router.generated_packet_ttl"

#define T64C_CONF_FILE__OPTION_KEY_ADDRESSING_MODE "addressing.mode"
#define T64C_CONF_FILE__OPTION_KEY_ADDRESSING_NAT64_CLAT_IPV4 "addressing.nat64_clat.ipv4"
#define T64C_CONF_FILE__OPTION_KEY_ADDRESSING_NAT64_CLAT_IPV6 "addressing.nat64_clat.ipv6"
#define T64C_CONF_FILE__OPTION_KEY_ADDRESSING_NAT64_CLAT_SIIT_PREFIX "addressing.nat64_clat_siit.prefix"
#define T64C_CONF_FILE__OPTION_KEY_ADDRESSING_NAT64_CLAT_SIIT_ALLOW_TRANSLATION_OF_PRIVATE_IPS "addressing.nat64_clat_siit.allow_translation_of_private_ips"
#define T64C_CONF_FILE__OPTION_KEY_ADDRESSING_EXTERNAL_TRANSPORT "addressing.external.transport"
#define T64C_CONF_FILE__OPTION_KEY_ADDRESSING_EXTERNAL_UNIX_PATH "addressing.external.unix.path"
#define T64C_CONF_FILE__OPTION_KEY_ADDRESSING_EXTERNAL_TCP_HOST "addressing.external.tcp.host"
#define T64C_CONF_FILE__OPTION_KEY_ADDRESSING_EXTERNAL_TCP_PORT "addressing.external.tcp.port"
#define T64C_CONF_FILE__OPTION_KEY_ADDRESSING_EXTERNAL_UNIX_TCP_TIMEOUT_MILLISECONDS "addressing.external.unix_tcp.timeout_milliseconds"
#define T64C_CONF_FILE__OPTION_KEY_ADDRESSING_EXTERNAL_CACHE_SIZE_MAIN_ADDRESSES "addressing.external.cache_size.main_addresses"
#define T64C_CONF_FILE__OPTION_KEY_ADDRESSING_EXTERNAL_CACHE_SIZE_ICMP_ERROR_ADDRESSES "addressing.external.cache_size.icmp_error_addresses"

#define T64C_CONF_FILE__OPTION_KEY_TRANSLATOR_IPV4_OUTBOUND_MTU "translator.ipv4.outbound_mtu"
#define T64C_CONF_FILE__OPTION_KEY_TRANSLATOR_IPV6_OUTBOUND_MTU "translator.ipv6.outbound_mtu"
#define T64C_CONF_FILE__OPTION_KEY_TRANSLATOR_6TO4_COPY_DSCP_AND_ECN "translator.6to4.copy_dscp_and_ecn"
#define T64C_CONF_FILE__OPTION_KEY_TRANSLATOR_4TO6_COPY_DSCP_AND_ECN "translator.4to6.copy_dscp_and_ecn"

#define T64C_CONF_FILE__IO_MODE_INHERITED_FDS "inherited-fds"
#define T64C_CONF_FILE__IO_MODE_TUN "tun"

#define T64C_CONF_FILE__ADDRESSING_MODE_NAT64 "nat64"
#define T64C_CONF_FILE__ADDRESSING_MODE_CLAT "clat"
#define T64C_CONF_FILE__ADDRESSING_MODE_SIIT "siit"
#define T64C_CONF_FILE__ADDRESSING_MODE_EXTERNAL "external"

#define T64C_CONF_FILE__ADDRESSING_EXTERNAL_TRANSPORT_INHERITED_FDS "inherited-fds"
#define T64C_CONF_FILE__ADDRESSING_EXTERNAL_TRANSPORT_UNIX "unix"
#define T64C_CONF_FILE__ADDRESSING_EXTERNAL_TRANSPORT_TCP "tcp"


extern t64ts_tundra__conf_file *t64fa_conf_file__read_and_parse_configuration_file(const char *filepath);
extern void t64f_conf_file__free_parsed_configuration_file(t64ts_tundra__conf_file *file_configuration);


#endif // _T64I_CONF_FILE_H
