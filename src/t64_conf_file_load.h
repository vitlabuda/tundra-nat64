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

#ifndef _T64I_CONF_FILE_LOAD_H
#define _T64I_CONF_FILE_LOAD_H

#include"t64_tundra.h"


#define T64C_CONF_FILE_LOAD__FIND_STRING_NO_MAX_CHARACTERS SIZE_MAX
#define T64C_CONF_FILE_LOAD__FIND_UINT64_NO_MIN_VALUE 0
#define T64C_CONF_FILE_LOAD__FIND_UINT64_NO_MAX_VALUE UINT64_MAX


extern t64ts_tundra__conf_file_entry **t64fa_conf_file_load__read_configuration_file(const char *filepath);
extern void t64f_conf_file_load__free_configuration_file(t64ts_tundra__conf_file_entry **config_file_entries);
extern const char *t64f_conf_file_load__find_string(t64ts_tundra__conf_file_entry **config_file_entries, const char *key, const size_t max_characters, const bool empty_string_forbidden);
extern uint64_t t64f_conf_file_load__find_uint64(t64ts_tundra__conf_file_entry **config_file_entries, const char *key, const uint64_t min_value, const uint64_t max_value);
extern bool t64f_conf_file_load__find_boolean(t64ts_tundra__conf_file_entry **config_file_entries, const char *key);
extern void t64f_conf_file_load__find_ipv4_address(t64ts_tundra__conf_file_entry **config_file_entries, const char *key, uint8_t *destination);
extern void t64f_conf_file_load__find_ipv6_address(t64ts_tundra__conf_file_entry **config_file_entries, const char *key, uint8_t *destination);


#endif // _T64I_CONF_FILE_LOAD_H
