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
#include"tundra.h"


#define CONF_FILE_LOAD__FIND_STRING_NO_MAX_CHARS SIZE_MAX
#define CONF_FILE_LOAD__FIND_INTEGER_NO_MIN_VALUE 0
#define CONF_FILE_LOAD__FIND_INTEGER_NO_MAX_VALUE UINT64_MAX


typedef struct conf_file_load__conf_entry {
    char *key;
    char *value;
} conf_file_load__conf_entry;


extern conf_file_load__conf_entry **conf_file_load__read_config_file(const char *const filepath);
extern void conf_file_load__free_config_file(conf_file_load__conf_entry **entries);
extern const char *conf_file_load__find_string(conf_file_load__conf_entry **entries, const char *const key, const size_t max_chars, const bool empty_string_forbidden);
extern uint64_t conf_file_load__find_integer(conf_file_load__conf_entry **entries, const char *const key, const uint64_t min_value, const uint64_t max_value, uint64_t (*const fallback_value_getter)(void));
extern bool conf_file_load__find_boolean(conf_file_load__conf_entry **entries, const char *const key, bool (*const fallback_value_getter)(void));
extern void conf_file_load__find_ipv4_address(conf_file_load__conf_entry **entries, const char *const key, uint8_t *destination, void (*const fallback_value_getter)(uint8_t *destination));
extern void conf_file_load__find_ipv6_address(conf_file_load__conf_entry **entries, const char *const key, uint8_t *destination, void (*const fallback_value_getter)(uint8_t *destination));
extern void conf_file_load__find_ipv6_prefix(conf_file_load__conf_entry **entries, const char *const key, uint8_t *destination, void (*const fallback_value_getter)(uint8_t *destination));
