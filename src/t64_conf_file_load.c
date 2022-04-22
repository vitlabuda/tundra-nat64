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
#include"t64_conf_file_load.h"

#include"t64_utils.h"
#include"t64_utils_ip.h"
#include"t64_log.h"


#define _T64C_CONF_FILE_LOAD__LINE_BUFFER_SIZE 4096
#define _T64C_CONF_FILE_LOAD__STOP_PARSING_CONFIG_SYMBOL "!STOP"


static t64ts_tundra__conf_file_entry **_t64fa_conf_file_load__read_open_config_file(FILE *conf_file_stream);
static char *_t64f_conf_file_load__strip_whitespace_from_string(char *string);
static const char *_t64f_conf_file_load__get_entry_value_by_key(t64ts_tundra__conf_file_entry **config_file_entries, const char *key);


t64ts_tundra__conf_file_entry **t64fa_conf_file_load__read_configuration_file(const char *filepath) {
    FILE *conf_file_stream = fopen(filepath, "r");
    if(conf_file_stream == NULL)
        t64f_log__crash(true, "Failed to open the configuration file: %s", filepath);

    const int conf_file_fd = fileno(conf_file_stream);
    if(conf_file_fd < 0)
        t64f_log__crash(true, "Failed to get the file descriptor of the open configuration file: %s", filepath);

    if(flock(conf_file_fd, LOCK_SH) != 0)
        t64f_log__crash(true, "Failed to lock the open configuration file: %s", filepath);

    t64ts_tundra__conf_file_entry **config_file_entries = _t64fa_conf_file_load__read_open_config_file(conf_file_stream);

    if(flock(conf_file_fd, LOCK_UN) != 0)
        t64f_log__crash(true, "Failed to unlock the open configuration file: %s", filepath);

    if(fclose(conf_file_stream) != 0)
        t64f_log__crash(true, "Failed to close the configuration file: %s", filepath);

    return config_file_entries;
}

static t64ts_tundra__conf_file_entry** _t64fa_conf_file_load__read_open_config_file(FILE *conf_file_stream) {
    size_t entry_index = 0;
    t64ts_tundra__conf_file_entry **config_file_entries = t64fa_utils__allocate_memory(1, sizeof(t64ts_tundra__conf_file_entry *));
    *config_file_entries = NULL;

    char line_buffer[_T64C_CONF_FILE_LOAD__LINE_BUFFER_SIZE];
    for(int line_number = 1; fgets(line_buffer, _T64C_CONF_FILE_LOAD__LINE_BUFFER_SIZE, conf_file_stream) != NULL; line_number++) {
        if(T64M_UTILS__STRING_EMPTY(line_buffer) || line_buffer[strlen(line_buffer) - 1] != '\n')
            t64f_log__crash(false, "Line %d of the configuration file is too long!", line_number);

        char *key_ptr = _t64f_conf_file_load__strip_whitespace_from_string(line_buffer);
        if(T64M_UTILS__STRING_EMPTY(key_ptr) || *key_ptr == '#' || *key_ptr == ';')
            continue;
        if(T64M_UTILS__STRINGS_EQUAL(key_ptr, _T64C_CONF_FILE_LOAD__STOP_PARSING_CONFIG_SYMBOL))
            break;

        char *value_ptr = strchr(key_ptr, '=');
        if(value_ptr == NULL)
            t64f_log__crash(false, "Line %d of the configuration file does not contain a '=' character!", line_number);
        *(value_ptr++) = '\0';

        key_ptr = _t64f_conf_file_load__strip_whitespace_from_string(key_ptr);
        value_ptr = _t64f_conf_file_load__strip_whitespace_from_string(value_ptr);
        if(T64M_UTILS__STRING_EMPTY(key_ptr))
            t64f_log__crash(false, "The entry on line %d of the configuration file does not have a key!", line_number);

        if(_t64f_conf_file_load__get_entry_value_by_key(config_file_entries, key_ptr) != NULL)
            t64f_log__crash(false, "The key '%s' is specified more than once in the configuration file!", key_ptr);

        t64ts_tundra__conf_file_entry *new_entry = t64fa_utils__allocate_memory(1, sizeof(t64ts_tundra__conf_file_entry));
        new_entry->key = t64fa_utils__duplicate_string(key_ptr);
        new_entry->value = t64fa_utils__duplicate_string(value_ptr);

        config_file_entries = t64fa_utils__reallocate_memory(config_file_entries, entry_index + 2, sizeof(t64ts_tundra__conf_file_entry *));
        config_file_entries[entry_index++] = new_entry;
        config_file_entries[entry_index] = NULL;
    }

    return config_file_entries;
}

static char *_t64f_conf_file_load__strip_whitespace_from_string(char *string) {
    // --- Leading whitespace ---
    while(isspace(*string))
        string++;

    // --- Trailing whitespace ---
    char *end = string + strlen(string) - 1;
    while(end >= string && isspace(*end))
        end--;
    end[1] = '\0';

    return string;
}

void t64f_conf_file_load__free_configuration_file(t64ts_tundra__conf_file_entry **config_file_entries) {
    for(t64ts_tundra__conf_file_entry **current_entry = config_file_entries; *current_entry != NULL; current_entry++) {
        t64f_utils__free_memory((*current_entry)->key);
        t64f_utils__free_memory((*current_entry)->value);
        t64f_utils__free_memory(*current_entry);
    }

    t64f_utils__free_memory(config_file_entries);
}

static const char *_t64f_conf_file_load__get_entry_value_by_key(t64ts_tundra__conf_file_entry **config_file_entries, const char *key) {
    // Very inefficient linear search algorithm is used, because this function must be able to work with unsorted arrays (duplicate checking while reading the config file).
    // However, it's not really a problem, since the number of entries won't be huge.
    for(t64ts_tundra__conf_file_entry **current_entry = config_file_entries; *current_entry != NULL; current_entry++) {
        if(T64M_UTILS__STRINGS_EQUAL((*current_entry)->key, key))
            return (*current_entry)->value;
    }

    return NULL;
}

const char *t64f_conf_file_load__find_string(t64ts_tundra__conf_file_entry **config_file_entries, const char *key, const size_t max_characters, const bool empty_string_forbidden) {
    const char *string_value = _t64f_conf_file_load__get_entry_value_by_key(config_file_entries, key);

    if(string_value == NULL)
        t64f_log__crash(false, "The key '%s' could not be found in the configuration file!", key);

    if(empty_string_forbidden && T64M_UTILS__STRING_EMPTY(string_value))
        t64f_log__crash(false, "The '%s' configuration file option's string value must not be empty!", key);

    size_t string_length = strlen(string_value);
    if(string_length > max_characters)
        t64f_log__crash(false, "The '%s' configuration file option's string value must not have more than %zu characters (got %zu)!", key, max_characters, string_length);

    return string_value;
}

uint64_t t64f_conf_file_load__find_uint64(t64ts_tundra__conf_file_entry **config_file_entries, const char *key, const uint64_t min_value, const uint64_t max_value) {
    const char *string_value = t64f_conf_file_load__find_string(config_file_entries, key, T64C_CONF_FILE_LOAD__FIND_STRING_NO_MAX_CHARACTERS, false);

    uint64_t integer_value;
    if(sscanf(string_value, "%"SCNu64, &integer_value) != 1)
        t64f_log__crash(false, "The '%s' configuration file option's value is not a valid integer: '%s'", key, string_value);

    if(integer_value < min_value)
        t64f_log__crash(false, "The '%s' configuration file option's integer value must not be less than %"PRIu64" (got %"PRIu64")!", key, min_value, integer_value);

    if(integer_value > max_value)
        t64f_log__crash(false, "The '%s' configuration file option's integer value must not be more than %"PRIu64" (got %"PRIu64")!", key, max_value, integer_value);

    return integer_value;
}

bool t64f_conf_file_load__find_boolean(t64ts_tundra__conf_file_entry **config_file_entries, const char *key) {
    const char *string_value = t64f_conf_file_load__find_string(config_file_entries, key, T64C_CONF_FILE_LOAD__FIND_STRING_NO_MAX_CHARACTERS, false);

    if(
        T64M_UTILS__STRINGS_EQUAL_CI(string_value, "1") ||
        T64M_UTILS__STRINGS_EQUAL_CI(string_value, "true") ||
        T64M_UTILS__STRINGS_EQUAL_CI(string_value, "y") ||
        T64M_UTILS__STRINGS_EQUAL_CI(string_value, "yes") ||
        T64M_UTILS__STRINGS_EQUAL_CI(string_value, "on")
    ) return true;

    if(
        T64M_UTILS__STRINGS_EQUAL_CI(string_value, "0") ||
        T64M_UTILS__STRINGS_EQUAL_CI(string_value, "false") ||
        T64M_UTILS__STRINGS_EQUAL_CI(string_value, "n") ||
        T64M_UTILS__STRINGS_EQUAL_CI(string_value, "no") ||
        T64M_UTILS__STRINGS_EQUAL_CI(string_value, "off")
    ) return false;

    t64f_log__crash(false, "The '%s' configuration file option's value is not a valid boolean: '%s'", key, string_value);
}

void t64f_conf_file_load__find_ipv4_address(t64ts_tundra__conf_file_entry **config_file_entries, const char *key, uint8_t *destination) {
    const char *string_value = t64f_conf_file_load__find_string(config_file_entries, key, T64C_CONF_FILE_LOAD__FIND_STRING_NO_MAX_CHARACTERS, false);

    struct in_addr ipv4_address_value;
    if(inet_aton(string_value, &ipv4_address_value) == 0)
        t64f_log__crash(false, "The '%s' configuration file option's value is not a valid IPv4 address: '%s'", key, string_value);

    if(t64f_utils_ip__is_ipv4_address_unusable((uint8_t *) &ipv4_address_value.s_addr))
        t64f_log__crash(false, "The IPv4 address specified in the '%s' configuration file option is valid, but not usable: '%s'", key, string_value);

    memcpy(destination, &ipv4_address_value.s_addr, 4);
}

void t64f_conf_file_load__find_ipv6_address(t64ts_tundra__conf_file_entry **config_file_entries, const char *key, uint8_t *destination) {
    const char *string_value = t64f_conf_file_load__find_string(config_file_entries, key, T64C_CONF_FILE_LOAD__FIND_STRING_NO_MAX_CHARACTERS, false);

    struct in6_addr ipv6_address_value;
    if(inet_pton(AF_INET6, string_value, &ipv6_address_value) != 1)
        t64f_log__crash(false, "The '%s' configuration file option's value is not a valid IPv6 address: '%s'", key, string_value);

    if(t64f_utils_ip__is_ipv6_address_unusable((uint8_t *) ipv6_address_value.s6_addr))
        t64f_log__crash(false, "The IPv6 address specified in the '%s' configuration file option is valid, but not usable: '%s'", key, string_value);

    memcpy(destination, ipv6_address_value.s6_addr, 16);
}


#undef _T64C_CONF_FILE_LOAD__LINE_BUFFER_SIZE
#undef _T64C_CONF_FILE_LOAD__STOP_PARSING_CONFIG_SYMBOL
