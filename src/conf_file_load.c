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
#include"conf_file_load.h"

#include"utils.h"
#include"utils_ip.h"
#include"log.h"


#define _LINE_BUFFER_SIZE 8192


static conf_file_load__conf_entry **_read_open_config_file(FILE *const conf_file_stream);
static char *_strip_whitespace(char *string);
static const char *_get_entry_value_by_key(conf_file_load__conf_entry **entries, const char *const key);


conf_file_load__conf_entry **conf_file_load__read_config_file(const char *const filepath) {
    conf_file_load__conf_entry **entries = NULL;

    if(UTILS__STR_EQ(filepath, "-")) {
        entries = _read_open_config_file(stdin);
    } else {
        FILE *const conf_file_stream = fopen(filepath, "r");
        if(conf_file_stream == NULL)
            log__crash(true, "Failed to open the configuration file: %s", filepath);

        const int conf_file_fd = fileno(conf_file_stream);
        if(conf_file_fd < 0)
            log__crash(true, "Failed to get the file descriptor of the open configuration file: %s", filepath);

        if(flock(conf_file_fd, LOCK_SH) != 0)
            log__crash(true, "Failed to lock the open configuration file: %s", filepath);

        entries = _read_open_config_file(conf_file_stream);

        if(flock(conf_file_fd, LOCK_UN) != 0)
            log__crash(true, "Failed to unlock the open configuration file: %s", filepath);

        if(fclose(conf_file_stream) != 0)
            log__crash(true, "Failed to close the configuration file: %s", filepath);
    }

    return entries;
}

static conf_file_load__conf_entry** _read_open_config_file(FILE *const conf_file_stream) {
    size_t entry_index = 0;
    conf_file_load__conf_entry **entries = utils__alloc_zeroed_out_memory(1, sizeof(conf_file_load__conf_entry *));
    *entries = NULL;

    char line_buffer[_LINE_BUFFER_SIZE];
    for(int line_number = 1; fgets(line_buffer, _LINE_BUFFER_SIZE, conf_file_stream) != NULL; line_number++) {
        char *key_ptr = _strip_whitespace(line_buffer);
        if(UTILS__STR_EMPTY(key_ptr) || *key_ptr == '#' || *key_ptr == ';')
            continue;
        if(UTILS__STR_EQ(key_ptr, "!STOP"))
            break;

        char *value_ptr = strchr(key_ptr, '=');
        if(value_ptr == NULL)
            log__crash(false, "Line %d of the configuration file does not contain a '=' character!", line_number);
        *(value_ptr++) = '\0';

        key_ptr = _strip_whitespace(key_ptr);
        value_ptr = _strip_whitespace(value_ptr);
        if(UTILS__STR_EMPTY(key_ptr))
            log__crash(false, "The entry on line %d of the configuration file does not have a key!", line_number);

        if(_get_entry_value_by_key(entries, key_ptr) != NULL)
            log__crash(false, "The key '%s' is specified more than once in the configuration file!", key_ptr);

        conf_file_load__conf_entry *new_entry = utils__alloc_zeroed_out_memory(1, sizeof(conf_file_load__conf_entry));
        new_entry->key = utils__duplicate_string(key_ptr);
        new_entry->value = utils__duplicate_string(value_ptr);

        entries = utils__realloc_memory(entries, entry_index + 2, sizeof(conf_file_load__conf_entry *));
        entries[entry_index++] = new_entry;
        entries[entry_index] = NULL;
    }

    return entries;
}

static char *_strip_whitespace(char *string) {
    // Leading whitespace
    while(isspace(*string))
        string++;

    // Trailing whitespace
    char *end = string + strlen(string) - 1;
    while(end >= string && isspace(*end))
        end--;
    end[1] = '\0';

    return string;
}

void conf_file_load__free_config_file(conf_file_load__conf_entry **entries) {
    for(conf_file_load__conf_entry **current_entry = entries; *current_entry != NULL; current_entry++) {
        utils__free_memory((*current_entry)->key);
        utils__free_memory((*current_entry)->value);
        utils__free_memory(*current_entry);
    }

    utils__free_memory(entries);
}

static const char *_get_entry_value_by_key(conf_file_load__conf_entry **entries, const char *const key) {
    // Very inefficient linear search algorithm is used, because this function must be able to work with unsorted arrays (duplicate checking while reading the config file).
    // However, it's not really a problem, since the number of entries won't be huge.
    for(conf_file_load__conf_entry **current_entry = entries; *current_entry != NULL; current_entry++) {
        if(UTILS__STR_EQ((*current_entry)->key, key))
            return (*current_entry)->value;
    }

    return NULL;
}

const char *conf_file_load__find_string(conf_file_load__conf_entry **entries, const char *const key, const size_t max_chars, const bool empty_string_forbidden) {
    const char *const string_value = _get_entry_value_by_key(entries, key);

    if(string_value == NULL)
        log__crash(false, "The key '%s' could not be found in the configuration file!", key);

    if(empty_string_forbidden && UTILS__STR_EMPTY(string_value))
        log__crash(false, "The '%s' configuration file option's string value must not be empty!", key);

    size_t string_length = strlen(string_value);
    if(string_length > max_chars)
        log__crash(false, "The '%s' configuration file option's string value must not have more than %zu characters (got %zu)!", key, max_chars, string_length);

    return string_value;
}

uint64_t conf_file_load__find_integer(conf_file_load__conf_entry **entries, const char *const key, const uint64_t min_value, const uint64_t max_value, uint64_t (*const fallback_value_getter)(void)) {
    const char *const string_value = conf_file_load__find_string(entries, key, CONF_FILE_LOAD__FIND_STRING_NO_MAX_CHARS, false);

    uint64_t integer_value;
    if(UTILS__STR_EMPTY(string_value) && fallback_value_getter != NULL)
        integer_value = (*fallback_value_getter)();
    else if(sscanf(string_value, "%"SCNu64, &integer_value) != 1)
        log__crash(false, "The '%s' configuration file option's value is not a valid integer: '%s'", key, string_value);

    if(integer_value < min_value)
        log__crash(false, "The '%s' configuration file option's integer value must not be less than %"PRIu64" (got %"PRIu64")!", key, min_value, integer_value);

    if(integer_value > max_value)
        log__crash(false, "The '%s' configuration file option's integer value must not be more than %"PRIu64" (got %"PRIu64")!", key, max_value, integer_value);

    return integer_value;
}

bool conf_file_load__find_boolean(conf_file_load__conf_entry **entries, const char *const key, bool (*const fallback_value_getter)(void)) {
    const char *const string_value = conf_file_load__find_string(entries, key, CONF_FILE_LOAD__FIND_STRING_NO_MAX_CHARS, false);

    if(UTILS__STR_EMPTY(string_value) && fallback_value_getter != NULL)
        return (*fallback_value_getter)();

    if(
        UTILS__STR_EQ_CI(string_value, "1") ||
        UTILS__STR_EQ_CI(string_value, "true") ||
        UTILS__STR_EQ_CI(string_value, "y") ||
        UTILS__STR_EQ_CI(string_value, "yes") ||
        UTILS__STR_EQ_CI(string_value, "on")
    ) return true;

    if(
        UTILS__STR_EQ_CI(string_value, "0") ||
        UTILS__STR_EQ_CI(string_value, "false") ||
        UTILS__STR_EQ_CI(string_value, "n") ||
        UTILS__STR_EQ_CI(string_value, "no") ||
        UTILS__STR_EQ_CI(string_value, "off")
    ) return false;

    log__crash(false, "The '%s' configuration file option's value is not a valid boolean: '%s'", key, string_value);
}

void conf_file_load__find_ipv4_address(conf_file_load__conf_entry **entries, const char *const key, uint8_t *destination, void (*const fallback_value_getter)(uint8_t *destination)) {
    const char *const string_value = conf_file_load__find_string(entries, key, CONF_FILE_LOAD__FIND_STRING_NO_MAX_CHARS, false);

    if(UTILS__STR_EMPTY(string_value) && fallback_value_getter != NULL) {
        (*fallback_value_getter)(destination);
    } else {
        struct in_addr ipv4_address_value;
        if(inet_aton(string_value, &ipv4_address_value) == 0)
            log__crash(false, "The '%s' configuration file option's value is not a valid IPv4 address: '%s'", key, string_value);

        memcpy(destination, &ipv4_address_value.s_addr, 4);
    }

    if(utils_ip__is_ipv4_addr_unusable(destination))
        log__crash(false, "The IPv4 address specified in the '%s' configuration file option is valid, but not usable: '%s'", key, string_value);
}

void conf_file_load__find_ipv6_address(conf_file_load__conf_entry **entries, const char *const key, uint8_t *destination, void (*const fallback_value_getter)(uint8_t *destination)) {
    const char *const string_value = conf_file_load__find_string(entries, key, CONF_FILE_LOAD__FIND_STRING_NO_MAX_CHARS, false);

    if(UTILS__STR_EMPTY(string_value) && fallback_value_getter != NULL) {
        (*fallback_value_getter)(destination);
    } else {
        struct in6_addr ipv6_address_value;
        if(inet_pton(AF_INET6, string_value, &ipv6_address_value) != 1)
            log__crash(false, "The '%s' configuration file option's value is not a valid IPv6 address: '%s'", key, string_value);

        memcpy(destination, ipv6_address_value.s6_addr, 16);
    }

    if(utils_ip__is_ipv6_addr_unusable(destination))
        log__crash(false, "The IPv6 address specified in the '%s' configuration file option is valid, but not usable: '%s'", key, string_value);
}

void conf_file_load__find_ipv6_prefix(conf_file_load__conf_entry **entries, const char *const key, uint8_t *destination, void (*const fallback_value_getter)(uint8_t *destination)) {
    conf_file_load__find_ipv6_address(entries, key, destination, fallback_value_getter);

    if(!UTILS__MEM_EQ((destination + 12), "\x00\x00\x00\x00", 4))
        log__crash(false, "The last 4 bytes of '%s' must be 0, as it is supposed to be an IPv6 /96 prefix!", key);
}


#undef _LINE_BUFFER_SIZE
