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
#include"t64_utils.h"

#include"t64_log.h"


void *t64fa_utils__allocate_memory(const size_t n, const size_t item_size) {
    void *memory = calloc(n, item_size);
    if(memory == NULL)
        t64f_log__crash(false, "Out of memory!");

    return memory;
}

void *t64fa_utils__reallocate_memory(void *old_memory, const size_t n, const size_t item_size) {
    void *new_memory = realloc(old_memory, n * item_size);
    if(new_memory == NULL)
        t64f_log__crash(false, "Out of memory!");

    return new_memory;
}

char *t64fa_utils__duplicate_string(const char *string) {
    char *new_string = strdup(string);
    if(new_string == NULL)
        t64f_log__crash(false, "Out of memory!");

    return new_string;
}

void t64f_utils__free_memory(void *memory) {
    // For future extension.
    free(memory);
}

void t64f_utils__secure_strncpy(char *destination, const char *source, const size_t buffer_size) {
    /* https://www.cplusplus.com/reference/cstring/strncpy/:
     *   No null-character is implicitly appended at the end of destination if source is longer than num.
     *   Thus, in this case, destination shall not be considered a null terminated C string (reading it as such would overflow).
     */

    strncpy(destination, source, buffer_size - 1);
    destination[buffer_size - 1] = '\0';
}

bool t64f_utils__secure_memcpy(void *destination, const void *source, const size_t copied_size, const size_t max_size) {
    if(copied_size > max_size)
        return false;

    memcpy(destination, source, copied_size);
    return true;
}

size_t t64f_utils__secure_memcpy_with_size_clamping(void *destination, const void *source, size_t copied_size, const size_t max_size) {
    if(copied_size > max_size)
        copied_size = max_size;

    memcpy(destination, source, copied_size);
    return copied_size;
}
