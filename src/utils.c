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
#include"utils.h"

#include"log.h"


#define _OOM_MESSAGE "Out of memory!"


void *utils__alloc_zeroed_out_memory(const size_t n, const size_t item_size) {
    void *memory = calloc(n, item_size);
    if(memory == NULL)
        log__crash(false, "%s", _OOM_MESSAGE);

    return memory;
}

void *utils__alloc_aligned_zeroed_out_memory(const size_t n, const size_t item_size, const size_t alignment) {
    const size_t size_in_bytes = n * item_size;
    if(size_in_bytes % alignment != 0)
        log__crash(false, "Could not allocate aligned memory - the required alignment is invalid! (%zu is not divisible by %zu)", size_in_bytes, alignment);

    void *memory = aligned_alloc(alignment, size_in_bytes);
    if(memory == NULL)
        log__crash(false, "%s", _OOM_MESSAGE);

    UTILS__MEM_ZERO_OUT(memory, size_in_bytes);

    return memory;
}

void *utils__realloc_memory(void *old_memory, const size_t n, const size_t item_size) {
    void *new_memory = realloc(old_memory, n * item_size);
    if(new_memory == NULL)
        log__crash(false, "%s", _OOM_MESSAGE);

    return new_memory;
}

char *utils__duplicate_string(const char *const string) {
    char *new_string = strdup(string);
    if(new_string == NULL)
        log__crash(false, "%s", _OOM_MESSAGE);

    return new_string;
}

void utils__free_memory(void *memory) {
    // For future extension.
    free(memory);
}

void utils__secure_strncpy(char *destination, const char *const source, const size_t buffer_size) {
    /* https://www.cplusplus.com/reference/cstring/strncpy/:
     *   No null-character is implicitly appended at the end of destination if source is longer than num.
     *   Thus, in this case, destination shall not be considered a null terminated C string (reading it as such would overflow).
     */

    strncpy(destination, source, buffer_size - 1);
    destination[buffer_size - 1] = '\0';
}


#undef _OOM_MESSAGE
