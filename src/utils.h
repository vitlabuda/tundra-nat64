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


// If a macro's name ends with 'UNSAFE', it means that at least one of its arguments is used more than once in its
//  expansion/definition.
// Therefore, arguments "passed" to these macros must always be expressions which cannot possibly have any side
//  effects - while simple literals, constants or variables are fine, anything more sophisticated may not be OK.

#define UTILS__STR_EQ(str1, str2) (strcmp((str1), (str2)) == 0)
#define UTILS__STR_EQ_CI(str1, str2) (strcasecmp((str1), (str2)) == 0)
#define UTILS__STR_EMPTY(str) (*(str) == '\0')

#define UTILS__MEM_EQ(ptr1, ptr2, n) (memcmp((ptr1), (ptr2), (n)) == 0)
#define UTILS__MEM_ZERO_OUT(memory, n) (memset((memory), 0, (n)))

#define UTILS__MINIMUM_UNSAFE(num1, num2) (((num1) > (num2)) ? (num2) : (num1))
#define UTILS__MAXIMUM_UNSAFE(num1, num2) (((num1) > (num2)) ? (num1) : (num2))


extern void *utils__alloc_zeroed_out_memory(const size_t n, const size_t item_size);
extern void *utils__realloc_memory(void *old_memory, const size_t n, const size_t item_size);
extern char *utils__duplicate_string(const char *const string);
extern void utils__free_memory(void *memory);
extern void utils__secure_strncpy(char *destination, const char *const source, const size_t buffer_size);
