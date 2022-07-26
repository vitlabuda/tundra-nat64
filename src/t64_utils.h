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

#ifndef _T64I_UTILS_H
#define _T64I_UTILS_H

#include"t64_tundra.h"


#define T64M_UTILS__STRINGS_EQUAL(str1, str2) (strcmp((str1), (str2)) == 0)
#define T64M_UTILS__STRINGS_EQUAL_CI(str1, str2) (strcasecmp((str1), (str2)) == 0)
#define T64M_UTILS__STRING_EMPTY(str) (*(str) == '\0')

#define T64M_UTILS__MEMORY_EQUAL(ptr1, ptr2, n) (memcmp((ptr1), (ptr2), (n)) == 0)
#define T64M_UTILS__MEMORY_ZERO_OUT(memory, n) (memset((memory), 0, (n)))

#define T64MM_UTILS__MINIMUM(num1, num2) (((num1) > (num2)) ? (num2) : (num1))
#define T64MM_UTILS__MAXIMUM(num1, num2) (((num1) > (num2)) ? (num1) : (num2))


extern void *t64fa_utils__allocate_zeroed_out_memory(const size_t n, const size_t item_size);
extern void *t64fa_utils__reallocate_memory(void *old_memory, const size_t n, const size_t item_size);
extern char *t64fa_utils__duplicate_string(const char *string);
extern void t64f_utils__free_memory(void *memory);
extern void t64f_utils__secure_strncpy(char *destination, const char *source, const size_t buffer_size);
extern bool t64f_utils__secure_memcpy(void *destination, const void *source, const size_t copied_size, const size_t max_size);
extern size_t t64f_utils__secure_memcpy_with_size_clamping(void *destination, const void *source, size_t copied_size, const size_t max_size);


#endif // _T64I_UTILS_H
