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
#include"log.h"


static pthread_mutex_t _log_output_mutex;


static void _print_log_message(const size_t thread_id, const bool print_errno, const char *const banner, const char *format, va_list argument_list);


void log__initialize(void) {
    if(pthread_mutex_init(&_log_output_mutex, NULL) != 0)
        exit(TUNDRA__EXIT_MUTEX_FAILURE);
}

void log__finalize(void) {
    if(pthread_mutex_destroy(&_log_output_mutex) != 0)
        exit(TUNDRA__EXIT_MUTEX_FAILURE);
}

noreturn void log__crash(const bool print_errno, const char *format, ...) {
    va_list argument_list;
    va_start(argument_list, format);

    _print_log_message(0, print_errno, LOG__BANNER_CRASH, format, argument_list);

    va_end(argument_list);

    exit(TUNDRA__EXIT_CRASH);
}

noreturn void log__crash_invalid_internal_state(const char *const state_description) {
    log__crash(false, "The program's internal state is invalid (%s)!", state_description);
}

noreturn void log__thread_crash(const size_t thread_id, const bool print_errno, const char *format, ...) {
    va_list argument_list;
    va_start(argument_list, format);

    _print_log_message(thread_id, print_errno, LOG__BANNER_CRASH, format, argument_list);

    va_end(argument_list);

    pthread_exit(NULL);
}

noreturn void log__thread_crash_invalid_internal_state(const size_t thread_id, const char *const state_description) {
    log__thread_crash(thread_id, false, "A thread's internal state is invalid (%s)!", state_description);
}

void log__info(const char *format, ...) {
    va_list argument_list;
    va_start(argument_list, format);

    _print_log_message(0, false, LOG__BANNER_INFO, format, argument_list);

    va_end(argument_list);
}

void log__thread_info(const size_t thread_id, const char *format, ...) {
    va_list argument_list;
    va_start(argument_list, format);

    _print_log_message(thread_id, false, LOG__BANNER_INFO, format, argument_list);

    va_end(argument_list);
}

static void _print_log_message(const size_t thread_id, const bool print_errno, const char *const banner, const char *format, va_list argument_list) {
    pthread_mutex_lock(&_log_output_mutex);

    if(thread_id == 0) // Main thread
        fprintf(stderr, "[%s] ", banner);
    else
        fprintf(stderr, "[T%zu :: %s] ", thread_id, banner);

    vfprintf(stderr, format, argument_list);
    if(print_errno) {
        // strerror_r() is problematic as it has two versions - GNU and XSI, and the former is not available everywhere
        //  (namely, OpenWRT does not seem to support it).
        // However, since this code always runs in locked context and this is the only place in this program where it
        //  is used, the thread-unsafe strerror() function can be used.
        fprintf(stderr, " [Errno %d: %s]", errno, strerror(errno));
    }

    fputc('\n', stderr);
    fflush(stderr);

    pthread_mutex_unlock(&_log_output_mutex);
}
