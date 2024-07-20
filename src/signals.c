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
#include"signals.h"

#include"utils.h"
#include"log.h"


#define _MAIN_THREAD_TERM_SIGNAL_MESSAGE "["LOG__BANNER_SIGNAL"] A signal was received - the translator will shut down soon.\n"


static __thread volatile sig_atomic_t _term_signal_caught_in_thread = 0;


static void _term_signal_handler(__attribute__((unused)) int sig, siginfo_t *info, __attribute__((unused)) void *ucontext);
static void _ignore_signal(const int signal_number);
static void _set_signal_handler(const int signal_number, void (*signal_handler)(int, siginfo_t *, void *));
static sigset_t _generate_empty_signal_mask(void);


void signals__initialize(void) {
    /*
     * It is ABSOLUTELY CRUCIAL for this program to ignore 'SIGPIPE' signals, as it handles errors caused by
     * unexpectedly closed file descriptors itself, and is sometimes able to recover from them (for example,
     * the subsystem dealing with external addressing mode [xlat_addr_external.c] is programmed to reconnect to
     * the configured external address translation server in case an unexpected error occurs)!
     */
    _ignore_signal(SIGPIPE);

    // Since signal handlers are shared among all threads, make sure 'SIGNALS__XLAT_THREAD_TERM_SIGNAL'
    //  is configured to be handled! (as of now, the constant is an alias for 'SIGTERM')
    _set_signal_handler(SIGTERM, _term_signal_handler);
    _set_signal_handler(SIGINT, _term_signal_handler);
    _set_signal_handler(SIGHUP, _term_signal_handler);
}

bool signals__should_this_thread_keep_running(void) {
    return (bool) (!_term_signal_caught_in_thread);
}

static void _term_signal_handler(__attribute__((unused)) int sig, siginfo_t *info, __attribute__((unused)) void *ucontext) {
    pid_t process_pid = getpid();
    pid_t this_thread_pid = (pid_t) syscall(SYS_gettid);  // The gettid() wrapper function is not available on some platforms, namely on older versions of OpenWRT

    if(process_pid == this_thread_pid) {  // If this function is being run on the main thread
        _term_signal_caught_in_thread = 1;

        // Here, write() is used instead of fprintf(), which cannot be safely called within signal handlers, and since
        //  ignoring the return value of fprintf(stderr) is common and absolutely OK, we can ignore it here as well.
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wunused-result"
        (void) write(STDERR_FILENO, _MAIN_THREAD_TERM_SIGNAL_MESSAGE, strlen(_MAIN_THREAD_TERM_SIGNAL_MESSAGE));
        #pragma GCC diagnostic pop

    } else if(info->si_pid == process_pid) {  // If the signal has been sent from within this process
        _term_signal_caught_in_thread = 1;
    }
}

static void _ignore_signal(const int signal_number) {
    struct sigaction signal_action;
    UTILS__MEM_ZERO_OUT(&signal_action, sizeof(struct sigaction));
    signal_action.sa_handler = SIG_IGN;
    signal_action.sa_mask = _generate_empty_signal_mask();
    signal_action.sa_flags = 0;
    signal_action.sa_restorer = NULL;

    if(sigaction(signal_number, &signal_action, NULL) < 0)
        log__crash(true, "Failed to ignore the signal with number %d!", signal_number);
}

static void _set_signal_handler(const int signal_number, void (*signal_handler)(int, siginfo_t *, void *)) {
    struct sigaction signal_action;
    UTILS__MEM_ZERO_OUT(&signal_action, sizeof(struct sigaction));
    signal_action.sa_sigaction = signal_handler;
    signal_action.sa_mask = _generate_empty_signal_mask();
    signal_action.sa_flags = SA_SIGINFO;
    signal_action.sa_restorer = NULL;

    if(sigaction(signal_number, &signal_action, NULL) < 0)
        log__crash(true, "Failed to set a handler for the signal with number %d!", signal_number);
}

static sigset_t _generate_empty_signal_mask(void) {
    sigset_t signal_mask;
    UTILS__MEM_ZERO_OUT(&signal_mask, sizeof(sigset_t));
    sigemptyset(&signal_mask);

    return signal_mask;
}


#undef _MAIN_THREAD_TERM_SIGNAL_MESSAGE
