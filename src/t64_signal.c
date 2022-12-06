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
#include"t64_signal.h"

#include"t64_utils.h"
#include"t64_log.h"


#define _T64C_SIGNAL__MAIN_THREAD_TERMINATION_SIGNAL_MESSAGE "[T0 :: "T64C_LOG__CATEGORY_BANNER_SIGNAL"] A signal was received - the translator will shut down soon.\n"


static __thread volatile sig_atomic_t _t64gt_signal__termination_signal_caught = 0;


static void _t64f_signal__termination_signal_handler_function(__attribute__((unused)) int sig, siginfo_t *info, __attribute__((unused)) void *ucontext);
static void _t64f_signal__ignore_signal(const int signal_number);
static void _t64f_signal__set_signal_handler(const int signal_number, void (*signal_handler)(int, siginfo_t *, void *));
static sigset_t _t64f_signal__generate_empty_signal_mask(void);


void t64f_signal__initialize(void) {
    /*
     * It is ABSOLUTELY CRUCIAL for this program to ignore 'SIGPIPE' signals, as it handles errors caused by
     * unexpectedly closed file descriptors itself, and is sometimes able to recover from them (for example,
     * the subsystem dealing with external addressing mode [t64_xlat_addr_external.c] is programmed to reconnect to
     * the configured external address translation server in case an unexpected error occurs)!
     */
    _t64f_signal__ignore_signal(SIGPIPE);

    // Since signal handlers are shared among all threads, make sure 'T64C_SIGNAL__TRANSLATOR_THREAD_TERMINATION_SIGNAL'
    //  is configured to be handled! (as of now, the constant is an alias for 'SIGTERM')
    _t64f_signal__set_signal_handler(SIGTERM, _t64f_signal__termination_signal_handler_function);
    _t64f_signal__set_signal_handler(SIGINT, _t64f_signal__termination_signal_handler_function);
    _t64f_signal__set_signal_handler(SIGHUP, _t64f_signal__termination_signal_handler_function);
}

bool t64f_signal__should_this_thread_continue_running(void) {
    return (bool) (!_t64gt_signal__termination_signal_caught);
}

static void _t64f_signal__termination_signal_handler_function(__attribute__((unused)) int sig, siginfo_t *info, __attribute__((unused)) void *ucontext) {
    pid_t process_pid = getpid();
    pid_t this_thread_pid = (pid_t) syscall(SYS_gettid);  // The gettid() wrapper function is not available on some platforms, namely on older versions of OpenWRT

    if(process_pid == this_thread_pid) {  // If this function is being run on the main thread
        _t64gt_signal__termination_signal_caught = 1;
        write(STDERR_FILENO, _T64C_SIGNAL__MAIN_THREAD_TERMINATION_SIGNAL_MESSAGE, strlen(_T64C_SIGNAL__MAIN_THREAD_TERMINATION_SIGNAL_MESSAGE));

    } else if(info->si_pid == process_pid) {  // If the signal has been sent from within this process
        _t64gt_signal__termination_signal_caught = 1;

    }
}

static void _t64f_signal__ignore_signal(const int signal_number) {
    struct sigaction signal_action;
    T64M_UTILS__MEMORY_ZERO_OUT(&signal_action, sizeof(struct sigaction));
    signal_action.sa_handler = SIG_IGN;
    signal_action.sa_mask = _t64f_signal__generate_empty_signal_mask();
    signal_action.sa_flags = 0;
    signal_action.sa_restorer = NULL;

    if(sigaction(signal_number, &signal_action, NULL) < 0)
        t64f_log__crash(true, "Failed to ignore the signal with number %d!", signal_number);
}

static void _t64f_signal__set_signal_handler(const int signal_number, void (*signal_handler)(int, siginfo_t *, void *)) {
    struct sigaction signal_action;
    T64M_UTILS__MEMORY_ZERO_OUT(&signal_action, sizeof(struct sigaction));
    signal_action.sa_sigaction = signal_handler;
    signal_action.sa_mask = _t64f_signal__generate_empty_signal_mask();
    signal_action.sa_flags = SA_SIGINFO;
    signal_action.sa_restorer = NULL;

    if(sigaction(signal_number, &signal_action, NULL) < 0)
        t64f_log__crash(true, "Failed to set a handler for the signal with number %d!", signal_number);
}

static sigset_t _t64f_signal__generate_empty_signal_mask(void) {
    sigset_t signal_mask;
    T64M_UTILS__MEMORY_ZERO_OUT(&signal_mask, sizeof(sigset_t));
    sigemptyset(&signal_mask);

    return signal_mask;
}


#undef _T64C_SIGNAL__MAIN_THREAD_TERMINATION_SIGNAL_MESSAGE
