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


#define _T64C_SIGNAL__SIGNAL_RECEIVED_MESSAGE "[T0 :: "T64C_LOG__CATEGORY_BANNER_SIGNAL"] A signal was received - the translator will shut down soon.\n"


static volatile sig_atomic_t _t64g_signal__should_translator_continue_running = 1;


static void _t64f_signal__signal_handler_function(int signum);


sig_atomic_t t64f_signal__should_translator_continue_running(void) {
    return _t64g_signal__should_translator_continue_running;
}

void t64f_signal__set_signal_handlers(void) {
    sigset_t signal_mask;
    sigemptyset(&signal_mask);

    struct sigaction signal_action;
    T64M_UTILS__MEMORY_CLEAR(&signal_action, 1, sizeof(struct sigaction));
    signal_action.sa_handler = _t64f_signal__signal_handler_function;
    signal_action.sa_mask = signal_mask;
    signal_action.sa_flags = 0;
    signal_action.sa_restorer = NULL;

    if(
        (sigaction(SIGTERM, &signal_action, NULL) < 0) ||
        (sigaction(SIGINT, &signal_action, NULL) < 0) ||
        (sigaction(SIGHUP, &signal_action, NULL) < 0)
    ) t64f_log__crash(true, "Failed to set the program's signal handlers!");
}

static void _t64f_signal__signal_handler_function(int signum) {
    _t64g_signal__should_translator_continue_running = 0;

    // t64f_log_info() cannot be called, as it uses async-signal-unsafe functions.
    write(STDERR_FILENO, _T64C_SIGNAL__SIGNAL_RECEIVED_MESSAGE, strlen(_T64C_SIGNAL__SIGNAL_RECEIVED_MESSAGE));
}


#undef _T64C_SIGNAL__SIGNAL_RECEIVED_MESSAGE
