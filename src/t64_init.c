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
#include"t64_init.h"

#include"t64_utils.h"
#include"t64_log.h"
#include"t64_conf_cmdline.h"
#include"t64_conf_file.h"
#include"t64_opmode_translate.h"
#include"t64_opmode_mktun.h"
#include"t64_opmode_rmtun.h"
#include"t64_opmode_validate_config.h"
#include"t64_opmode_print_config.h"


static void _t64f_init__check_compile_time_config(void);
static void _t64f_init__initialize_program(void);
static void _t64f_init__ignore_sigpipe(void);
static void _t64f_init__finalize_program(void);
static void _t64f_init__run_program_according_to_operation_mode(const t64ts_tundra__conf_cmdline *cmdline_configuration, const t64ts_tundra__conf_file *file_configuration);


void t64f_init__main(int argc, char **argv) {
    _t64f_init__check_compile_time_config();
    _t64f_init__initialize_program(); // Must be called first!


    t64ts_tundra__conf_cmdline *cmdline_configuration = t64fa_conf_cmdline__parse_cmdline_configuration(argc, argv);
    t64ts_tundra__conf_file *file_configuration = t64fa_conf_file__read_and_parse_configuration_file(cmdline_configuration->config_file_path);

    _t64f_init__run_program_according_to_operation_mode(cmdline_configuration, file_configuration);

    t64f_conf_file__free_parsed_configuration_file(file_configuration);
    t64f_conf_cmdline__free_cmdline_configuration(cmdline_configuration);


    _t64f_init__finalize_program(); // Must be called last!
}

static void _t64f_init__check_compile_time_config(void) {
    // Since the numeric constants contain typecasts and sizeof() cannot be (without using hacks) used within
    //  preprocessor '#if' macros, a "runtime" check is performed. However, since the condition should always come out
    //  false, it should be removed by optimizing compilers (just as this entire function).

    if(
        (T64C_TUNDRA__MAX_PACKET_SIZE < 1520) || (T64C_TUNDRA__MAX_PACKET_SIZE > 65535) ||
        (T64C_TUNDRA__MINIMUM_MTU_IPV4 < 68) || (T64C_TUNDRA__MINIMUM_MTU_IPV4 > (T64C_TUNDRA__MAX_PACKET_SIZE - 20)) ||
        (T64C_TUNDRA__MINIMUM_MTU_IPV6 < 1280) || (T64C_TUNDRA__MINIMUM_MTU_IPV6 > (T64C_TUNDRA__MAX_PACKET_SIZE - 20)) ||
        (T64C_TUNDRA__MAXIMUM_MTU_IPV4 < 68) || (T64C_TUNDRA__MAXIMUM_MTU_IPV4 > (T64C_TUNDRA__MAX_PACKET_SIZE - 20)) ||
        (T64C_TUNDRA__MAXIMUM_MTU_IPV6 < 1280) || (T64C_TUNDRA__MAXIMUM_MTU_IPV6 > (T64C_TUNDRA__MAX_PACKET_SIZE - 20)) ||
        (T64C_TUNDRA__MINIMUM_MTU_IPV4 > T64C_TUNDRA__MAXIMUM_MTU_IPV4) ||
        (T64C_TUNDRA__MINIMUM_MTU_IPV6 > T64C_TUNDRA__MAXIMUM_MTU_IPV6) ||
        (T64C_TUNDRA__MINIMUM_GENERATED_PACKET_TTL < 1) || (T64C_TUNDRA__MINIMUM_GENERATED_PACKET_TTL > 255) ||
        (T64C_TUNDRA__MAXIMUM_GENERATED_PACKET_TTL < 1) || (T64C_TUNDRA__MAXIMUM_GENERATED_PACKET_TTL > 255) ||
        (T64C_TUNDRA__MINIMUM_GENERATED_PACKET_TTL > T64C_TUNDRA__MAXIMUM_GENERATED_PACKET_TTL) ||
        (T64C_TUNDRA__MINIMUM_TIMEOUT_MILLISECONDS > T64C_TUNDRA__MAXIMUM_TIMEOUT_MILLISECONDS) ||
        (sizeof(struct iphdr) != 20) || (sizeof(struct ipv6hdr) != 40) ||
        (sizeof(t64ts_tundra__ipv6_fragment_header) != 8) || (sizeof(t64ts_tundra__external_addr_xlat_message) != 40)
    ) exit(T64C_TUNDRA__EXIT_CODE_INVALID_COMPILE_TIME_CONFIG);
}

static void _t64f_init__initialize_program(void) {
    t64f_log__initialize(); // Must be called first!

    if(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        t64f_log__crash(true, "Failed to set 'PR_SET_NO_NEW_PRIVS' to 1!");

    _t64f_init__ignore_sigpipe();

    if(setlocale(LC_ALL, "C") == NULL)
        t64f_log__crash(false, "Failed to set the program's locale to 'C'!");
}

static void _t64f_init__ignore_sigpipe(void) {
    /*
     * It is ABSOLUTELY CRUCIAL for this program to ignore 'SIGPIPE' signals, as it handles errors caused by
     * unexpectedly closed file descriptors itself, and is sometimes able to recover from them (for example,
     * the subsystem dealing with external addressing mode [t64_xlat_addr_external.c] is programmed to reconnect to
     * the configured external address translation server in case an unexpected error occurs)!
     */

    sigset_t signal_mask;
    sigemptyset(&signal_mask);

    struct sigaction signal_action;
    T64M_UTILS__MEMORY_ZERO_OUT(&signal_action, sizeof(struct sigaction));
    signal_action.sa_handler = SIG_IGN;
    signal_action.sa_mask = signal_mask;
    signal_action.sa_flags = 0;
    signal_action.sa_restorer = NULL;

    if(sigaction(SIGPIPE, &signal_action, NULL) < 0)
        t64f_log__crash(true, "Failed to make the program ignore the 'SIGPIPE' signal!");
}

static void _t64f_init__finalize_program(void) {
    t64f_log__finalize(); // Must be called last!
}

static void _t64f_init__run_program_according_to_operation_mode(const t64ts_tundra__conf_cmdline *cmdline_configuration, const t64ts_tundra__conf_file *file_configuration) {
    switch(cmdline_configuration->mode_of_operation) {
        case T64TE_TUNDRA__OPERATION_MODE_TRANSLATE:
            t64f_opmode_translate__run(cmdline_configuration, file_configuration);
            break;

        case T64TE_TUNDRA__OPERATION_MODE_MKTUN:
            t64f_opmode_mktun__run(file_configuration);
            break;

        case T64TE_TUNDRA__OPERATION_MODE_RMTUN:
            t64f_opmode_rmtun__run(file_configuration);
            break;

        case T64TE_TUNDRA__OPERATION_MODE_VALIDATE_CONFIG:
            t64f_opmode_validate_config__run();
            break;

        case T64TE_TUNDRA__OPERATION_MODE_PRINT_CONFIG:
            t64f_opmode_print_config__run(cmdline_configuration, file_configuration);
            break;

        default:
            t64f_log__crash_invalid_internal_state("Invalid mode of operation");
    }
}
