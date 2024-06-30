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
#include"init.h"

#include"log.h"
#include"signals.h"
#include"conf_cmdline.h"
#include"conf_file.h"
#include"opmode_translate.h"
#include"opmode_mktun.h"
#include"opmode_rmtun.h"
#include"opmode_validate_config.h"


static void _check_compile_time_config(void);
static void _initialize_program(void);
static void _finalize_program(void);
static void _run_operation_mode_handler(const tundra__conf_cmdline *const cmdline_config, const tundra__conf_file *const file_config);


void init__run_program(int argc, char **argv) {
    _check_compile_time_config();
    _initialize_program(); // Must be called first!


    tundra__conf_cmdline *const cmdline_config = conf_cmdline__parse_cmdline_config(argc, argv);
    tundra__conf_file *const file_config = conf_file__read_and_parse_config_file(cmdline_config->config_file_path);

    _run_operation_mode_handler(cmdline_config, file_config);

    conf_file__free_parsed_config_file(file_config);
    conf_cmdline__free_cmdline_config(cmdline_config);


    _finalize_program(); // Must be called last!
}

static void _check_compile_time_config(void) {
    // Since the numeric constants contain typecasts and sizeof() cannot be (without using hacks) used within
    //  preprocessor '#if' macros, a "runtime" check is performed. However, since the condition should always come out
    //  false, it should be removed by optimizing compilers (just as this entire function).

    if(
        (TUNDRA__MAX_PACKET_SIZE < 1520) || (TUNDRA__MAX_PACKET_SIZE > 65535) ||
        (TUNDRA__MIN_MTU_IPV4 < 96) || (TUNDRA__MIN_MTU_IPV4 > (TUNDRA__MAX_PACKET_SIZE - 20)) ||
        (TUNDRA__MIN_MTU_IPV6 < 1280) || (TUNDRA__MIN_MTU_IPV6 > (TUNDRA__MAX_PACKET_SIZE - 20)) ||
        (TUNDRA__MAX_MTU_IPV4 < 96) || (TUNDRA__MAX_MTU_IPV4 > (TUNDRA__MAX_PACKET_SIZE - 20)) ||
        (TUNDRA__MAX_MTU_IPV6 < 1280) || (TUNDRA__MAX_MTU_IPV6 > (TUNDRA__MAX_PACKET_SIZE - 20)) ||
        (TUNDRA__MIN_MTU_IPV4 > TUNDRA__MAX_MTU_IPV4) ||
        (TUNDRA__MIN_MTU_IPV6 > TUNDRA__MAX_MTU_IPV6) ||
        (TUNDRA__MIN_GENERATED_PACKET_TTL < 1) || (TUNDRA__MIN_GENERATED_PACKET_TTL > 255) ||
        (TUNDRA__MAX_GENERATED_PACKET_TTL < 1) || (TUNDRA__MAX_GENERATED_PACKET_TTL > 255) ||
        (TUNDRA__MIN_GENERATED_PACKET_TTL > TUNDRA__MAX_GENERATED_PACKET_TTL) ||
        (TUNDRA__MIN_TIMEOUT_MILLISECONDS > TUNDRA__MAX_TIMEOUT_MILLISECONDS) ||
        (sizeof(struct iphdr) != 20) || (sizeof(struct ipv6hdr) != 40) ||
        (sizeof(tundra__ipv6_frag_header) != 8) || (sizeof(tundra__external_addr_xlat_message) != 40)
    ) exit(TUNDRA__EXIT_INVALID_COMPILE_TIME_CONFIG);
}

static void _initialize_program(void) {
    log__initialize(); // Must be called first!

    signals__initialize();

    if(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        log__crash(true, "Failed to set 'PR_SET_NO_NEW_PRIVS' to 1!");

    if(setlocale(LC_ALL, "C") == NULL)
        log__crash(false, "Failed to set the program's locale to 'C'!");
}

static void _finalize_program(void) {
    log__finalize(); // Must be called last!
}

static void _run_operation_mode_handler(const tundra__conf_cmdline *const cmdline_config, const tundra__conf_file *const file_config) {
    switch(cmdline_config->mode_of_operation) {
        case TUNDRA__OPERATION_MODE_TRANSLATE:
            opmode_translate__run(cmdline_config, file_config);
            break;

        case TUNDRA__OPERATION_MODE_MKTUN:
            opmode_mktun__run(file_config);
            break;

        case TUNDRA__OPERATION_MODE_RMTUN:
            opmode_rmtun__run(file_config);
            break;

        case TUNDRA__OPERATION_MODE_VALIDATE_CONFIG:
            opmode_validate_config__run();
            break;

        default:
            log__crash_invalid_internal_state("Invalid mode of operation");
    }
}
