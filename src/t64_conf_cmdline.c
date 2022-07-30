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
#include"t64_conf_cmdline.h"

#include"t64_utils.h"
#include"t64_log.h"
#include"t64_conf_file.h"


#define _T64C_CONF_CMDLINE__HELP_FORMAT_STRING "\
"T64C_TUNDRA__PROGRAM_INFO_STRING"\n\
\n\
Usage: %s [OPTION]... [MODE_OF_OPERATION]\n\
\n\
Options:\n\
  -h, --"T64C_CONF_CMDLINE__LONGOPT_HELP"\n\
    Prints help and exits.\n\
  -v, --"T64C_CONF_CMDLINE__LONGOPT_VERSION"\n\
    Prints version information and exits.\n\
  -l, --"T64C_CONF_CMDLINE__LONGOPT_LICENSE"\n\
    Prints license and exits.\n\
  -c, --"T64C_CONF_CMDLINE__LONGOPT_CONFIG_FILE"=CONFIG_FILE_PATH\n\
    Specifies the file from which the program's configuration will be loaded.\n\
    DEFAULT: "T64C_TUNDRA__DEFAULT_CONFIG_FILE_PATH"\n\
    NOTE: To load the configuration from standard input, specify '-' as the config file path.\n\
  -f, --"T64C_CONF_CMDLINE__LONGOPT_IO_INHERITED_FDS"=THREAD1_IN,THREAD1_OUT[;THREAD2_IN,THREAD2_OUT]...\n\
    Specifies the file descriptors to be used in the '"T64C_CONF_FILE__IO_MODE_INHERITED_FDS"' I/O mode. Ignored otherwise.\n\
  -F, --"T64C_CONF_CMDLINE__LONGOPT_ADDRESSING_EXTERNAL_INHERITED_FDS"=THREAD1_IN,THREAD1_OUT[;THREAD2_IN,THREAD2_OUT]...\n\
    Specifies the file descriptors to be used for the '"T64C_CONF_FILE__ADDRESSING_EXTERNAL_TRANSPORT_INHERITED_FDS"' transport of the '"T64C_CONF_FILE__ADDRESSING_MODE_EXTERNAL"' addressing mode. Ignored otherwise.\n\
\n\
Modes of operation:\n\
  "T64C_CONF_CMDLINE__OPMODE_TRANSLATE"\n\
    The program will act as a stateless NAT64/CLAT translator.\n\
    This is the default mode of operation.\n\
  "T64C_CONF_CMDLINE__OPMODE_MKTUN"\n\
    Creates a persistent TUN device according to the configuration file, then exits.\n\
    Applicable only in the '"T64C_CONF_FILE__IO_MODE_TUN"' I/O mode.\n\
  "T64C_CONF_CMDLINE__OPMODE_RMTUN"\n\
    Destroys a previously created persistent TUN device according to the configuration file, then exits.\n\
    Applicable only in the '"T64C_CONF_FILE__IO_MODE_TUN"' I/O mode.\n\
  "T64C_CONF_CMDLINE__OPMODE_VALIDATE_CONFIG"\n\
    Tries to configure the program and prints an informational message if it succeeds, then exits.\n\
  "T64C_CONF_CMDLINE__OPMODE_PRINT_CONFIG"\n\
    Prints the program's configuration in a human-readable format, then exits.\n\
\n\
"

#define _T64C_CONF_CMDLINE__LICENSE_STRING "\
Copyright (c) 2022 Vít Labuda. All rights reserved.\n\
\n\
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the\n\
following conditions are met:\n\
 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following\n\
    disclaimer.\n\
 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the\n\
    following disclaimer in the documentation and/or other materials provided with the distribution.\n\
 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote\n\
    products derived from this software without specific prior written permission.\n\
\n\
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS \"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES,\n\
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE\n\
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,\n\
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR\n\
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,\n\
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE\n\
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n\
\n\
"


static void _t64f_conf_cmdline__parse_cmdline_options(t64ts_tundra__conf_cmdline *cmdline_configuration, int argc, char **argv);
static void _t64f_conf_cmdline__parse_cmdline_arguments(t64ts_tundra__conf_cmdline *cmdline_configuration, int argc, char **argv);
static noreturn void _t64f_conf_cmdline__print_help_and_exit(const char *argv_0);
static noreturn void _t64f_conf_cmdline__print_version_and_exit(void);
static noreturn void _t64f_conf_cmdline__print_license_and_exit(void);
static t64te_tundra__operation_mode _t64f_conf_cmdline__determine_operation_mode_from_string(const char *mode_of_operation_string);


t64ts_tundra__conf_cmdline *t64fa_conf_cmdline__parse_cmdline_configuration(int argc, char **argv) {
    if(argc < 1 || argv[0] == NULL)
        t64f_log__crash(false, "argv[0] does not exist or is NULL!");

    t64ts_tundra__conf_cmdline *cmdline_configuration = t64fa_utils__allocate_zeroed_out_memory(1, sizeof(t64ts_tundra__conf_cmdline));
    cmdline_configuration->config_file_path = NULL;
    cmdline_configuration->io_inherited_fds = NULL;
    cmdline_configuration->addressing_external_inherited_fds = NULL;
    cmdline_configuration->mode_of_operation = T64TE_TUNDRA__OPERATION_MODE_TRANSLATE;

    _t64f_conf_cmdline__parse_cmdline_options(cmdline_configuration, argc, argv);

    _t64f_conf_cmdline__parse_cmdline_arguments(cmdline_configuration, argc, argv);

    if(cmdline_configuration->config_file_path == NULL)
        cmdline_configuration->config_file_path = t64fa_utils__duplicate_string(T64C_TUNDRA__DEFAULT_CONFIG_FILE_PATH);

    return cmdline_configuration;
}

static void _t64f_conf_cmdline__parse_cmdline_options(t64ts_tundra__conf_cmdline *cmdline_configuration, int argc, char **argv) {
    static const char *option_string = "hvlc:f:F:";
    static const struct option long_options[] = {
            {T64C_CONF_CMDLINE__LONGOPT_HELP,                               no_argument,        NULL, T64C_CONF_CMDLINE__SHORTOPT_HELP},
            {T64C_CONF_CMDLINE__LONGOPT_VERSION,                            no_argument,        NULL, T64C_CONF_CMDLINE__SHORTOPT_VERSION},
            {T64C_CONF_CMDLINE__LONGOPT_LICENSE,                            no_argument,        NULL, T64C_CONF_CMDLINE__SHORTOPT_LICENSE},
            {T64C_CONF_CMDLINE__LONGOPT_CONFIG_FILE,                        required_argument,  NULL, T64C_CONF_CMDLINE__SHORTOPT_CONFIG_FILE},
            {T64C_CONF_CMDLINE__LONGOPT_IO_INHERITED_FDS,                   required_argument,  NULL, T64C_CONF_CMDLINE__SHORTOPT_IO_INHERITED_FDS},
            {T64C_CONF_CMDLINE__LONGOPT_ADDRESSING_EXTERNAL_INHERITED_FDS,  required_argument,  NULL, T64C_CONF_CMDLINE__SHORTOPT_ADDRESSING_EXTERNAL_INHERITED_FDS},
            {NULL,                                                          no_argument,        NULL, 0},
    };

    int getopt_option;
    while ((getopt_option = getopt_long(argc, argv, option_string, long_options, NULL)) > 0) {
        switch (getopt_option) {
            case T64C_CONF_CMDLINE__SHORTOPT_HELP:
                _t64f_conf_cmdline__print_help_and_exit(argv[0]);

            case T64C_CONF_CMDLINE__SHORTOPT_VERSION:
                _t64f_conf_cmdline__print_version_and_exit();

            case T64C_CONF_CMDLINE__SHORTOPT_LICENSE:
                _t64f_conf_cmdline__print_license_and_exit();

            case T64C_CONF_CMDLINE__SHORTOPT_CONFIG_FILE:
                if(cmdline_configuration->config_file_path != NULL)
                    t64f_log__crash(false, "The config file path has already been set: %s", cmdline_configuration->config_file_path);
                cmdline_configuration->config_file_path = t64fa_utils__duplicate_string(optarg);
                break;

            case T64C_CONF_CMDLINE__SHORTOPT_IO_INHERITED_FDS:
                if(cmdline_configuration->io_inherited_fds != NULL)
                    t64f_log__crash(false, "The list of inherited file descriptors for packet I/O has already been set: %s", cmdline_configuration->io_inherited_fds);
                cmdline_configuration->io_inherited_fds = t64fa_utils__duplicate_string(optarg);
                break;

            case T64C_CONF_CMDLINE__SHORTOPT_ADDRESSING_EXTERNAL_INHERITED_FDS:
                if(cmdline_configuration->addressing_external_inherited_fds != NULL)
                    t64f_log__crash(false, "The list of inherited file descriptors for external address translation has already been set: %s", cmdline_configuration->addressing_external_inherited_fds);
                cmdline_configuration->addressing_external_inherited_fds = t64fa_utils__duplicate_string(optarg);
                break;

            case '?':
                // getopt_long() prints an informative error message automatically
                t64f_log__crash(false, "An invalid command-line option has been passed to the program - see '--"T64C_CONF_CMDLINE__LONGOPT_HELP"' for more information!");

            default:
                t64f_log__crash(false, "An unknown error occurred while parsing command-line options!");
        }
    }
}

static void _t64f_conf_cmdline__parse_cmdline_arguments(t64ts_tundra__conf_cmdline *cmdline_configuration, int argc, char **argv) {
    const int argument_count = argc - optind;
    switch (argument_count) {
        case 0:
            break; // cmdline_options->mode_of_operation has already been set to the default value, T64TE_OPERATION_MODE_TRANSLATE

        case 1:
            cmdline_configuration->mode_of_operation = _t64f_conf_cmdline__determine_operation_mode_from_string(argv[optind]);
            break;

        default:
            t64f_log__crash(false, "Too many command-line arguments (%d)!", argument_count);
    }
}

static noreturn void _t64f_conf_cmdline__print_help_and_exit(const char *argv_0) {
    printf(_T64C_CONF_CMDLINE__HELP_FORMAT_STRING, argv_0);
    fflush(stdout);

    exit(T64C_TUNDRA__EXIT_CODE_SUCCESS);
}

static noreturn void _t64f_conf_cmdline__print_version_and_exit(void) {
    printf("%s\n", T64C_TUNDRA__PROGRAM_INFO_STRING);
    fflush(stdout);

    exit(T64C_TUNDRA__EXIT_CODE_SUCCESS);
}

static noreturn void _t64f_conf_cmdline__print_license_and_exit(void) {
    printf("%s", _T64C_CONF_CMDLINE__LICENSE_STRING);
    fflush(stdout);

    exit(T64C_TUNDRA__EXIT_CODE_SUCCESS);
}

static t64te_tundra__operation_mode _t64f_conf_cmdline__determine_operation_mode_from_string(const char *mode_of_operation_string) {
    if(T64M_UTILS__STRINGS_EQUAL(mode_of_operation_string, T64C_CONF_CMDLINE__OPMODE_TRANSLATE))
        return T64TE_TUNDRA__OPERATION_MODE_TRANSLATE;

    if(T64M_UTILS__STRINGS_EQUAL(mode_of_operation_string, T64C_CONF_CMDLINE__OPMODE_MKTUN))
        return T64TE_TUNDRA__OPERATION_MODE_MKTUN;

    if(T64M_UTILS__STRINGS_EQUAL(mode_of_operation_string, T64C_CONF_CMDLINE__OPMODE_RMTUN))
        return T64TE_TUNDRA__OPERATION_MODE_RMTUN;

    if(T64M_UTILS__STRINGS_EQUAL(mode_of_operation_string, T64C_CONF_CMDLINE__OPMODE_VALIDATE_CONFIG))
        return T64TE_TUNDRA__OPERATION_MODE_VALIDATE_CONFIG;

    if(T64M_UTILS__STRINGS_EQUAL(mode_of_operation_string, T64C_CONF_CMDLINE__OPMODE_PRINT_CONFIG))
        return T64TE_TUNDRA__OPERATION_MODE_PRINT_CONFIG;

    t64f_log__crash(false, "Invalid mode of operation string: %s", mode_of_operation_string);
}

void t64f_conf_cmdline__free_cmdline_configuration(t64ts_tundra__conf_cmdline *cmdline_configuration) {
    t64f_utils__free_memory(cmdline_configuration->config_file_path);
    if(cmdline_configuration->io_inherited_fds != NULL)
        t64f_utils__free_memory(cmdline_configuration->io_inherited_fds);
    if(cmdline_configuration->addressing_external_inherited_fds != NULL)
        t64f_utils__free_memory(cmdline_configuration->addressing_external_inherited_fds);

    t64f_utils__free_memory(cmdline_configuration);
}


#undef _T64C_CONF_CMDLINE__HELP_FORMAT_STRING
#undef _T64C_CONF_CMDLINE__LICENSE_STRING
