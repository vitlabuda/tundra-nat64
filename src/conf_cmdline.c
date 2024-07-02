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
#include"conf_cmdline.h"

#include"utils.h"
#include"log.h"


#define _HELP_FORMAT_STRING "\
"TUNDRA__PROGRAM_INFO_STRING"\n\
\n\
Usage: %s [OPTION]... [MODE_OF_OPERATION]\n\
\n\
Options:\n\
  -h, --help\n\
    Prints help and exits.\n\
  -v, --version\n\
    Prints version information and exits.\n\
  -l, --license\n\
    Prints license and exits.\n\
  -c, --config-file=CONFIG_FILE_PATH\n\
    Specifies the file from which the program's configuration will be loaded.\n\
    DEFAULT: "TUNDRA__DEFAULT_CONFIG_FILE_PATH"\n\
    NOTE: To load the configuration from standard input, specify '-' as the config file path.\n\
  -f, --io-inherited-fds=THREAD1_IN,THREAD1_OUT[;THREAD2_IN,THREAD2_OUT]...\n\
    Specifies the file descriptors to be used in the 'inherited-fds' I/O mode. Ignored otherwise.\n\
  -F, --addressing-external-inherited-fds=THREAD1_IN,THREAD1_OUT[;THREAD2_IN,THREAD2_OUT]...\n\
    Specifies the file descriptors to be used for the 'inherited-fds' transport of the 'external' addressing mode. Ignored otherwise.\n\
\n\
Modes of operation:\n\
  translate\n\
    The program will act as a stateless NAT64/CLAT translator.\n\
    This is the default mode of operation.\n\
  mktun\n\
    Creates a persistent TUN device according to the configuration file, then exits.\n\
    Applicable only in the 'tun' I/O mode.\n\
  rmtun\n\
    Destroys a previously created persistent TUN device according to the configuration file, then exits.\n\
    Applicable only in the 'tun' I/O mode.\n\
  validate-config\n\
    Tries to configure the program and prints an informational message if it succeeds, then exits.\n\
\n\
"

#define _LICENSE_STRING "\
Copyright (c) 2024 Vit Labuda. All rights reserved.\n\
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
"


static void _parse_cmdline_opts(tundra__conf_cmdline *const cmdline_config, int argc, char **argv);
static void _parse_cmdline_args(tundra__conf_cmdline *const cmdline_config, int argc, char **argv);
static noreturn void _print_help_and_exit(const char *const argv_0);
static noreturn void _print_version_and_exit(void);
static noreturn void _print_license_and_exit(void);
static tundra__operation_mode _get_operation_mode_from_string(const char *const operation_mode_string);


tundra__conf_cmdline *conf_cmdline__parse_cmdline_config(int argc, char **argv) {
    if(argc < 1 || argv[0] == NULL)
        log__crash(false, "argv[0] does not exist or is NULL!");

    tundra__conf_cmdline *const cmdline_config = utils__alloc_zeroed_out_memory(1, sizeof(tundra__conf_cmdline));
    cmdline_config->config_file_path = NULL;
    cmdline_config->io_inherited_fds = NULL;
    cmdline_config->addressing_external_inherited_fds = NULL;
    cmdline_config->mode_of_operation = TUNDRA__OPERATION_MODE_TRANSLATE;

    _parse_cmdline_opts(cmdline_config, argc, argv);
    _parse_cmdline_args(cmdline_config, argc, argv);

    if(cmdline_config->config_file_path == NULL)
        cmdline_config->config_file_path = utils__duplicate_string(TUNDRA__DEFAULT_CONFIG_FILE_PATH);

    return cmdline_config;
}

static void _parse_cmdline_opts(tundra__conf_cmdline *const cmdline_config, int argc, char **argv) {
    static const char *const option_string = "hvlc:f:F:";
    static const struct option long_options[] = {
            {"help",                              no_argument,       NULL, 'h'},
            {"version",                           no_argument,       NULL, 'v'},
            {"license",                           no_argument,       NULL, 'l'},
            {"config-file",                       required_argument, NULL, 'c'},
            {"io-inherited-fds",                  required_argument, NULL, 'f'},
            {"addressing-external-inherited-fds", required_argument, NULL, 'F'},
            {NULL,                                no_argument,       NULL, 0},
    };

    int getopt_option;
    while ((getopt_option = getopt_long(argc, argv, option_string, long_options, NULL)) > 0) {
        switch (getopt_option) {
            case 'h':
                _print_help_and_exit(argv[0]);

            case 'v':
                _print_version_and_exit();

            case 'l':
                _print_license_and_exit();

            case 'c':
                if(cmdline_config->config_file_path != NULL)
                    log__crash(false, "The config file path has already been set: %s", cmdline_config->config_file_path);
                cmdline_config->config_file_path = utils__duplicate_string(optarg);
                break;

            case 'f':
                if(cmdline_config->io_inherited_fds != NULL)
                    log__crash(false, "The list of inherited file descriptors for packet I/O has already been set: %s", cmdline_config->io_inherited_fds);
                cmdline_config->io_inherited_fds = utils__duplicate_string(optarg);
                break;

            case 'F':
                if(cmdline_config->addressing_external_inherited_fds != NULL)
                    log__crash(false, "The list of inherited file descriptors for external address translation has already been set: %s", cmdline_config->addressing_external_inherited_fds);
                cmdline_config->addressing_external_inherited_fds = utils__duplicate_string(optarg);
                break;

            case '?':
                // getopt_long() prints an informative error message automatically
                log__crash(false, "An invalid command-line option has been passed to the program - see '--help' for more information!");

            default:
                log__crash(false, "An unknown error occurred while parsing command-line options!");
        }
    }
}

static void _parse_cmdline_args(tundra__conf_cmdline *const cmdline_config, int argc, char **argv) {
    const int argument_count = argc - optind;
    switch (argument_count) {
        case 0:
            break; // cmdline_options->mode_of_operation has already been set to the default value, TUNDRA__OPERATION_MODE_TRANSLATE

        case 1:
            cmdline_config->mode_of_operation = _get_operation_mode_from_string(argv[optind]);
            break;

        default:
            log__crash(false, "Too many command-line arguments (%d)!", argument_count);
    }
}

static noreturn void _print_help_and_exit(const char *const argv_0) {
    printf(_HELP_FORMAT_STRING, argv_0);
    fflush(stdout);

    exit(TUNDRA__EXIT_SUCCESS);
}

static noreturn void _print_version_and_exit(void) {
    puts(TUNDRA__PROGRAM_INFO_STRING);
    fflush(stdout);

    exit(TUNDRA__EXIT_SUCCESS);
}

static noreturn void _print_license_and_exit(void) {
    puts(_LICENSE_STRING);
    fflush(stdout);

    exit(TUNDRA__EXIT_SUCCESS);
}

static tundra__operation_mode _get_operation_mode_from_string(const char *const operation_mode_string) {
    if(UTILS__STR_EQ(operation_mode_string, "translate"))
        return TUNDRA__OPERATION_MODE_TRANSLATE;

    if(UTILS__STR_EQ(operation_mode_string, "mktun"))
        return TUNDRA__OPERATION_MODE_MKTUN;

    if(UTILS__STR_EQ(operation_mode_string, "rmtun"))
        return TUNDRA__OPERATION_MODE_RMTUN;

    if(UTILS__STR_EQ(operation_mode_string, "validate-config"))
        return TUNDRA__OPERATION_MODE_VALIDATE_CONFIG;

    log__crash(false, "Invalid mode of operation string: %s", operation_mode_string);
}

void conf_cmdline__free_cmdline_config(tundra__conf_cmdline *const cmdline_config) {
    utils__free_memory(cmdline_config->config_file_path);

    if(cmdline_config->io_inherited_fds != NULL)
        utils__free_memory(cmdline_config->io_inherited_fds);

    if(cmdline_config->addressing_external_inherited_fds != NULL)
        utils__free_memory(cmdline_config->addressing_external_inherited_fds);

    utils__free_memory(cmdline_config);
}


#undef _HELP_FORMAT_STRING
#undef _LICENSE_STRING
