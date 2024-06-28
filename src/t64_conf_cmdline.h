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

#ifndef _T64I_CONF_CMDLINE_H
#define _T64I_CONF_CMDLINE_H

#include"t64_tundra.h"


#define T64C_CONF_CMDLINE__SHORTOPT_HELP 'h'
#define T64C_CONF_CMDLINE__SHORTOPT_VERSION 'v'
#define T64C_CONF_CMDLINE__SHORTOPT_LICENSE 'l'
#define T64C_CONF_CMDLINE__SHORTOPT_CONFIG_FILE 'c'
#define T64C_CONF_CMDLINE__SHORTOPT_IO_INHERITED_FDS 'f'
#define T64C_CONF_CMDLINE__SHORTOPT_ADDRESSING_EXTERNAL_INHERITED_FDS 'F'

#define T64C_CONF_CMDLINE__LONGOPT_HELP "help"
#define T64C_CONF_CMDLINE__LONGOPT_VERSION "version"
#define T64C_CONF_CMDLINE__LONGOPT_LICENSE "license"
#define T64C_CONF_CMDLINE__LONGOPT_CONFIG_FILE "config-file"
#define T64C_CONF_CMDLINE__LONGOPT_IO_INHERITED_FDS "io-inherited-fds"
#define T64C_CONF_CMDLINE__LONGOPT_ADDRESSING_EXTERNAL_INHERITED_FDS "addressing-external-inherited-fds"

#define T64C_CONF_CMDLINE__OPMODE_TRANSLATE "translate"
#define T64C_CONF_CMDLINE__OPMODE_MKTUN "mktun"
#define T64C_CONF_CMDLINE__OPMODE_RMTUN "rmtun"
#define T64C_CONF_CMDLINE__OPMODE_VALIDATE_CONFIG "validate-config"
#define T64C_CONF_CMDLINE__OPMODE_PRINT_CONFIG "print-config"


extern t64ts_tundra__conf_cmdline *t64fa_conf_cmdline__parse_cmdline_configuration(int argc, char **argv);
extern void t64f_conf_cmdline__free_cmdline_configuration(t64ts_tundra__conf_cmdline *cmdline_configuration);


#endif // _T64I_CONF_CMDLINE_H
