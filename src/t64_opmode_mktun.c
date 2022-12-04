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
#include"t64_opmode_mktun.h"

#include"t64_log.h"
#include"t64_init_io.h"
#include"t64_conf_file.h"


void t64f_opmode_mktun__run(const t64ts_tundra__conf_file *file_configuration) {
    if(file_configuration->io_mode != T64TE_TUNDRA__IO_MODE_TUN)
        t64f_log__crash(false, "The I/O mode is not '"T64C_CONF_FILE__IO_MODE_TUN"'; therefore, persistent TUN interfaces cannot be created!");

    {
        const int tun_fd = t64f_init_io__open_tun_interface(file_configuration);
        t64f_init_io__set_tun_interface_persistent(tun_fd, true);
        t64f_init_io__change_ownership_of_persistent_tun_interface(file_configuration, tun_fd);
        t64f_init_io__close_fd(tun_fd, false);
    }

    t64f_log__info("A persistent TUN interface named '%s' has been successfully created!", file_configuration->io_tun_interface_name);
}
