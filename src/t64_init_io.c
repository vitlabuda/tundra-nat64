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
#include"t64_init_io.h"

#include"t64_utils.h"
#include"t64_log.h"


// Creates the interface if it doesn't exist
// Can be used more than once (the TUN interface is multi-queue)
int t64f_init_io__open_tun_interface(const t64ts_tundra__conf_file *file_configuration) {
    int flags = IFF_TUN | IFF_NO_PI;
    if(file_configuration->program_translator_threads != 1)
        flags |= IFF_MULTI_QUEUE;

    struct ifreq tun_interface_request;
    T64M_UTILS__MEMORY_ZERO_OUT(&tun_interface_request, sizeof(struct ifreq));
    tun_interface_request.ifr_flags = flags;
    t64f_utils__secure_strncpy(tun_interface_request.ifr_name, file_configuration->io_tun_interface_name, IFNAMSIZ);

    const int tun_fd = open(file_configuration->io_tun_device_path, O_RDWR);
    if(tun_fd < 0)
        t64f_log__crash(true, "Failed to open the TUN device file: %s", file_configuration->io_tun_device_path);

    if(ioctl(tun_fd, TUNSETIFF, &tun_interface_request) < 0)
        t64f_log__crash(true, "Failed to request the TUN interface from the kernel!");

    if(!T64M_UTILS__STRINGS_EQUAL(tun_interface_request.ifr_name, file_configuration->io_tun_interface_name))
        t64f_log__crash(false, "The program requested a TUN interface named '%s', but got '%s' instead!", file_configuration->io_tun_interface_name, tun_interface_request.ifr_name);

    return tun_fd;
}

void t64f_init_io__set_tun_interface_persistent(const int tun_fd, const bool tun_persistent) {
    if(ioctl(tun_fd, TUNSETPERSIST, (tun_persistent ? 1 : 0)) < 0)
        t64f_log__crash(true, "Failed to %s the TUN interface's persistence status!", (tun_persistent ? "set" : "unset"));
}

void t64f_init_io__change_ownership_of_persistent_tun_interface(const t64ts_tundra__conf_file *file_configuration, const int persistent_tun_fd) {
    if(file_configuration->io_tun_owner_user_set && ioctl(persistent_tun_fd, TUNSETOWNER, file_configuration->io_tun_owner_user_uid) < 0)
        t64f_log__crash(true, "Failed to set the TUN interface's owner user to UID %"PRIdMAX"!", (intmax_t) file_configuration->io_tun_owner_user_uid);

    if(file_configuration->io_tun_owner_group_set && ioctl(persistent_tun_fd, TUNSETGROUP, file_configuration->io_tun_owner_group_gid) < 0)
        t64f_log__crash(true, "Failed to set the TUN interface's owner group to GID %"PRIdMAX"!", (intmax_t) file_configuration->io_tun_owner_group_gid);
}

char *t64f_init_io__get_fd_pair_from_inherited_fds_string(int *read_fd, int *write_fd, char *next_fds_string_ptr, const char short_opt, const char *long_opt) {
    if(next_fds_string_ptr == NULL)
        t64f_log__crash(false, "The value of the '-%c' / '--%s' command-line option does not contain enough file descriptors for all translator threads!", short_opt, long_opt);

    if(sscanf(next_fds_string_ptr, "%d,%d", read_fd, write_fd) != 2)
        t64f_log__crash(false, "The value of the '-%c' / '--%s' command-line option is formatted incorrectly: '%s'", short_opt, long_opt, next_fds_string_ptr);

    if(*read_fd < 0 || fcntl(*read_fd, F_GETFD) < 0)
        t64f_log__crash(true, "The read file descriptor %d obtained from the '-%c' / '--%s' command-line option is invalid!", *read_fd, short_opt, long_opt);

    if(*write_fd < 0 || fcntl(*write_fd, F_GETFD) < 0)
        t64f_log__crash(true, "The write file descriptor %d obtained from the '-%c' / '--%s' command-line option is invalid!", *write_fd, short_opt, long_opt);

    char *separator_ptr = strchr(next_fds_string_ptr, ';');
    if(separator_ptr == NULL)
        return NULL;

    return (separator_ptr + 1);
}

void t64f_init_io__create_anonymous_pipe(int *pipe_read_fd, int *pipe_write_fd) {
    int pipe_fds[2];
    if(pipe(pipe_fds) < 0)
        t64f_log__crash(true, "Failed to create a new anonymous pipe!");

    *pipe_read_fd = pipe_fds[0];
    *pipe_write_fd = pipe_fds[1];
}

void t64f_init_io__close_fd(const int fd) {
    if(close(fd) < 0)
        t64f_log__crash(true, "Failed to close the file descriptor %d!", fd);
}
