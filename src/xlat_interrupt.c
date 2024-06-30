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
#include"xlat_interrupt.h"

#include"signals.h"


ssize_t xlat_interrupt__read(const int fd, void *buf, const size_t count) {
    for(;;) {
        if(!signals__should_this_thread_keep_running())
            pthread_exit(NULL);

        const ssize_t ret_value = read(fd, buf, count);

        if(ret_value < 0 && errno == EINTR)
            continue;

        return ret_value;
    }
}

ssize_t xlat_interrupt__write(const int fd, const void *buf, const size_t count) {
    for(;;) {
        if(!signals__should_this_thread_keep_running())
            pthread_exit(NULL);

        const ssize_t ret_value = write(fd, buf, count);

        if(ret_value < 0 && errno == EINTR)
            continue;

        return ret_value;
    }
}

ssize_t xlat_interrupt__writev(const int fd, const struct iovec *iov, const int iovcnt) {
    for(;;) {
        if(!signals__should_this_thread_keep_running())
            pthread_exit(NULL);

        const ssize_t ret_value = writev(fd, iov, iovcnt);

        if(ret_value < 0 && errno == EINTR)
            continue;

        return ret_value;
    }
}

int xlat_interrupt__connect(const int sockfd, const struct sockaddr *addr, const socklen_t addrlen, const bool close_sockfd_before_exiting) {
    for(;;) {
        if(!signals__should_this_thread_keep_running()) {
            // If the close() call gets interrupted, the file descriptor will remain open; however, the chance
            //  of this happening is minimal (close() calls are almost always instant), and the results will almost
            //  certainly not be fatal, so it is not handled
            if(close_sockfd_before_exiting)
                close(sockfd);

            pthread_exit(NULL);
        }

        const int ret_value = connect(sockfd, addr, addrlen);

        if(ret_value < 0 && errno == EINTR)
            continue;

        return ret_value;
    }
}

int xlat_interrupt__close(const int fd) {
    for(;;) {
        if(!signals__should_this_thread_keep_running()) {
            // If the close() call gets interrupted, the file descriptor will remain open; however, the chance
            //  of this happening is minimal (close() calls are almost always instant), and the results will almost
            //  certainly not be fatal, so it is not handled (the main purpose of this function is to filter out
            //  signals on which the thread chose not to act)
            pthread_exit(NULL);
        }

        const int ret_value = close(fd);

        if(ret_value < 0 && errno == EINTR)
            continue;

        return ret_value;
    }
}
