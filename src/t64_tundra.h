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

#ifndef _T64I_TUNDRA_H
#define _T64I_TUNDRA_H

// Preprocessor macro name flags:
// C = constant
// M = macro
// I = include guard

// Function name flags:
// a = allocates memory

// Type name flags:
// s = struct
// e = enum

// Macro name flags:
// M = a macro argument is used more than once (M = multi-use)

#define _GNU_SOURCE

#include<stddef.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdbool.h>
#include<stdarg.h>
#include<stdnoreturn.h>
#include<stdint.h>
#include<inttypes.h>
#include<limits.h>
#include<ctype.h>
#include<unistd.h>
#include<fcntl.h>
#include<errno.h>
#include<locale.h>
#include<getopt.h>
#include<signal.h>
#include<pwd.h>
#include<grp.h>
#include<poll.h>
#include<pthread.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<linux/if.h>
#include<linux/if_tun.h>
#include<linux/ip.h>
#include<linux/ipv6.h>
#include<linux/icmp.h>
#include<linux/icmpv6.h>
#include<linux/tcp.h>
#include<linux/udp.h>
#include<sys/types.h>
#include<sys/file.h>
#include<sys/socket.h>
#include<sys/ioctl.h>
#include<sys/prctl.h>
#include<sys/sysinfo.h>
#include<sys/random.h>


#if CHAR_BIT != 8
#error "Tundra only supports systems where CHAR_BIT is equal to 8!"
#endif


#include"t64_tundra_defs.h"
#include"t64_tundra_typedefs.h"


#endif // _T64I_TUNDRA_H
