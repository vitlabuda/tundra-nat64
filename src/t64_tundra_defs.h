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

#ifndef _T64I_TUNDRA_DEFS_H
#define _T64I_TUNDRA_DEFS_H


#define T64C_TUNDRA__VERSION "4.2.0"
#define T64C_TUNDRA__PROGRAM_INFO_STRING "Tundra-NAT64 / v"T64C_TUNDRA__VERSION" / Copyright (c) 2022 Vit Labuda"

#define T64C_TUNDRA__DEFAULT_CONFIG_FILE_PATH "/etc/tundra-nat64/tundra-nat64.conf"
#define T64C_TUNDRA__DEFAULT_TUN_DEVICE_PATH "/dev/net/tun"

#define T64C_TUNDRA__WORKING_DIRECTORY "/" // The program does not access the filesystem after changing the working directory!
#define T64C_TUNDRA__MAX_TRANSLATOR_THREADS ((size_t) 256) // Multi-queue TUN interfaces can have up to 256 queues (= file descriptors)
#define T64C_TUNDRA__MAX_ADDRESSING_EXTERNAL_CACHE_SIZE ((size_t) 10000000)
#define T64C_TUNDRA__TRANSLATOR_THREAD_MONITOR_INTERVAL ((unsigned int) 1) // In seconds

#define T64C_TUNDRA__MAX_PACKET_SIZE ((size_t) 65535)
#define T64C_TUNDRA__MINIMUM_MTU_IPV4 ((size_t) 68)
#define T64C_TUNDRA__MINIMUM_MTU_IPV6 ((size_t) 1280)
#define T64C_TUNDRA__MAXIMUM_MTU_IPV4 ((size_t) 65515)
#define T64C_TUNDRA__MAXIMUM_MTU_IPV6 ((size_t) 65515)
#define T64C_TUNDRA__MINIMUM_GENERATED_PACKET_TTL ((uint8_t) 64)
#define T64C_TUNDRA__MAXIMUM_GENERATED_PACKET_TTL ((uint8_t) 255)

#define T64C_TUNDRA__MINIMUM_TIMEOUT_MILLISECONDS ((uint64_t) 10)
#define T64C_TUNDRA__MAXIMUM_TIMEOUT_MILLISECONDS ((uint64_t) 2000)

#define T64C_TUNDRA__EXIT_CODE_SUCCESS ((int) 0)
#define T64C_TUNDRA__EXIT_CODE_CRASH ((int) 1)
#define T64C_TUNDRA__EXIT_CODE_MUTEX_FAILURE ((int) 2)
#define T64C_TUNDRA__EXIT_CODE_INVALID_COMPILE_TIME_CONFIG ((int) 3)


#endif // _T64I_TUNDRA_DEFS_H
