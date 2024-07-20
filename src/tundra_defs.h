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

#pragma once



// *** The build system is responsible for specifying the version of the program. The macro should be defined at
//     compile-time by instructing the build system to pass a '-DTUNDRA__VERSION_STRING="..."' argument to the compiler.
#ifndef TUNDRA__VERSION_STRING
#error "The macro 'TUNDRA__VERSION_STRING' is not defined - it should have been defined by the build system!"
#endif



// *** In some cases, it might be desirable to set the values of the following macros at compile-time. Therefore, the
//     macros are defined (with a sensible default value) only if they have not been defined before (by the build
//     system/compiler).
#ifndef TUNDRA__DEFAULT_CONFIG_FILE_PATH
#define TUNDRA__DEFAULT_CONFIG_FILE_PATH "/etc/tundra-nat64/tundra-nat64.conf"
#endif

#ifndef TUNDRA__DEFAULT_TUN_DEVICE_PATH
#define TUNDRA__DEFAULT_TUN_DEVICE_PATH "/dev/net/tun"
#endif



// *** If you are just compiling the program, you probably should not change the following macros. If you are a
//     developer and looking into changing them, make sure you absolutely know what you are doing - you could very
//     easily end up with a weirdly-behaving or straight up broken program!
#define TUNDRA__PROGRAM_INFO_STRING "Tundra-NAT64 / v"TUNDRA__VERSION_STRING" / Copyright (c) 2024 Vit Labuda"

#define TUNDRA__WORK_DIR "/"  // The program does not access the filesystem after changing the working directory!
#define TUNDRA__MAX_XLAT_THREADS ((size_t) 256)  // Multi-queue TUN interfaces can have up to 256 queues (= file descriptors)
#define TUNDRA__MAX_ADDRESSING_EXTERNAL_CACHE_SIZE ((size_t) 10000000)
#define TUNDRA__XLAT_THREAD_MONITOR_INTERVAL_MICROSECONDS ((useconds_t) 900000)
#define TUNDRA__XLAT_THREAD_TERM_INTERVAL_MICROSECONDS ((useconds_t) 100000)

#define TUNDRA__MAX_PACKET_SIZE ((size_t) 65535)  // (TUNDRA__MAX_PACKET_SIZE + 1) must be divisible by 64!
#define TUNDRA__MIN_MTU_IPV4 ((size_t) 96)
#define TUNDRA__MIN_MTU_IPV6 ((size_t) 1280)
#define TUNDRA__MAX_MTU_IPV4 ((size_t) 65515)
#define TUNDRA__MAX_MTU_IPV6 ((size_t) 65515)
#define TUNDRA__MIN_GENERATED_PACKET_TTL ((uint8_t) 64)
#define TUNDRA__MAX_GENERATED_PACKET_TTL ((uint8_t) 255)

#define TUNDRA__MIN_TIMEOUT_MILLISECONDS ((uint64_t) 10)
#define TUNDRA__MAX_TIMEOUT_MILLISECONDS ((uint64_t) 2000)

#define TUNDRA__EXIT_SUCCESS ((int) 0)
#define TUNDRA__EXIT_CRASH ((int) 1)
#define TUNDRA__EXIT_MUTEX_FAILURE ((int) 2)
#define TUNDRA__EXIT_INVALID_COMPILE_TIME_CONFIG ((int) 3)
