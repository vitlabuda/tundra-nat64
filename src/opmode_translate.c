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
#include"opmode_translate.h"

#include"utils.h"
#include"log.h"
#include"init_io.h"
#include"signals.h"
#include"xlat.h"


static tundra__thread_ctx *_initialize_thread_contexts(const tundra__conf_cmdline *const cmdline_config, const tundra__conf_file *const file_config);
static tundra__external_addr_xlat_state *_initialize_external_addr_xlat_state(const tundra__conf_file *const file_config, char **addressing_external_next_fds_string_ptr);
static void _free_thread_contexts(const tundra__conf_file *const file_config, tundra__thread_ctx *thread_contexts);
static void _free_external_addr_xlat_state(tundra__external_addr_xlat_state *external_addr_xlat_state);
static void _partially_daemonize(const tundra__conf_file *const file_config);
static void _start_threads(const tundra__conf_file *const file_config, tundra__thread_ctx *thread_contexts);
static void _print_info_about_xlat_start(const tundra__conf_file *const file_config);
static void _monitor_threads(const tundra__conf_file *const file_config, tundra__thread_ctx *thread_contexts);
static void _terminate_threads(const tundra__conf_file *const file_config, tundra__thread_ctx *thread_contexts);


void opmode_translate__run(const tundra__conf_cmdline *const cmdline_config, const tundra__conf_file *const file_config) {
    if(file_config->program_translator_threads < 1 || file_config->program_translator_threads > TUNDRA__MAX_XLAT_THREADS)
        log__crash_invalid_internal_state("Invalid count of translator threads");

    log__info("%s", TUNDRA__PROGRAM_INFO_STRING);

    tundra__thread_ctx *thread_contexts = _initialize_thread_contexts(cmdline_config, file_config);
    _partially_daemonize(file_config);
    _start_threads(file_config, thread_contexts);
    _print_info_about_xlat_start(file_config);

    _monitor_threads(file_config, thread_contexts);

    _terminate_threads(file_config, thread_contexts);
    _free_thread_contexts(file_config, thread_contexts);

    log__info("Tundra will now terminate.");
}

static tundra__thread_ctx *_initialize_thread_contexts(const tundra__conf_cmdline *const cmdline_config, const tundra__conf_file *const file_config) {
    tundra__thread_ctx *thread_contexts = utils__alloc_zeroed_out_memory(file_config->program_translator_threads, sizeof(tundra__thread_ctx));

    if(file_config->io_mode == TUNDRA__IO_MODE_INHERITED_FDS && cmdline_config->io_inherited_fds == NULL)
        log__crash(false, "Even though the program is in the 'inherited-fds' I/O mode, the '-f' / '--io-inherited-fds' command-line option is missing!");

    if(file_config->addressing_mode == TUNDRA__ADDRESSING_MODE_EXTERNAL && file_config->addressing_external_transport == TUNDRA__ADDRESSING_EXTERNAL_TRANSPORT_INHERITED_FDS && cmdline_config->addressing_external_inherited_fds == NULL)
        log__crash(false, "Even though the program is configured to use the 'inherited-fds' transport of the 'external' addressing mode, the '-F' / '--addressing-external-inherited-fds' command-line option is missing!");


    char *io_next_fds_string_ptr = cmdline_config->io_inherited_fds;
    char *addressing_external_next_fds_string_ptr = cmdline_config->addressing_external_inherited_fds;
    int single_queue_tun_fd = -1;

    for(size_t i = 0; i < file_config->program_translator_threads; i++) {
        // thread_contexts[i].thread stays uninitialized (it is initialized in _start_threads())
        thread_contexts[i].thread_id = (i + 1); // Thread ID 0 is reserved for the main thread
        thread_contexts[i].in_packet_buffer = utils__alloc_zeroed_out_memory(TUNDRA__MAX_PACKET_SIZE + 1, sizeof(uint8_t));
        thread_contexts[i].in_packet_size = 0;
        thread_contexts[i].config = file_config;
        thread_contexts[i].joined = false;

        if(getrandom(&thread_contexts[i].frag_id_ipv6, 4, 0) != 4 || getrandom(&thread_contexts[i].frag_id_ipv4, 2, 0) != 2)
            log__crash(false, "Failed to generate fragment identifiers using the getrandom() system call!");

        thread_contexts[i].external_addr_xlat_state = (
            (file_config->addressing_mode == TUNDRA__ADDRESSING_MODE_EXTERNAL) ?
            _initialize_external_addr_xlat_state(file_config, &addressing_external_next_fds_string_ptr) :
            NULL
        );

        switch(file_config->io_mode) {
            case TUNDRA__IO_MODE_INHERITED_FDS:
                io_next_fds_string_ptr = init_io__get_fd_pair_from_inherited_fds_string(&thread_contexts[i].packet_read_fd, &thread_contexts[i].packet_write_fd, io_next_fds_string_ptr, 'f', "io-inherited-fds");
                break;

            case TUNDRA__IO_MODE_TUN:
                if(file_config->io_tun_multi_queue) {
                    thread_contexts[i].packet_read_fd = init_io__open_tun(file_config);
                    thread_contexts[i].packet_write_fd = thread_contexts[i].packet_read_fd;
                } else {
                    if(single_queue_tun_fd < 0)
                        single_queue_tun_fd = init_io__open_tun(file_config);

                    thread_contexts[i].packet_read_fd = single_queue_tun_fd;
                    thread_contexts[i].packet_write_fd = single_queue_tun_fd;
                }
                break;

            default:
                log__crash_invalid_internal_state("Invalid I/O mode");
        }
    }

    return thread_contexts;
}

static tundra__external_addr_xlat_state *_initialize_external_addr_xlat_state(const tundra__conf_file *const file_config, char **addressing_external_next_fds_string_ptr) {
    tundra__external_addr_xlat_state *external_addr_xlat_state = utils__alloc_zeroed_out_memory(1, sizeof(tundra__external_addr_xlat_state));

    if(file_config->addressing_external_cache_size_main_addresses > 0) {
        // It is absolutely crucial that the cache memory is zeroed out!
        external_addr_xlat_state->cache_4to6_main_packet = utils__alloc_zeroed_out_memory(file_config->addressing_external_cache_size_main_addresses, sizeof(tundra__external_addr_xlat_cache_entry));
        external_addr_xlat_state->cache_6to4_main_packet = utils__alloc_zeroed_out_memory(file_config->addressing_external_cache_size_main_addresses, sizeof(tundra__external_addr_xlat_cache_entry));
    } else {
        external_addr_xlat_state->cache_4to6_main_packet = NULL;
        external_addr_xlat_state->cache_6to4_main_packet = NULL;
    }

    if(file_config->addressing_external_cache_size_icmp_error_addresses > 0) {
        // It is absolutely crucial that the cache memory is zeroed out!
        external_addr_xlat_state->cache_4to6_icmp_error_packet = utils__alloc_zeroed_out_memory(file_config->addressing_external_cache_size_icmp_error_addresses, sizeof(tundra__external_addr_xlat_cache_entry));
        external_addr_xlat_state->cache_6to4_icmp_error_packet = utils__alloc_zeroed_out_memory(file_config->addressing_external_cache_size_icmp_error_addresses, sizeof(tundra__external_addr_xlat_cache_entry));
    } else {
        external_addr_xlat_state->cache_4to6_icmp_error_packet = NULL;
        external_addr_xlat_state->cache_6to4_icmp_error_packet = NULL;
    }

    if(file_config->addressing_external_transport == TUNDRA__ADDRESSING_EXTERNAL_TRANSPORT_INHERITED_FDS) {
        *addressing_external_next_fds_string_ptr = init_io__get_fd_pair_from_inherited_fds_string(&external_addr_xlat_state->read_fd, &external_addr_xlat_state->write_fd, *addressing_external_next_fds_string_ptr, 'F', "addressing-external-inherited-fds");
    } else {
        external_addr_xlat_state->read_fd = external_addr_xlat_state->write_fd = -1;
    }

    if(getrandom(&external_addr_xlat_state->message_identifier, 4, 0) != 4)
        log__crash(false, "Failed to generate a message identifier for external address translation using the getrandom() system call!");

    return external_addr_xlat_state;
}

// Closes 'packet_read_fd' and 'packet_write_fd', but not 'termination_pipe_read_fd'!
static void _free_thread_contexts(const tundra__conf_file *const file_config, tundra__thread_ctx *thread_contexts) {
    for(size_t i = 0; i < file_config->program_translator_threads; i++) {
        utils__free_memory(thread_contexts[i].in_packet_buffer);

        if(thread_contexts[i].external_addr_xlat_state != NULL)
            _free_external_addr_xlat_state(thread_contexts[i].external_addr_xlat_state);

        init_io__close_fd(thread_contexts[i].packet_read_fd, true);
        init_io__close_fd(thread_contexts[i].packet_write_fd, true);
    }

    utils__free_memory(thread_contexts);
}

static void _free_external_addr_xlat_state(tundra__external_addr_xlat_state *external_addr_xlat_state) {
    if(external_addr_xlat_state->cache_4to6_main_packet != NULL)
        utils__free_memory(external_addr_xlat_state->cache_4to6_main_packet);

    if(external_addr_xlat_state->cache_4to6_icmp_error_packet != NULL)
        utils__free_memory(external_addr_xlat_state->cache_4to6_icmp_error_packet);

    if(external_addr_xlat_state->cache_6to4_main_packet != NULL)
        utils__free_memory(external_addr_xlat_state->cache_6to4_main_packet);

    if(external_addr_xlat_state->cache_6to4_icmp_error_packet != NULL)
        utils__free_memory(external_addr_xlat_state->cache_6to4_icmp_error_packet);

    init_io__close_fd(external_addr_xlat_state->read_fd, true);
    init_io__close_fd(external_addr_xlat_state->write_fd, true);

    utils__free_memory(external_addr_xlat_state);
}

static void _partially_daemonize(const tundra__conf_file *const file_config) {
    // --- chdir() ---
    if(chdir(TUNDRA__WORK_DIR) < 0)
        log__crash(true, "Failed to change the program's working directory (the chdir() call failed)!");

    // --- setgroups() & setgid() ---
    if(file_config->program_privilege_drop_group_perform) {
        if(setgroups(1, &file_config->program_privilege_drop_group_gid) < 0)
            log__crash(true, "Failed to drop the program's group privileges to GID %"PRIdMAX" (the setgroups() call failed)!", (intmax_t) file_config->program_privilege_drop_group_gid);

        if(setgid(file_config->program_privilege_drop_group_gid) < 0)
            log__crash(true, "Failed to drop the program's group privileges to GID %"PRIdMAX" (the setgid() call failed)!", (intmax_t) file_config->program_privilege_drop_group_gid);
    }

    // --- setuid() ---
    if(file_config->program_privilege_drop_user_perform && setuid(file_config->program_privilege_drop_user_uid) < 0)
        log__crash(true, "Fail to drop the program's user privileges to UID %"PRIdMAX" (the setuid() call failed)!", (intmax_t) file_config->program_privilege_drop_user_uid);
}

static void _start_threads(const tundra__conf_file *const file_config, tundra__thread_ctx *thread_contexts) {
    for(size_t i = 0; i < file_config->program_translator_threads; i++) {
        const int pthread_errno = pthread_create(&thread_contexts[i].thread, NULL, xlat__run_thread, thread_contexts + i);
        if(pthread_errno != 0) {
            errno = pthread_errno;
            log__crash(true, "Failed to create a new translator thread!");
        }
    }
}

static void _print_info_about_xlat_start(const tundra__conf_file *const file_config) {
    const char *addressing_mode_string;
    switch(file_config->addressing_mode) {
        case TUNDRA__ADDRESSING_MODE_NAT64: addressing_mode_string = "NAT64"; break;
        case TUNDRA__ADDRESSING_MODE_CLAT: addressing_mode_string = "CLAT"; break;
        case TUNDRA__ADDRESSING_MODE_SIIT: addressing_mode_string = "SIIT"; break;
        case TUNDRA__ADDRESSING_MODE_EXTERNAL: addressing_mode_string = "<external>"; break;
        default: log__crash_invalid_internal_state("Invalid addressing mode");
    }

    switch(file_config->io_mode) {
        case TUNDRA__IO_MODE_INHERITED_FDS:
            log__info("%zu threads are now performing %s translation of packets on command-line-provided file descriptors...", file_config->program_translator_threads, addressing_mode_string);
            break;

        case TUNDRA__IO_MODE_TUN:
            log__info("%zu threads are now performing %s translation of packets on TUN interface '%s'...", file_config->program_translator_threads, addressing_mode_string, file_config->io_tun_interface_name);
            break;

        default:
            log__crash_invalid_internal_state("Invalid I/O mode");
    }
}

static void _monitor_threads(const tundra__conf_file *const file_config, tundra__thread_ctx *thread_contexts) {
    while(signals__should_this_thread_keep_running()) {
        for(size_t i = 0; i < file_config->program_translator_threads; i++) {
            if(pthread_tryjoin_np(thread_contexts[i].thread, NULL) != EBUSY)
                log__crash(false, "A translator thread has terminated unexpectedly!");
        }

        usleep(TUNDRA__XLAT_THREAD_MONITOR_INTERVAL_MICROSECONDS);
    }
}

static void _terminate_threads(const tundra__conf_file *const file_config, tundra__thread_ctx *thread_contexts) {
    // Even though it is extremely unlikely, threads may not terminate on first signal (due to a race condition - when
    //  the signal is delivered between signals__should_this_thread_keep_running() and a blocking system call);
    //  therefore, the termination is performed within an "infinite" loop.
    for(;;) {
        bool are_there_running_threads = false;

        for(size_t i = 0; i < file_config->program_translator_threads; i++) {
            if(thread_contexts[i].joined)
                continue;

            switch(pthread_tryjoin_np(thread_contexts[i].thread, NULL)) {
                case 0:
                    {
                        thread_contexts[i].joined = true;
                    }
                    break;

                case EBUSY:
                    {
                        are_there_running_threads = true;

                        // There is a possibility of a race condition occurring (when the thread terminates between
                        //  pthread_tryjoin_np() and pthread_kill()), but it is ignored, because the chance of it
                        //  occurring is extremely tiny, and there seems to be no easy and performance-friendly way
                        //  of implementing the termination process 100% atomically.
                        if(pthread_kill(thread_contexts[i].thread, SIGNALS__XLAT_THREAD_TERM_SIGNAL) != 0)
                            log__crash(false, "Failed to inform a translator thread that it should terminate (using a signal)!");
                    }
                    break;

                default:
                    log__crash(false, "Failed to join a translator thread!");
            }
        }

        if(are_there_running_threads)
            usleep(TUNDRA__XLAT_THREAD_TERM_INTERVAL_MICROSECONDS);
        else
            break;
    }
}
