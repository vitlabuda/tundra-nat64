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
#include"xlat_6to4_icmp.h"

#include"utils.h"
#include"utils_ip.h"
#include"checksum.h"
#include"xlat_addr.h"


typedef struct _out_ipv4_packet_in_error_data {
    const uint8_t *payload_ptr; // Points to a part of 'ctx->in_packet_buffer' --> must not be modified!
    size_t payload_size;
    uint8_t carried_protocol;
    bool is_fragment; // Not necessary, but improves code readability and lowers the chance of a programming mistake happening
} _out_ipv4_packet_in_error_data;


static bool _validate_and_translate_icmp_type_and_code(const uint8_t old_icmpv6_type, const uint8_t old_icmpv6_code, uint8_t *new_icmpv4_type, uint8_t *new_icmpv4_code);
static bool _validate_and_translate_rest_of_header(const tundra__thread_ctx *const ctx, const uint8_t old_icmpv6_type, const uint8_t old_icmpv6_code, const uint8_t *old_icmpv6_rest_of_header, uint8_t *new_icmpv4_rest_of_header);
static uint16_t _recalculate_packet_too_big_mtu(const tundra__thread_ctx *const ctx, uint16_t mtu);
static bool _translate_parameter_problem_pointer(const uint8_t old_pointer, uint8_t *new_pointer);
static bool _validate_and_translate_ip_header_of_packet_in_error(tundra__thread_ctx *const ctx, const uint8_t *in_icmpv6_payload_ptr, const size_t in_icmpv6_payload_size, uint8_t *out_packet_in_error_buffer_28b, _out_ipv4_packet_in_error_data *const out_packet_in_error_data, const bool dont_fragment);


bool xlat_6to4_icmp__translate_icmpv6_to_icmpv4(tundra__thread_ctx *const ctx, const uint8_t *in_packet_payload_ptr, const size_t in_packet_payload_size, xlat_6to4_icmp__out_icmpv4_message_data *const out_message_data) {
    if(in_packet_payload_size < 8)
        return false;


    // IMPROVE: Due to the fact that both the base IPv6 header's length and the length of all IPv6 extension headers is
    //  divisible by 8, the pointer should always be at least 8-byte aligned. However, this fact is by no means obvious
    //  from the source code, and a subtle change in a seemingly unrelated part of the program could break this
    //  assumption - for this reason, this line is marked for future improvement (which would, however, likely require
    //  copying stuff around, perhaps slowing the program down).
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wcast-align"
    const struct icmp6hdr *in_icmpv6_header = (const struct icmp6hdr *) in_packet_payload_ptr;
    #pragma GCC diagnostic pop

    struct icmphdr *out_icmpv4_header = (struct icmphdr *) __builtin_assume_aligned(out_message_data->message_start_36b, 64);
    out_message_data->message_start_size_m8u = 8;


    // :: Type & Code
    if(!_validate_and_translate_icmp_type_and_code(
        in_icmpv6_header->icmp6_type,
        in_icmpv6_header->icmp6_code,
        &out_icmpv4_header->type,
        &out_icmpv4_header->code
    )) return false;


    // :: Rest of header
    if(!_validate_and_translate_rest_of_header(
        ctx,
        in_icmpv6_header->icmp6_type,
        in_icmpv6_header->icmp6_code,
        (in_packet_payload_ptr + 4),
        (out_message_data->message_start_36b + 4)
    )) return false;


    // :: Payload
    const uint8_t *in_icmpv6_payload_ptr = (in_packet_payload_ptr + 8);
    const size_t in_icmpv6_payload_size = (in_packet_payload_size - 8);

    if(in_icmpv6_header->icmp6_type == 128 || in_icmpv6_header->icmp6_type == 129) { // Echo Request, Echo Reply
        out_message_data->nullable_message_end_ptr = in_icmpv6_payload_ptr;
        out_message_data->zeroable_message_end_size = in_icmpv6_payload_size;
    } else { // ICMP Error message
        _out_ipv4_packet_in_error_data out_packet_in_error_data;
        if(!_validate_and_translate_ip_header_of_packet_in_error(
            ctx,
            in_icmpv6_payload_ptr,
            in_icmpv6_payload_size,
            (out_message_data->message_start_36b + 8),
            &out_packet_in_error_data,
            (bool) (in_icmpv6_header->icmp6_type == 2) // "Packet too big" -> "Fragmentation Needed and DF was Set" (it literally says that DF must be set)
        )) return false;
        out_message_data->message_start_size_m8u += 20; // Always 28 bytes -> not aligned to 8!

        if(out_packet_in_error_data.carried_protocol == 1) { // ICMPv4
            // If the packet in error is a fragment or its payload is smaller than 8 bytes, it is not possible to tell
            //  if it is an ICMP Echo packet, and therefore it is dropped
            if(out_packet_in_error_data.is_fragment || out_packet_in_error_data.payload_size < 8)
                return false;

            // WARNING: Only the first 4 bytes (fields type, code, checksum) are set and therefore accessible!!!
            // Since 'out_message_data->message_start_36b' is always 64-byte aligned, it can be assumed, that if the
            //  pointer is moved 28 bytes forward, the resulting pointer will always be (only) 4-byte aligned.
            struct icmphdr *new_icmpv4_packet_in_error_payload_ptr = (struct icmphdr *) __builtin_assume_aligned(out_message_data->message_start_36b + 28, 4);
            memcpy(new_icmpv4_packet_in_error_payload_ptr, out_packet_in_error_data.payload_ptr, 4);
            out_message_data->message_start_size_m8u += 4; // Always 32 bytes -> aligned to 8

            /*
             * https://datatracker.ietf.org/doc/html/rfc7915#page-14 states:
             * "The translation of the inner IP header can be done by invoking the
             *  function that translated the outer IP headers.  This process MUST
             *  stop at the first embedded header and drop the packet if it contains
             *  more embedded headers."
             *
             *  Echo Reply and Echo Request are the only translatable ICMP types that do not carry a packet "in error".
             */
            if(new_icmpv4_packet_in_error_payload_ptr->code != 0)
                return false;

            if(new_icmpv4_packet_in_error_payload_ptr->type == 128)
                new_icmpv4_packet_in_error_payload_ptr->type = 8;
            else if(new_icmpv4_packet_in_error_payload_ptr->type == 129)
                new_icmpv4_packet_in_error_payload_ptr->type = 0;
            else
                return false;

            // The first 4 bytes of the payload are in the message start buffer (due to alignment).
            out_message_data->nullable_message_end_ptr = (out_packet_in_error_data.payload_ptr + 4);
            out_message_data->zeroable_message_end_size = (out_packet_in_error_data.payload_size - 4);
        } else if(out_packet_in_error_data.payload_size >= 4) { // All other transport protocols - payload at least 4 bytes in size
            memcpy(out_message_data->message_start_36b + 28, out_packet_in_error_data.payload_ptr, 4);
            out_message_data->message_start_size_m8u += 4; // Always 32 bytes -> aligned to 8

            out_message_data->nullable_message_end_ptr = (out_packet_in_error_data.payload_ptr + 4);
            out_message_data->zeroable_message_end_size = (out_packet_in_error_data.payload_size - 4);
        } else { // All other transport protocols - payload less than 4 bytes in size
            memcpy(out_message_data->message_start_36b + 28, out_packet_in_error_data.payload_ptr, out_packet_in_error_data.payload_size);
            out_message_data->message_start_size_m8u += out_packet_in_error_data.payload_size; // Not always aligned to 8, but it does not matter since 'nullable_message_end_ptr' is NULL.

            out_message_data->nullable_message_end_ptr = NULL;
            out_message_data->zeroable_message_end_size = 0;
        }

        // Limit ICMPv4 error messages to be 576 bytes in size at maximum (if 'out_message_data->zeroable_message_end_size' is 0, it won't be affected)
        out_message_data->zeroable_message_end_size = UTILS__MINIMUM_UNSAFE(
            out_message_data->zeroable_message_end_size,
            (556 - out_message_data->message_start_size_m8u)
        );
    }


    // :: Checksum
    out_icmpv4_header->checksum = 0;
    out_icmpv4_header->checksum = checksum__calculate_checksum_ipv4(
        out_message_data->message_start_36b,
        out_message_data->message_start_size_m8u,
        out_message_data->nullable_message_end_ptr,
        out_message_data->zeroable_message_end_size,
        NULL
    );


    return true;
}

static bool _validate_and_translate_icmp_type_and_code(const uint8_t old_icmpv6_type, const uint8_t old_icmpv6_code, uint8_t *new_icmpv4_type, uint8_t *new_icmpv4_code) {
    switch(old_icmpv6_type) {
        case 128: // Echo Request
            {
                if(old_icmpv6_code != 0)
                    return false;

                *new_icmpv4_type = 8;
                *new_icmpv4_code = 0;
            }
            break;

        case 129: // Echo Reply
            {
                if(old_icmpv6_code != 0)
                    return false;

                *new_icmpv4_type = 0;
                *new_icmpv4_code = 0;
            }
            break;

        case 1: // Destination Unreachable
            {
                *new_icmpv4_type = 3;

                switch(old_icmpv6_code) {
                    case 0: case 2: case 3: // No route to destination, Beyond scope of source address, Address unreachable
                        *new_icmpv4_code = 1;
                        break;

                    case 1: // Communication with destination administratively prohibited
                        *new_icmpv4_code = 10;
                        break;

                    case 4: // Port unreachable
                        *new_icmpv4_code = 3;
                        break;

                    default:
                        return false;
                }
            }
            break;

        case 2: // Packet Too Big
            {
                if(old_icmpv6_code != 0)
                    return false;

                *new_icmpv4_type = 3;
                *new_icmpv4_code = 4;
            }
            break;

        case 3: // Time Exceeded
            {
                if(old_icmpv6_code != 0 && old_icmpv6_code != 1)
                    return false;

                *new_icmpv4_type = 11;
                *new_icmpv4_code = old_icmpv6_code;
            }
            break;

        case 4: // Parameter Problem
            switch(old_icmpv6_code) {
                case 0: // Erroneous header field encountered
                    *new_icmpv4_type = 12;
                    *new_icmpv4_code = 0;
                    break;

                case 1: // Unrecognized Next Header type encountered
                    *new_icmpv4_type = 3;
                    *new_icmpv4_code = 2;
                    break;

                default:
                    // All other codes, including:
                    // - Code 2 (Unrecognized IPv6 option encountered)
                    return false;
            }
            break;

        default:
            // All other types, including:
            // - MLD Multicast Listener Query/Report/Done (Type 130, 131, 132)
            // - Neighbor Discover messages (Type 133 through 137)
            return false;
    }

    return true;
}

static bool _validate_and_translate_rest_of_header(const tundra__thread_ctx *const ctx, const uint8_t old_icmpv6_type, const uint8_t old_icmpv6_code, const uint8_t *old_icmpv6_rest_of_header, uint8_t *new_icmpv4_rest_of_header) {
    // Echo Request, Echo Reply
    if(old_icmpv6_type == 128 || old_icmpv6_type == 129) {
        memcpy(new_icmpv4_rest_of_header, old_icmpv6_rest_of_header, 4);
        return true;
    }

    // Packet Too Big
    if(old_icmpv6_type == 2) {
        if(!UTILS__MEM_EQ(old_icmpv6_rest_of_header, "\x00\x00", 2))
            return false;
        UTILS__MEM_ZERO_OUT(new_icmpv4_rest_of_header, 2);

        // Memory alignment
        uint16_t old_mtu;
        memcpy(&old_mtu, old_icmpv6_rest_of_header + 2, 2);
        old_mtu = ntohs(old_mtu);

        uint16_t new_mtu = _recalculate_packet_too_big_mtu(ctx, old_mtu);
        new_mtu = htons(new_mtu);
        memcpy(new_icmpv4_rest_of_header + 2, &new_mtu, 2);

        return true;
    }

    // Parameter Problem
    if(old_icmpv6_type == 4) {
        if(old_icmpv6_code == 0) { // Erroneous header field encountered
            if(!UTILS__MEM_EQ(old_icmpv6_rest_of_header, "\x00\x00\x00", 3))
                return false;
            UTILS__MEM_ZERO_OUT(new_icmpv4_rest_of_header + 1, 3);

            return _translate_parameter_problem_pointer(old_icmpv6_rest_of_header[3], new_icmpv4_rest_of_header);
        }

        // Unrecognized Next Header type encountered (the old ICMPv6 rest of header, containing a pointer, is not validated intentionally)
        UTILS__MEM_ZERO_OUT(new_icmpv4_rest_of_header, 4);
        return true;
    }

    // All the other message types & codes
    if(!UTILS__MEM_EQ(old_icmpv6_rest_of_header, "\x00\x00\x00\x00", 4))
        return false;

    UTILS__MEM_ZERO_OUT(new_icmpv4_rest_of_header, 4);
    return true;
}

// Both the argument-passed and the returned value is in host byte order!
static uint16_t _recalculate_packet_too_big_mtu(const tundra__thread_ctx *const ctx, uint16_t mtu) {
    // Although the minimum IPv6 MTU is 1280 bytes, some networks may be broken

    // https://datatracker.ietf.org/doc/html/rfc7915#page-21
    mtu = (uint16_t) UTILS__MAXIMUM_UNSAFE(20, mtu); // Integer overflow prevention
    mtu = (uint16_t) UTILS__MINIMUM_UNSAFE(mtu - 20, (uint16_t) ctx->config->translator_ipv4_outbound_mtu);
    mtu = (uint16_t) UTILS__MINIMUM_UNSAFE(mtu, ((uint16_t) ctx->config->translator_ipv6_outbound_mtu) - 20);
    mtu = (uint16_t) UTILS__MAXIMUM_UNSAFE(68, mtu);

    return mtu;
}

static bool _translate_parameter_problem_pointer(const uint8_t old_pointer, uint8_t *new_pointer) {
    // https://datatracker.ietf.org/doc/html/rfc7915#page-22

    if(old_pointer == 0 || old_pointer == 1) {
        *new_pointer = old_pointer;
        return true;
    }

    if(old_pointer == 4 || old_pointer == 5) {
        *new_pointer = 2;
        return true;
    }

    if(old_pointer == 6) {
        *new_pointer = 9;
        return true;
    }

    if(old_pointer == 7) {
        *new_pointer = 8;
        return true;
    }

    if(old_pointer >= 8 && old_pointer <= 23) {
        *new_pointer = 12;
        return true;
    }

    if(old_pointer >= 24 && old_pointer <= 39) {
        *new_pointer = 16;
        return true;
    }

    // Including, but not limited to the values: 2, 3
    return false;
}

static bool _validate_and_translate_ip_header_of_packet_in_error(tundra__thread_ctx *const ctx, const uint8_t *in_icmpv6_payload_ptr, const size_t in_icmpv6_payload_size, uint8_t *out_packet_in_error_buffer_28b, _out_ipv4_packet_in_error_data *const out_packet_in_error_data, const bool dont_fragment) {
    if(in_icmpv6_payload_size < 40)
        return false;


    // IMPROVE: As of now, both pointers should always be at least 8-byte aligned; however, this fact is by no means
    //  obvious from the source code and a change in a seemingly unrelated part of code could break this assumption -
    //  for this reason, these lines are marked for future improvement.
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wcast-align"
    const struct ipv6hdr *in_ipv6_header = (const struct ipv6hdr *) in_icmpv6_payload_ptr;
    struct iphdr *out_ipv4_header = (struct iphdr *) out_packet_in_error_buffer_28b;
    #pragma GCC diagnostic pop



    // :: Basic validation
    if(in_ipv6_header->version != 6)
        return false;



    // :: Translation
    out_ipv4_header->version = 4;
    out_ipv4_header->ihl = 5; // 20 bytes
    out_ipv4_header->tos = (uint8_t) ((in_ipv6_header->priority << 4) | (in_ipv6_header->flow_lbl[0] >> 4));
    out_ipv4_header->tot_len = htons(
        // An integer overflow might occur here, but it does not really matter in this case, as we are translating a
        //  packet in error, which is expected to be "broken" in some way...
        (uint16_t) (ntohs(in_ipv6_header->payload_len) + 20)
    );
    out_ipv4_header->ttl = in_ipv6_header->hop_limit;

    {
        const uint8_t *current_header_ptr = (in_icmpv6_payload_ptr + 40);
        ssize_t remaining_packet_size = ((ssize_t) in_icmpv6_payload_size) - 40;
        uint8_t current_header_number = in_ipv6_header->nexthdr;
        const tundra__ipv6_frag_header *ipv6_fragment_header_ptr = NULL;

        while(
            (ipv6_fragment_header_ptr == NULL) &&
            (current_header_number == 0 || current_header_number == 43 || current_header_number == 44 || current_header_number == 60)
        ) {
            if(remaining_packet_size < 8)
                return false;

            if(current_header_number == 44)
                ipv6_fragment_header_ptr = (const tundra__ipv6_frag_header *) current_header_ptr;

            current_header_number = current_header_ptr[0];

            const ssize_t current_header_size = 8 + (((ssize_t) current_header_ptr[1]) * 8);
            current_header_ptr += current_header_size;
            remaining_packet_size -= current_header_size;
        }

        if(remaining_packet_size < 0)
            return false;

        out_packet_in_error_data->payload_ptr = current_header_ptr;
        out_packet_in_error_data->payload_size = (size_t) remaining_packet_size;

        if(ipv6_fragment_header_ptr != NULL) {
            out_ipv4_header->id = ipv6_fragment_header_ptr->identification[1];
            out_ipv4_header->frag_off = UTILS_IP__CONSTRUCT_IPV4_FRAG_OFFSET_AND_FLAGS(
                (uint16_t) dont_fragment,
                UTILS_IP__GET_IPV6_MORE_FRAGS(ipv6_fragment_header_ptr),
                UTILS_IP__GET_IPV6_FRAG_OFFSET(ipv6_fragment_header_ptr)
            );
        } else {
            utils_ip__generate_ipv4_frag_id(ctx, (uint8_t *) &out_ipv4_header->id);
            out_ipv4_header->frag_off = UTILS_IP__CONSTRUCT_IPV4_FRAG_OFFSET_AND_FLAGS((uint16_t) dont_fragment, 0, 0);
        }

        const uint8_t ipv4_protocol = (current_header_number == 58) ? 1 : current_header_number;
        out_packet_in_error_data->carried_protocol = ipv4_protocol;
        out_ipv4_header->protocol = ipv4_protocol;
    }


    if(!xlat_addr__translate_6to4_addr_for_icmp_error_packet(
        ctx,
        (const uint8_t *) in_ipv6_header->saddr.s6_addr,
        (const uint8_t *) in_ipv6_header->daddr.s6_addr,
        (uint8_t *) &out_ipv4_header->saddr,
        (uint8_t *) &out_ipv4_header->daddr
    )) return false;

    out_ipv4_header->check = 0;
    out_ipv4_header->check = checksum__calculate_ipv4_header_checksum(out_ipv4_header);

    out_packet_in_error_data->is_fragment = (bool) UTILS_IP__IS_IPV4_PACKET_FRAGMENTED_UNSAFE(out_ipv4_header);

    return true;
}
