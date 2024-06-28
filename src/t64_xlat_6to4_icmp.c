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

#include"t64_tundra.h"
#include"t64_xlat_6to4_icmp.h"

#include"t64_utils.h"
#include"t64_utils_ip.h"
#include"t64_checksum.h"
#include"t64_xlat_addr.h"


typedef struct {
    const uint8_t *payload_ptr; // Points to a part of 'context->in_packet_buffer' --> must not be modified!
    size_t payload_size;
    uint8_t carried_protocol;
    bool is_fragment; // Not necessary, but improves code readability and lowers the chance of a programming mistake happening
} _t64ts_xlat_6to4_icmp__out_ipv4_packet_in_error_data;


static bool _t64f_xlat_6to4_icmp__validate_and_translate_icmp_type_and_code(const uint8_t old_icmpv6_type, const uint8_t old_icmpv6_code, uint8_t *new_icmpv4_type, uint8_t *new_icmpv4_code);
static bool _t64f_xlat_6to4_icmp__validate_and_translate_rest_of_header(const t64ts_tundra__xlat_thread_context *context, const uint8_t old_icmpv6_type, const uint8_t old_icmpv6_code, const uint8_t *old_icmpv6_rest_of_header, uint8_t *new_icmpv4_rest_of_header);
static uint16_t _t64f_xlat_6to4_icmp__recalculate_packet_too_big_mtu(const t64ts_tundra__xlat_thread_context *context, uint16_t mtu);
static bool _t64f_xlat_6to4_icmp__translate_parameter_problem_pointer(const uint8_t old_pointer, uint8_t *new_pointer);
static bool _t64f_xlat_6to4_icmp__validate_and_translate_ip_header_of_packet_in_error(t64ts_tundra__xlat_thread_context *context, const uint8_t *in_icmpv6_payload_ptr, const size_t in_icmpv6_payload_size, uint8_t *out_packet_in_error_buffer_28b, _t64ts_xlat_6to4_icmp__out_ipv4_packet_in_error_data *out_packet_in_error_data, const bool dont_fragment);


bool t64f_xlat_6to4_icmp__translate_icmpv6_to_icmpv4(t64ts_tundra__xlat_thread_context *context, const uint8_t *in_packet_payload_ptr, const size_t in_packet_payload_size, t64ts_xlat_6to4_icmp__out_icmpv4_message_data *out_message_data) {
    if(in_packet_payload_size < 8)
        return false;

    const struct icmp6hdr *in_icmpv6_header = (const struct icmp6hdr *) in_packet_payload_ptr;
    struct icmphdr *out_icmpv4_header = (struct icmphdr *) out_message_data->message_start_36b;
    out_message_data->message_start_size_m8u = 8;


    // :: Type & Code
    if(!_t64f_xlat_6to4_icmp__validate_and_translate_icmp_type_and_code(
        in_icmpv6_header->icmp6_type,
        in_icmpv6_header->icmp6_code,
        &out_icmpv4_header->type,
        &out_icmpv4_header->code
    )) return false;


    // :: Rest of header
    if(!_t64f_xlat_6to4_icmp__validate_and_translate_rest_of_header(
        context,
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
        _t64ts_xlat_6to4_icmp__out_ipv4_packet_in_error_data out_packet_in_error_data;
        if(!_t64f_xlat_6to4_icmp__validate_and_translate_ip_header_of_packet_in_error(
            context,
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
            struct icmphdr *new_icmpv4_packet_in_error_payload_ptr = (struct icmphdr *) (out_message_data->message_start_36b + 28);
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
        out_message_data->zeroable_message_end_size = T64MM_UTILS__MINIMUM(
            out_message_data->zeroable_message_end_size,
            (556 - out_message_data->message_start_size_m8u)
        );
    }


    // :: Checksum
    out_icmpv4_header->checksum = 0;
    out_icmpv4_header->checksum = t64f_checksum__calculate_rfc1071_checksum_for_ipv4(
        out_message_data->message_start_36b,
        out_message_data->message_start_size_m8u,
        out_message_data->nullable_message_end_ptr,
        out_message_data->zeroable_message_end_size,
        NULL
    );


    return true;
}

static bool _t64f_xlat_6to4_icmp__validate_and_translate_icmp_type_and_code(const uint8_t old_icmpv6_type, const uint8_t old_icmpv6_code, uint8_t *new_icmpv4_type, uint8_t *new_icmpv4_code) {
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

static bool _t64f_xlat_6to4_icmp__validate_and_translate_rest_of_header(const t64ts_tundra__xlat_thread_context *context, const uint8_t old_icmpv6_type, const uint8_t old_icmpv6_code, const uint8_t *old_icmpv6_rest_of_header, uint8_t *new_icmpv4_rest_of_header) {
    // Echo Request, Echo Reply
    if(old_icmpv6_type == 128 || old_icmpv6_type == 129) {
        memcpy(new_icmpv4_rest_of_header, old_icmpv6_rest_of_header, 4);
        return true;
    }

    // Packet Too Big
    if(old_icmpv6_type == 2) {
        if(!T64M_UTILS__MEMORY_EQUAL(old_icmpv6_rest_of_header, "\x00\x00", 2))
            return false;
        T64M_UTILS__MEMORY_ZERO_OUT(new_icmpv4_rest_of_header, 2);

        const uint16_t old_mtu = ntohs(*((const uint16_t *) (old_icmpv6_rest_of_header + 2)));
        const uint16_t new_mtu = _t64f_xlat_6to4_icmp__recalculate_packet_too_big_mtu(context, old_mtu);
        *((uint16_t *) (new_icmpv4_rest_of_header + 2)) = htons(new_mtu);

        return true;
    }

    // Parameter Problem
    if(old_icmpv6_type == 4) {
        if(old_icmpv6_code == 0) { // Erroneous header field encountered
            if(!T64M_UTILS__MEMORY_EQUAL(old_icmpv6_rest_of_header, "\x00\x00\x00", 3))
                return false;
            T64M_UTILS__MEMORY_ZERO_OUT(new_icmpv4_rest_of_header + 1, 3);

            return _t64f_xlat_6to4_icmp__translate_parameter_problem_pointer(old_icmpv6_rest_of_header[3], new_icmpv4_rest_of_header);
        }

        // Unrecognized Next Header type encountered (the old ICMPv6 rest of header, containing a pointer, is not validated intentionally)
        T64M_UTILS__MEMORY_ZERO_OUT(new_icmpv4_rest_of_header, 4);
        return true;
    }

    // All the other message types & codes
    if(!T64M_UTILS__MEMORY_EQUAL(old_icmpv6_rest_of_header, "\x00\x00\x00\x00", 4))
        return false;

    T64M_UTILS__MEMORY_ZERO_OUT(new_icmpv4_rest_of_header, 4);
    return true;
}

// Both the argument-passed and the returned value is in host byte order!
static uint16_t _t64f_xlat_6to4_icmp__recalculate_packet_too_big_mtu(const t64ts_tundra__xlat_thread_context *context, uint16_t mtu) {
    // Although the minimum IPv6 MTU is 1280 bytes, some networks may be broken

    // https://datatracker.ietf.org/doc/html/rfc7915#page-21
    mtu = T64MM_UTILS__MAXIMUM(20, mtu); // Integer overflow prevention
    mtu = T64MM_UTILS__MINIMUM(mtu - 20, (uint16_t) context->configuration->translator_ipv4_outbound_mtu);
    mtu = T64MM_UTILS__MINIMUM(mtu, ((uint16_t) context->configuration->translator_ipv6_outbound_mtu) - 20);
    mtu = T64MM_UTILS__MAXIMUM(68, mtu);

    return mtu;
}

static bool _t64f_xlat_6to4_icmp__translate_parameter_problem_pointer(const uint8_t old_pointer, uint8_t *new_pointer) {
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

static bool _t64f_xlat_6to4_icmp__validate_and_translate_ip_header_of_packet_in_error(t64ts_tundra__xlat_thread_context *context, const uint8_t *in_icmpv6_payload_ptr, const size_t in_icmpv6_payload_size, uint8_t *out_packet_in_error_buffer_28b, _t64ts_xlat_6to4_icmp__out_ipv4_packet_in_error_data *out_packet_in_error_data, const bool dont_fragment) {
    if(in_icmpv6_payload_size < 40)
        return false;

    const struct ipv6hdr *in_ipv6_header = (const struct ipv6hdr *) in_icmpv6_payload_ptr;
    struct iphdr *out_ipv4_header = (struct iphdr *) out_packet_in_error_buffer_28b;

    if(in_ipv6_header->version != 6)
        return false;

    // Translation
    out_ipv4_header->version = 4;
    out_ipv4_header->ihl = 5; // 20 bytes
    out_ipv4_header->tos = (uint8_t) ((in_ipv6_header->priority << 4) | (in_ipv6_header->flow_lbl[0] >> 4));
    out_ipv4_header->tot_len = htons(ntohs(in_ipv6_header->payload_len) + 20);
    out_ipv4_header->ttl = in_ipv6_header->hop_limit;

    {
        const uint8_t *current_header_ptr = (in_icmpv6_payload_ptr + 40);
        ssize_t remaining_packet_size = ((ssize_t) in_icmpv6_payload_size) - 40;
        uint8_t current_header_number = in_ipv6_header->nexthdr;
        const t64ts_tundra__ipv6_fragment_header *ipv6_fragment_header_ptr = NULL;

        while(
            (ipv6_fragment_header_ptr == NULL) &&
            (current_header_number == 0 || current_header_number == 43 || current_header_number == 44 || current_header_number == 60)
        ) {
            if(remaining_packet_size < 8)
                return false;

            if(current_header_number == 44)
                ipv6_fragment_header_ptr = (const t64ts_tundra__ipv6_fragment_header *) current_header_ptr;

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
            out_ipv4_header->frag_off = T64M_UTILS_IP__CONSTRUCT_IPV4_FRAGMENT_OFFSET_AND_FLAGS_FIELD(
                (uint16_t) dont_fragment,
                T64M_UTILS_IP__GET_IPV6_FRAGMENT_MORE_FRAGMENTS_BIT(ipv6_fragment_header_ptr),
                T64M_UTILS_IP__GET_IPV6_FRAGMENT_OFFSET(ipv6_fragment_header_ptr)
            );
        } else {
            t64f_utils_ip__generate_ipv4_fragment_identifier(context, (uint8_t *) &out_ipv4_header->id);
            out_ipv4_header->frag_off = T64M_UTILS_IP__CONSTRUCT_IPV4_FRAGMENT_OFFSET_AND_FLAGS_FIELD((uint16_t) dont_fragment, 0, 0);
        }

        const uint8_t ipv4_protocol = (current_header_number == 58) ? 1 : current_header_number;
        out_packet_in_error_data->carried_protocol = ipv4_protocol;
        out_ipv4_header->protocol = ipv4_protocol;
    }

    if(!t64f_xlat_addr__perform_6to4_address_translation_for_icmp_error_packet(
        context,
        (const uint8_t *) in_ipv6_header->saddr.s6_addr,
        (const uint8_t *) in_ipv6_header->daddr.s6_addr,
        (uint8_t *) &out_ipv4_header->saddr,
        (uint8_t *) &out_ipv4_header->daddr
    )) return false;

    out_ipv4_header->check = 0;
    out_ipv4_header->check = t64f_checksum__calculate_ipv4_header_checksum(out_ipv4_header);

    out_packet_in_error_data->is_fragment = (bool) T64MM_UTILS_IP__IS_IPV4_PACKET_FRAGMENTED(out_ipv4_header);

    return true;
}
