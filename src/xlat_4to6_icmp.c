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
#include"xlat_4to6_icmp.h"

#include"utils.h"
#include"utils_ip.h"
#include"checksum.h"
#include"xlat_addr.h"


typedef struct _out_ipv6_packet_in_error_data {
    const uint8_t *payload_ptr; // Points to a part of 'ctx->in_packet_buffer' --> must not be modified!
    size_t payload_size;
    uint8_t carried_protocol;
    bool is_fragment; // Not necessary, but improves code readability and lowers the chance of a programming mistake happening
} _out_ipv6_packet_in_error_data;


// See RFC 1191 - https://datatracker.ietf.org/doc/html/rfc1191
// The array must be zero-terminated, and the integers must be in descending order!
static const uint16_t _plateau_mtus[] = {
    65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68, 0
};
static const uint16_t _default_plateau_mtu = 68; // Used when the MTU value cannot be decided from the above defined array (for whatever reason).


static bool _validate_and_translate_icmp_type_and_code(const uint8_t old_icmpv4_type, const uint8_t old_icmpv4_code, uint8_t *new_icmpv6_type, uint8_t *new_icmpv6_code);
static bool _validate_and_translate_rest_of_icmp_header(const tundra__thread_ctx *const ctx, const uint8_t *old_icmpv4_payload_ptr, const size_t old_icmpv4_payload_size, const uint8_t old_icmpv4_type, const uint8_t old_icmpv4_code, const uint8_t *old_icmpv4_rest_of_header, uint8_t *new_icmpv6_rest_of_header);
static uint16_t _recalculate_packet_too_big_mtu(const tundra__thread_ctx *const ctx, const uint8_t *old_icmpv4_payload_ptr, const size_t old_icmpv4_payload_size, uint16_t mtu);
static uint16_t _estimate_likely_mtu(const uint8_t *old_icmpv4_payload_ptr, const size_t old_icmpv4_payload_size);
static bool _translate_parameter_problem_pointer(const uint8_t old_pointer, uint8_t *new_pointer);
static bool _validate_and_translate_ip_header_of_packet_in_error(tundra__thread_ctx *const ctx, const uint8_t *in_icmpv4_payload_ptr, const size_t in_icmpv4_payload_size, uint8_t *out_packet_in_error_buffer_56b, _out_ipv6_packet_in_error_data *const out_packet_in_error_data);


bool xlat_4to6_icmp__translate_icmpv4_to_icmpv6(tundra__thread_ctx *const ctx, const uint8_t *in_packet_payload_ptr, const size_t in_packet_payload_size, const struct ipv6hdr *out_packet_ipv6_header_ptr, xlat_4to6_icmp__out_icmpv6_message_data *const out_message_data) {
    if(in_packet_payload_size < 8)
        return false;


    // IMPROVE: Due to the fact that the IHL field in IPv4 header specifies the header length in 4-byte units, this
    //  pointer should always be at least 4-byte aligned. However, this fact is by no means obvious from the source
    //  code, and a subtle change in a seemingly unrelated part of the program could break this assumption - for this
    //  reason, this line is marked for future improvement (which would, however, likely require copying stuff around,
    //  perhaps slowing the program down).
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wcast-align"
    const struct icmphdr *in_icmpv4_header = (const struct icmphdr *) in_packet_payload_ptr;
    #pragma GCC diagnostic pop

    struct icmp6hdr *out_icmpv6_header = (struct icmp6hdr *) __builtin_assume_aligned(out_message_data->message_start_64b, 64);
    out_message_data->message_start_size_m8 = 8;


    // :: Type & Code
    if(!_validate_and_translate_icmp_type_and_code(
        in_icmpv4_header->type,
        in_icmpv4_header->code,
        &out_icmpv6_header->icmp6_type,
        &out_icmpv6_header->icmp6_code
    )) return false;


    // :: Rest of header
    const uint8_t *in_icmpv4_payload_ptr = (in_packet_payload_ptr + 8);
    const size_t in_icmpv4_payload_size = (in_packet_payload_size - 8);

    if(!_validate_and_translate_rest_of_icmp_header(
        ctx,
        in_icmpv4_payload_ptr,
        in_icmpv4_payload_size,
        in_icmpv4_header->type,
        in_icmpv4_header->code,
        (in_packet_payload_ptr + 4),
        (out_message_data->message_start_64b + 4)
    )) return false;


    // :: Payload
    if(in_icmpv4_header->type == 0 || in_icmpv4_header->type == 8) { // Echo Reply, Echo Request
        out_message_data->message_end_ptr = in_icmpv4_payload_ptr;
        out_message_data->message_end_size = in_icmpv4_payload_size;

    } else { // ICMP Error message
        _out_ipv6_packet_in_error_data out_packet_in_error_data;
        if(!_validate_and_translate_ip_header_of_packet_in_error(
            ctx,
            in_icmpv4_payload_ptr,
            in_icmpv4_payload_size,
            (out_message_data->message_start_64b + 8),
            &out_packet_in_error_data
        )) return false;
        out_message_data->message_start_size_m8 += (out_packet_in_error_data.is_fragment ? 48 : 40);

        if(out_packet_in_error_data.carried_protocol == 58) { // ICMPv6
            // If the packet in error is a fragment or its payload is smaller than 8 bytes, it is not possible to tell
            //  if it is an ICMP Echo packet, and therefore it is dropped
            if(out_packet_in_error_data.is_fragment || out_packet_in_error_data.payload_size < 8)
                return false;

            // Since 'out_message_data->message_start_64b' is always 64-byte aligned, is can be assumed, that if the
            //  pointer is moved 48 bytes forward, the resulting pointer will always be 16-byte aligned.
            struct icmp6hdr *new_icmpv6_packet_in_error_payload_ptr = (struct icmp6hdr *) __builtin_assume_aligned(out_message_data->message_start_64b + 48, 16);
            memcpy(new_icmpv6_packet_in_error_payload_ptr, out_packet_in_error_data.payload_ptr, 8);
            out_message_data->message_start_size_m8 += 8;

            /*
             * https://datatracker.ietf.org/doc/html/rfc7915#page-14 states:
             * "The translation of the inner IP header can be done by invoking the
             *  function that translated the outer IP headers.  This process MUST
             *  stop at the first embedded header and drop the packet if it contains
             *  more embedded headers."
             *
             *  Echo Reply and Echo Request are the only translatable ICMP types that do not carry a packet "in error".
             */
            if(new_icmpv6_packet_in_error_payload_ptr->icmp6_code != 0)
                return false;

            if(new_icmpv6_packet_in_error_payload_ptr->icmp6_type == 0) // Echo Reply
                new_icmpv6_packet_in_error_payload_ptr->icmp6_type = 129;
            else if(new_icmpv6_packet_in_error_payload_ptr->icmp6_type == 8) // Echo Request
                new_icmpv6_packet_in_error_payload_ptr->icmp6_type = 128;
            else
                return false;

            out_message_data->message_end_ptr = (out_packet_in_error_data.payload_ptr + 8);
            out_message_data->message_end_size = (out_packet_in_error_data.payload_size - 8);
        } else { // All other transport protocols
            out_message_data->message_end_ptr = out_packet_in_error_data.payload_ptr;
            out_message_data->message_end_size = out_packet_in_error_data.payload_size;
        }

        // ICMPv6 error messages should be 1280 bytes in size at maximum
        out_message_data->message_end_size = UTILS__MINIMUM_UNSAFE(
            out_message_data->message_end_size,
            (1240 - out_message_data->message_start_size_m8)
        );
    }


    // :: Checksum
    out_icmpv6_header->icmp6_cksum = 0;
    out_icmpv6_header->icmp6_cksum = checksum__calculate_checksum_ipv6(
        out_message_data->message_start_64b,
        out_message_data->message_start_size_m8,
        out_message_data->message_end_ptr,
        out_message_data->message_end_size,
        out_packet_ipv6_header_ptr, // For pseudo-header checksum computation
        58
    );


    return true;
}

static bool _validate_and_translate_icmp_type_and_code(const uint8_t old_icmpv4_type, const uint8_t old_icmpv4_code, uint8_t *new_icmpv6_type, uint8_t *new_icmpv6_code) {
    switch(old_icmpv4_type) {
        case 8: // Echo Request
            {
                if(old_icmpv4_code != 0)
                    return false;

                *new_icmpv6_type = 128;
                *new_icmpv6_code = 0;
            }
            break;

        case 0: // Echo Reply
            {
                if(old_icmpv4_code != 0)
                    return false;

                *new_icmpv6_type = 129;
                *new_icmpv6_code = 0;
            }
            break;

        case 3: // Destination Unreachable
            switch(old_icmpv4_code) {
                case 0: case 1: case 5: case 6: case 7: case 8: case 11: case 12: // Net Unreachable, Host Unreachable, Source Route Failed
                    *new_icmpv6_type = 1;
                    *new_icmpv6_code = 0;
                    break;

                case 9: case 10: case 13: case 15: // Communication with Destination Host Administratively Prohibited, Communication Administratively Prohibited, Precedence cutoff in effect
                    *new_icmpv6_type = 1;
                    *new_icmpv6_code = 1;
                    break;

                case 2: // Protocol Unreachable
                    *new_icmpv6_type = 4;
                    *new_icmpv6_code = 1;
                    break;

                case 3: // Port Unreachable
                    *new_icmpv6_type = 1;
                    *new_icmpv6_code = 4;
                    break;

                case 4: // Fragmentation Needed and DF was Set
                    *new_icmpv6_type = 2;
                    *new_icmpv6_code = 0;
                    break;

                default:
                    // All other codes, including:
                    // - Code 14 (Host Precedence Violation)
                    return false;
            }
            break;

        case 11: // Time Exceeded
            {
                if(old_icmpv4_code != 0 && old_icmpv4_code != 1)
                    return false;

                *new_icmpv6_type = 3;
                *new_icmpv6_code = old_icmpv4_code;
            }
            break;

        case 12: // Parameter Problem
            {
                if(old_icmpv4_code != 0 && old_icmpv4_code != 2)
                    return false;

                *new_icmpv6_type = 4;
                *new_icmpv6_code = 0;
            }
            break;

        default:
            // All other types, including:
            // - Information Request/Reply (Type 15 and Type 16)
            // - Timestamp and Timestamp Reply (Type 13 and Type 14)
            // - Address Mask Request/Reply (Type 17 and Type 18)
            // - ICMP Router Advertisement (Type 9)
            // - ICMP Router Solicitation (Type 10)
            // - Redirect (Type 5)
            // - Alternative Host Address (Type 6)
            // - Source Quench (Type 4)
            return false;
    }

    return true;
}

static bool _validate_and_translate_rest_of_icmp_header(const tundra__thread_ctx *const ctx, const uint8_t *old_icmpv4_payload_ptr, const size_t old_icmpv4_payload_size, const uint8_t old_icmpv4_type, const uint8_t old_icmpv4_code, const uint8_t *old_icmpv4_rest_of_header, uint8_t *new_icmpv6_rest_of_header) {
    // Echo Reply, Echo Request
    if(old_icmpv4_type == 0 || old_icmpv4_type == 8) {
        memcpy(new_icmpv6_rest_of_header, old_icmpv4_rest_of_header, 4);
        return true;
    }

    // Destination Unreachable
    if(old_icmpv4_type == 3) {
        if(old_icmpv4_code == 2) { // Protocol Unreachable
            if(!UTILS__MEM_EQ(old_icmpv4_rest_of_header, "\x00\x00\x00\x00", 4))
                return false;

            UTILS__MEM_ZERO_OUT(new_icmpv6_rest_of_header, 3);
            new_icmpv6_rest_of_header[3] = 6; // Pointer points to the "Next header" field
            return true;
        }

        if(old_icmpv4_code == 4) { // Fragmentation Needed and DF was Set
            if(!UTILS__MEM_EQ(old_icmpv4_rest_of_header, "\x00\x00", 2))
                return false;
            UTILS__MEM_ZERO_OUT(new_icmpv6_rest_of_header, 2);

            // Memory alignment
            uint16_t old_mtu;
            memcpy(&old_mtu, old_icmpv4_rest_of_header + 2, 2);
            old_mtu = ntohs(old_mtu);

            uint16_t new_mtu = _recalculate_packet_too_big_mtu(ctx, old_icmpv4_payload_ptr, old_icmpv4_payload_size, old_mtu);
            new_mtu = htons(new_mtu);
            memcpy(new_icmpv6_rest_of_header + 2, &new_mtu, 2);

            return true;
        }
    }

    // Parameter Problem
    if(old_icmpv4_type == 12) {
        if(!UTILS__MEM_EQ(old_icmpv4_rest_of_header + 1, "\x00\x00\x00", 3))
            return false;
        UTILS__MEM_ZERO_OUT(new_icmpv6_rest_of_header, 3);

        return _translate_parameter_problem_pointer(*old_icmpv4_rest_of_header, new_icmpv6_rest_of_header + 3);
    }

    // All the other message types & codes
    if(!UTILS__MEM_EQ(old_icmpv4_rest_of_header, "\x00\x00\x00\x00", 4))
        return false;

    UTILS__MEM_ZERO_OUT(new_icmpv6_rest_of_header, 4);
    return true;
}

// Both the argument-passed and the returned value is in host byte order!
static uint16_t _recalculate_packet_too_big_mtu(const tundra__thread_ctx *const ctx, const uint8_t *old_icmpv4_payload_ptr, const size_t old_icmpv4_payload_size, uint16_t mtu) {
    if(mtu == 0)
        mtu = _estimate_likely_mtu(old_icmpv4_payload_ptr, old_icmpv4_payload_size);

    // Although the minimum IPv4 MTU is 68 bytes, some networks may be broken

    // https://datatracker.ietf.org/doc/html/rfc7915#page-11
    mtu = (uint16_t) UTILS__MINIMUM_UNSAFE(65515, mtu); // Integer overflow prevention
    mtu = (uint16_t) UTILS__MINIMUM_UNSAFE(mtu + 20, (uint16_t) ctx->config->translator_ipv6_outbound_mtu);
    mtu = (uint16_t) UTILS__MINIMUM_UNSAFE(mtu, ((uint16_t) ctx->config->translator_ipv4_outbound_mtu) + 20);
    mtu = (uint16_t) UTILS__MAXIMUM_UNSAFE(1280, mtu);

    return mtu;
}

// See RFC 1191 - https://datatracker.ietf.org/doc/html/rfc1191
static uint16_t _estimate_likely_mtu(const uint8_t *old_icmpv4_payload_ptr, const size_t old_icmpv4_payload_size) {
    if(old_icmpv4_payload_size < 20)
        return _default_plateau_mtu;


    // IMPROVE: As of now, this pointer should always be at least 4-byte aligned; however, this fact is by no means
    //  obvious from the source code and a change in a seemingly unrelated part of code could break this assumption -
    //  for this reason, this line is marked for future improvement.
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wcast-align"
    const struct iphdr *packet_in_error = (const struct iphdr *) old_icmpv4_payload_ptr;
    #pragma GCC diagnostic pop


    const uint16_t packet_in_error_total_length = ntohs(packet_in_error->tot_len);
    for(size_t i = 0; _plateau_mtus[i] != 0; i++) {
        if(_plateau_mtus[i] < packet_in_error_total_length)
            return _plateau_mtus[i];
    }

    return _default_plateau_mtu;
}

static bool _translate_parameter_problem_pointer(const uint8_t old_pointer, uint8_t *new_pointer) {
    // https://datatracker.ietf.org/doc/html/rfc7915#page-13
    switch(old_pointer) {
        case 0: case 1:
            *new_pointer = old_pointer;
            break;

        case 2: case 3:
            *new_pointer = 4;
            break;

        case 8:
            *new_pointer = 7;
            break;

        case 9:
            *new_pointer = 6;
            break;

        case 12: case 13: case 14: case 15:
            *new_pointer = 8;
            break;

        case 16: case 17: case 18: case 19:
            *new_pointer = 24;
            break;

        default:
            // Including, but not limited to the following values: 4, 5, 6, 7, 10, 11
            return false;
    }

    return true;
}

static bool _validate_and_translate_ip_header_of_packet_in_error(tundra__thread_ctx *const ctx, const uint8_t *in_icmpv4_payload_ptr, const size_t in_icmpv4_payload_size, uint8_t *out_packet_in_error_buffer_56b, _out_ipv6_packet_in_error_data *const out_packet_in_error_data) {
    if(in_icmpv4_payload_size < 20)
        return false;


    // IMPROVE: As of now, both pointers should always be at least 4-byte aligned; however, this fact is by no means
    //  obvious from the source code and a change in a seemingly unrelated part of code could break this assumption -
    //  for this reason, these lines are marked for future improvement.
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wcast-align"
    const struct iphdr *in_ipv4_header = (const struct iphdr *) in_icmpv4_payload_ptr;
    struct ipv6hdr *out_ipv6_header = (struct ipv6hdr *) out_packet_in_error_buffer_56b;
    #pragma GCC diagnostic pop



    // :: Basic validation
    if(in_ipv4_header->version != 4)
        return false;

    const size_t in_ipv4_header_size = ((size_t) in_ipv4_header->ihl) * 4;
    if(in_ipv4_header_size < 20 || in_ipv4_header_size > in_icmpv4_payload_size)
        return false;



    // :: Translation
    out_ipv6_header->version = 6;

    // FALSE-POSITIVE: The value assigned to 'out_ipv6_header->priority' cannot be such that it would not fit into
    //  4 bits; however, since C does not support bit-field type casts, e.g. '(uint8_t : 4)', there seems to be
    //  no other way to let the compiler know that this is OK other than to ignore this warning.
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wconversion"
    out_ipv6_header->priority = (uint8_t) (in_ipv4_header->tos >> 4);
    #pragma GCC diagnostic pop

    out_ipv6_header->flow_lbl[0] = (uint8_t) (in_ipv4_header->tos << 4);
    out_ipv6_header->flow_lbl[1] = 0;
    out_ipv6_header->flow_lbl[2] = 0;
    out_ipv6_header->payload_len = htons(
        // An integer overflow might occur here, but it does not really matter in this case, as we are translating a
        //  packet in error, which is expected to be "broken" in some way...
        (uint16_t) (ntohs(in_ipv4_header->tot_len) - (uint16_t) in_ipv4_header_size)
    );
    out_ipv6_header->hop_limit = in_ipv4_header->ttl;


    const uint8_t ipv6_carried_protocol = (in_ipv4_header->protocol == 1) ? 58 : in_ipv4_header->protocol;

    if(UTILS_IP__IS_IPV4_PACKET_FRAGMENTED_UNSAFE(in_ipv4_header)) {
        out_ipv6_header->nexthdr = 44;

        tundra__ipv6_frag_header *out_ipv6_fragment_header = (tundra__ipv6_frag_header *) (out_packet_in_error_buffer_56b + 40);
        out_ipv6_fragment_header->next_header = ipv6_carried_protocol;
        out_ipv6_fragment_header->reserved = 0;
        out_ipv6_fragment_header->offset_and_flags = UTILS_IP__CONSTRUCT_IPV6_FRAG_OFFSET_AND_FLAGS(
            UTILS_IP__GET_IPV4_FRAG_OFFSET(in_ipv4_header),
            UTILS_IP__GET_IPV4_MORE_FRAGS(in_ipv4_header)
        );
        out_ipv6_fragment_header->identification[0] = 0;
        out_ipv6_fragment_header->identification[1] = in_ipv4_header->id;

        out_packet_in_error_data->is_fragment = true;
    } else {
        out_ipv6_header->nexthdr = ipv6_carried_protocol;

        out_packet_in_error_data->is_fragment = false;
    }


    if(!xlat_addr__translate_4to6_addr_for_icmp_error_packet(
        ctx,
        (const uint8_t *) &in_ipv4_header->saddr,
        (const uint8_t *) &in_ipv4_header->daddr,
        (uint8_t *) out_ipv6_header->saddr.s6_addr,
        (uint8_t *) out_ipv6_header->daddr.s6_addr
    )) return false;


    out_packet_in_error_data->payload_ptr = (in_icmpv4_payload_ptr + in_ipv4_header_size);
    out_packet_in_error_data->payload_size = (in_icmpv4_payload_size - in_ipv4_header_size);
    out_packet_in_error_data->carried_protocol = ipv6_carried_protocol;

    return true;
}
