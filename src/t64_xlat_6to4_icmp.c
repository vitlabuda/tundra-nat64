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
#include"t64_xlat_6to4_icmp.h"

#include"t64_utils.h"
#include"t64_utils_ip.h"
#include"t64_checksum.h"


static t64te_tundra__xlat_status _t64f_xlat_6to4_icmp__translate_echo_request_or_echo_reply_message(t64ts_tundra__xlat_thread_context *context);
static t64te_tundra__xlat_status _t64f_xlat_6to4_icmp__translate_destination_unreachable_message(t64ts_tundra__xlat_thread_context *context);
static t64te_tundra__xlat_status _t64f_xlat_6to4_icmp__translate_packet_too_big_message(t64ts_tundra__xlat_thread_context *context);
static t64te_tundra__xlat_status _t64f_xlat_6to4_icmp__translate_time_exceeded_message(t64ts_tundra__xlat_thread_context *context);
static t64te_tundra__xlat_status _t64f_xlat_6to4_icmp__translate_parameter_problem_message(t64ts_tundra__xlat_thread_context *context);
static t64te_tundra__xlat_status _t64f_xlat_6to4_icmp__translate_carried_ip_header_and_part_of_data(t64ts_tundra__xlat_thread_context *context, const int dont_fragment);
static uint8_t _t64f_xlat_6to4_icmp__translate_parameter_problem_pointer_value(const uint8_t in_pointer);


t64te_tundra__xlat_status t64f_xlat_6to4_icmp__translate_icmpv6_to_icmpv4(t64ts_tundra__xlat_thread_context *context) {
    /*
     * REQUIRED-STATE-OF-PACKET-BUFFERS:
     *
     * in_packet->packet_raw (content) -- An IPv6 packet whose headers (base header + all extension headers, if there are any) have been validated
     * in_packet->packet_size -- The IPv6 packet's size (at least 40 bytes)
     * in_packet->payload_raw -- The packet's unvalidated payload (the pointer points to the beginning of the ICMPv6 header)
     * in_packet->payload_size -- The size of the packet's unvalidated payload (zero if the packet does not carry any payload)
     * in_packet->ipv6_fragment_header -- A pointer to the fragmentation header if the packet contains it; NULL otherwise
     * in_packet->ipv6_carried_protocol_field -- A pointer to the byte which contains the number of the transport protocol carried by the packet (58 - ICMPv6)
     *
     * out_packet->packet_raw (content) -- An IPv4 header whose protocol field is set to 1 (ICMP) (and whose 'tot_len' and 'check' fields are zero - they are set just before the packet is sent out)
     * out_packet->packet_size -- The size of the IPv4 header (always 20 bytes)
     * out_packet->payload_raw -- A pointer to the first byte after the packet's header (the translated payload shall be placed here)
     * out_packet->payload_size -- Zero
     * out_packet->ipv6_fragment_header -- Undefined (as the packet is IPv4)
     * out_packet->ipv6_carried_protocol_field -- Undefined (as the packet is IPv4)
     */

    if(T64M_UTILS_IP__IS_IPV6_PACKET_FRAGMENTED(&context->in_packet) || T64MM_UTILS_IP__IS_IPV4_PACKET_FRAGMENTED(context->out_packet.packet_ipv4hdr))
        return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION;

    if(context->in_packet.payload_size < 8)
        return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION;

    if(t64f_checksum__calculate_rfc1071_checksum(&context->in_packet, true) != 0)
        return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION;

    // OUT-PACKET-REMAINING-BUFFER-SIZE: at least 1520 bytes - 20 bytes IPv4 header = at least 1500 bytes free; 8 bytes needed (for ICMP header)

    switch(context->in_packet.payload_icmpv6hdr->icmp6_type) {
        case 128: case 129: // Echo Request and Echo Reply
            if(_t64f_xlat_6to4_icmp__translate_echo_request_or_echo_reply_message(context) != T64TE_TUNDRA__XLAT_STATUS_CONTINUE_TRANSLATION)
                return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION;
            break;

        case 1: // Destination Unreachable
            if(_t64f_xlat_6to4_icmp__translate_destination_unreachable_message(context) != T64TE_TUNDRA__XLAT_STATUS_CONTINUE_TRANSLATION)
                return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION;
            break;

        case 2: // Packet Too Big
            if(_t64f_xlat_6to4_icmp__translate_packet_too_big_message(context) != T64TE_TUNDRA__XLAT_STATUS_CONTINUE_TRANSLATION)
                return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION;
            break;

        case 3: // Time Exceeded
            if(_t64f_xlat_6to4_icmp__translate_time_exceeded_message(context) != T64TE_TUNDRA__XLAT_STATUS_CONTINUE_TRANSLATION)
                return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION;
            break;

        case 4: // Parameter Problem
            if(_t64f_xlat_6to4_icmp__translate_parameter_problem_message(context) != T64TE_TUNDRA__XLAT_STATUS_CONTINUE_TRANSLATION)
                return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION;
            break;

        default:
            // All other types, including:
            // - MLD Multicast Listener Query/Report/Done (Type 130, 131, 132)
            // - Neighbor Discover messages (Type 133 through 137)
            return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION;
    }

    if(context->out_packet.payload_size < 8)
        return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION; // Just to make sure...

    context->out_packet.payload_icmpv4hdr->checksum = 0;
    context->out_packet.payload_icmpv4hdr->checksum = t64f_checksum__calculate_rfc1071_checksum(&context->out_packet, false);

    return T64TE_TUNDRA__XLAT_STATUS_CONTINUE_TRANSLATION;
}

// Types 128 and 129 - Echo Request and Echo Reply
static t64te_tundra__xlat_status _t64f_xlat_6to4_icmp__translate_echo_request_or_echo_reply_message(t64ts_tundra__xlat_thread_context *context) {
    /*
     * REQUIRED-STATE-OF-PACKET-BUFFERS:
     *
     * in_packet->packet_raw (content) -- An unfragmented (!) IPv6 packet whose headers (base header + all extension headers, if there are any) have been validated
     * in_packet->packet_size -- The IPv6 packet's size which contains at least an ICMPv6 header (at least 48 bytes)
     * in_packet->payload_raw -- The packet's unvalidated ICMPv6 payload (the pointer points to the beginning of the ICMPv6 8-byte header, which is guaranteed to be there)
     * in_packet->payload_size -- The size of the packet's unvalidated ICMPv6 payload (at least 8 bytes - an 8-byte ICMPv6 header is guaranteed to be there)
     * in_packet->ipv6_fragment_header -- NULL
     * in_packet->ipv6_carried_protocol_field -- A pointer to the byte which contains the number of the transport protocol carried by the packet (58 - ICMPv6)
     *
     * out_packet->packet_raw (content) -- An IPv4 header whose protocol field is set to 1 (ICMP) (and whose 'tot_len' and 'check' fields are zero - they are set just before the packet is sent out)
     * out_packet->packet_size -- The size of the IPv4 header (always 20 bytes)
     * out_packet->payload_raw -- A pointer to the first byte after the packet's header (the translated payload shall be placed here)
     * out_packet->payload_size -- Zero
     * out_packet->ipv6_fragment_header -- Undefined (as the packet is IPv4)
     * out_packet->ipv6_carried_protocol_field -- Undefined (as the packet is IPv4)
     */

    // Copy the whole packet's payload
    if(!t64f_utils__secure_memcpy(
        context->out_packet.payload_raw,
        context->in_packet.payload_raw,
        context->in_packet.payload_size,
        (T64C_TUNDRA__MAX_PACKET_SIZE - context->out_packet.packet_size)
    )) return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION;

    // Adjust type
    if(context->out_packet.payload_icmpv4hdr->type == 128) // Echo request
        context->out_packet.payload_icmpv4hdr->type = 8;
    else if(context->out_packet.payload_icmpv4hdr->type == 129) // Echo reply
        context->out_packet.payload_icmpv4hdr->type = 0;
    else
        return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION; // This should never happen!

    // Check code
    if(context->out_packet.payload_icmpv4hdr->code != 0)
        return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION;

    context->out_packet.packet_size += context->in_packet.payload_size;
    context->out_packet.payload_size = context->in_packet.payload_size;

    return T64TE_TUNDRA__XLAT_STATUS_CONTINUE_TRANSLATION;
}

// Type 1 - Destination Unreachable
static t64te_tundra__xlat_status _t64f_xlat_6to4_icmp__translate_destination_unreachable_message(t64ts_tundra__xlat_thread_context *context) {
    /*
     * REQUIRED-STATE-OF-PACKET-BUFFERS:
     *
     * in_packet->packet_raw (content) -- An unfragmented (!) IPv6 packet whose headers (base header + all extension headers, if there are any) have been validated
     * in_packet->packet_size -- The IPv6 packet's size which contains at least an ICMPv6 header (at least 48 bytes)
     * in_packet->payload_raw -- The packet's unvalidated ICMPv6 payload (the pointer points to the beginning of the ICMPv6 8-byte header, which is guaranteed to be there)
     * in_packet->payload_size -- The size of the packet's unvalidated ICMPv6 payload (an 8-byte ICMPv6 header is guaranteed to be there)
     * in_packet->ipv6_fragment_header -- NULL
     * in_packet->ipv6_carried_protocol_field -- A pointer to the byte which contains the number of the transport protocol carried by the packet (58 - ICMPv6)
     *
     * out_packet->packet_raw (content) -- An IPv4 header whose protocol field is set to 1 (ICMP) (and whose 'tot_len' and 'check' fields are zero - they are set just before the packet is sent out)
     * out_packet->packet_size -- The size of the IPv4 header (always 20 bytes)
     * out_packet->payload_raw -- A pointer to the first byte after the packet's header (the translated payload shall be placed here)
     * out_packet->payload_size -- Zero
     * out_packet->ipv6_fragment_header -- Undefined (as the packet is IPv4)
     * out_packet->ipv6_carried_protocol_field -- Undefined (as the packet is IPv4)
     */

    // Check & evaluate inbound ICMPv6 header
    uint8_t out_icmp_code;
    switch(context->in_packet.payload_icmpv6hdr->icmp6_code) {
        case 0: case 2: case 3: // No route to destination, Beyond scope of source address, Address unreachable
            out_icmp_code = 1;
            break;

        case 1: // Communication with destination administratively prohibited
            out_icmp_code = 10;
            break;

        case 4: // Port unreachable
            out_icmp_code = 3;
            break;

        default:
            return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION;
    }

    if(!T64M_UTILS__MEMORY_EQUAL(context->in_packet.payload_raw + 4, "\x00\x00\x00\x00", 4))
        return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION;

    // Generate outbound ICMPv4 header
    t64f_utils_ip__generate_basic_icmpv4v6_header_to_empty_packet_payload(&context->out_packet, 3, out_icmp_code);

    // Build carried IP header & part of data
    if(_t64f_xlat_6to4_icmp__translate_carried_ip_header_and_part_of_data(context, 0) != T64TE_TUNDRA__XLAT_STATUS_CONTINUE_TRANSLATION)
        return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION;

    return T64TE_TUNDRA__XLAT_STATUS_CONTINUE_TRANSLATION;
}

// Type 2 - Packet Too Big
static t64te_tundra__xlat_status _t64f_xlat_6to4_icmp__translate_packet_too_big_message(t64ts_tundra__xlat_thread_context *context) {
    /*
     * REQUIRED-STATE-OF-PACKET-BUFFERS:
     *
     * in_packet->packet_raw (content) -- An unfragmented (!) IPv6 packet whose headers (base header + all extension headers, if there are any) have been validated
     * in_packet->packet_size -- The IPv6 packet's size which contains at least an ICMPv6 header (at least 48 bytes)
     * in_packet->payload_raw -- The packet's unvalidated ICMPv6 payload (the pointer points to the beginning of the ICMPv6 8-byte header, which is guaranteed to be there)
     * in_packet->payload_size -- The size of the packet's unvalidated ICMPv6 payload (an 8-byte ICMPv6 header is guaranteed to be there)
     * in_packet->ipv6_fragment_header -- NULL
     * in_packet->ipv6_carried_protocol_field -- A pointer to the byte which contains the number of the transport protocol carried by the packet (58 - ICMPv6)
     *
     * out_packet->packet_raw (content) -- An IPv4 header whose protocol field is set to 1 (ICMP) (and whose 'tot_len' and 'check' fields are zero - they are set just before the packet is sent out)
     * out_packet->packet_size -- The size of the IPv4 header (always 20 bytes)
     * out_packet->payload_raw -- A pointer to the first byte after the packet's header (the translated payload shall be placed here)
     * out_packet->payload_size -- Zero
     * out_packet->ipv6_fragment_header -- Undefined (as the packet is IPv4)
     * out_packet->ipv6_carried_protocol_field -- Undefined (as the packet is IPv4)
     */

    // Check inbound ICMPv6 header
    if(context->in_packet.payload_icmpv6hdr->icmp6_code != 0)
        return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION;

    if(!T64M_UTILS__MEMORY_EQUAL(context->in_packet.payload_raw + 4, "\x00\x00", 2))
        return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION; // = MTUs bigger than 65535 bytes cannot be handled when performing IPv6-to-IPv4 translation

    // Generate outbound ICMPv4 header
    t64f_utils_ip__generate_basic_icmpv4v6_header_to_empty_packet_payload(&context->out_packet, 3, 4);

    {
        uint16_t mtu;
        memcpy(&mtu, context->in_packet.payload_raw + 6, 2); // This is a hack which overcomes the 2-byte alignment requirement for 16-bit values.
        mtu = ntohs(mtu);
        // Although the minimum IPv6 MTU is 1280 bytes, some networks may be broken

        mtu = T64MM_UTILS__MAXIMUM(20, mtu); // Integer overflow prevention

        // https://datatracker.ietf.org/doc/html/rfc7915#page-21
        mtu = T64MM_UTILS__MINIMUM(mtu - 20, (uint16_t) context->configuration->translator_ipv4_outbound_mtu);
        mtu = T64MM_UTILS__MINIMUM(mtu, ((uint16_t) context->configuration->translator_ipv6_outbound_mtu) - 20);
        mtu = T64MM_UTILS__MAXIMUM(68, mtu);

        mtu = htons(mtu);
        memcpy(context->out_packet.payload_raw + 6, &mtu, 2);
    }

    // Build carried IP header & part of data
    //  The Don't fragment flag is set in the translated carried packet, as ICMPv4 Type 3 Code 4 is literally named "Fragmentation needed and DF set"
    if(_t64f_xlat_6to4_icmp__translate_carried_ip_header_and_part_of_data(context, 1) != T64TE_TUNDRA__XLAT_STATUS_CONTINUE_TRANSLATION)
        return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION;

    return T64TE_TUNDRA__XLAT_STATUS_CONTINUE_TRANSLATION;
}

// Type 3 - Time Exceeded
static t64te_tundra__xlat_status _t64f_xlat_6to4_icmp__translate_time_exceeded_message(t64ts_tundra__xlat_thread_context *context) {
    /*
     * REQUIRED-STATE-OF-PACKET-BUFFERS:
     *
     * in_packet->packet_raw (content) -- An unfragmented (!) IPv6 packet whose headers (base header + all extension headers, if there are any) have been validated
     * in_packet->packet_size -- The IPv6 packet's size which contains at least an ICMPv6 header (at least 48 bytes)
     * in_packet->payload_raw -- The packet's unvalidated ICMPv6 payload (the pointer points to the beginning of the ICMPv6 8-byte header, which is guaranteed to be there)
     * in_packet->payload_size -- The size of the packet's unvalidated ICMPv6 payload (an 8-byte ICMPv6 header is guaranteed to be there)
     * in_packet->ipv6_fragment_header -- NULL
     * in_packet->ipv6_carried_protocol_field -- A pointer to the byte which contains the number of the transport protocol carried by the packet (58 - ICMPv6)
     *
     * out_packet->packet_raw (content) -- An IPv4 header whose protocol field is set to 1 (ICMP) (and whose 'tot_len' and 'check' fields are zero - they are set just before the packet is sent out)
     * out_packet->packet_size -- The size of the IPv4 header (always 20 bytes)
     * out_packet->payload_raw -- A pointer to the first byte after the packet's header (the translated payload shall be placed here)
     * out_packet->payload_size -- Zero
     * out_packet->ipv6_fragment_header -- Undefined (as the packet is IPv4)
     * out_packet->ipv6_carried_protocol_field -- Undefined (as the packet is IPv4)
     */

    // Check inbound ICMPv6 header
    if(context->in_packet.payload_icmpv6hdr->icmp6_code != 0 && context->in_packet.payload_icmpv6hdr->icmp6_code != 1)
        return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION;

    if(!T64M_UTILS__MEMORY_EQUAL(context->in_packet.payload_raw + 4, "\x00\x00\x00\x00", 4))
        return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION;

    // Generate outbound ICMPv4 header
    t64f_utils_ip__generate_basic_icmpv4v6_header_to_empty_packet_payload(&context->out_packet, 11, context->in_packet.payload_icmpv6hdr->icmp6_code);

    // Build carried IP header & part of data
    if(_t64f_xlat_6to4_icmp__translate_carried_ip_header_and_part_of_data(context, 0) != T64TE_TUNDRA__XLAT_STATUS_CONTINUE_TRANSLATION)
        return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION;

    return T64TE_TUNDRA__XLAT_STATUS_CONTINUE_TRANSLATION;
}

// Type 4 - Parameter Problem
static t64te_tundra__xlat_status _t64f_xlat_6to4_icmp__translate_parameter_problem_message(t64ts_tundra__xlat_thread_context *context) {
    /*
     * REQUIRED-STATE-OF-PACKET-BUFFERS:
     *
     * in_packet->packet_raw (content) -- An unfragmented (!) IPv6 packet whose headers (base header + all extension headers, if there are any) have been validated
     * in_packet->packet_size -- The IPv6 packet's size which contains at least an ICMPv6 header (at least 48 bytes)
     * in_packet->payload_raw -- The packet's unvalidated ICMPv6 payload (the pointer points to the beginning of the ICMPv6 8-byte header, which is guaranteed to be there)
     * in_packet->payload_size -- The size of the packet's unvalidated ICMPv6 payload (an 8-byte ICMPv6 header is guaranteed to be there)
     * in_packet->ipv6_fragment_header -- NULL
     * in_packet->ipv6_carried_protocol_field -- A pointer to the byte which contains the number of the transport protocol carried by the packet (58 - ICMPv6)
     *
     * out_packet->packet_raw (content) -- An IPv4 header whose protocol field is set to 1 (ICMP) (and whose 'tot_len' and 'check' fields are zero - they are set just before the packet is sent out)
     * out_packet->packet_size -- The size of the IPv4 header (always 20 bytes)
     * out_packet->payload_raw -- A pointer to the first byte after the packet's header (the translated payload shall be placed here)
     * out_packet->payload_size -- Zero
     * out_packet->ipv6_fragment_header -- Undefined (as the packet is IPv4)
     * out_packet->ipv6_carried_protocol_field -- Undefined (as the packet is IPv4)
     */

    switch(context->in_packet.payload_icmpv6hdr->icmp6_code) {
        case 0: // Erroneous header field encountered
            {
                // Check inbound ICMPv6 header
                if(!T64M_UTILS__MEMORY_EQUAL(context->in_packet.payload_raw + 4, "\x00\x00\x00", 3))
                    return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION;

                // Generate outbound ICMPv4 header
                t64f_utils_ip__generate_basic_icmpv4v6_header_to_empty_packet_payload(&context->out_packet, 12, 0);

                const uint8_t out_pointer = _t64f_xlat_6to4_icmp__translate_parameter_problem_pointer_value(context->in_packet.payload_raw[7]);
                if(out_pointer == 255)
                    return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION;

                context->out_packet.payload_raw[4] = out_pointer;
            }
            break;

        case 1: // Unrecognized Next Header type encountered
            t64f_utils_ip__generate_basic_icmpv4v6_header_to_empty_packet_payload(&context->out_packet, 3, 2);
            break;

        default:
            // All other codes, including:
            // - Code 2 (Unrecognized IPv6 option encountered)
            return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION;
    }

    // Build carried IP header & part of data
    if(_t64f_xlat_6to4_icmp__translate_carried_ip_header_and_part_of_data(context, 0) != T64TE_TUNDRA__XLAT_STATUS_CONTINUE_TRANSLATION)
        return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION;

    return T64TE_TUNDRA__XLAT_STATUS_CONTINUE_TRANSLATION;
}

static t64te_tundra__xlat_status _t64f_xlat_6to4_icmp__translate_carried_ip_header_and_part_of_data(t64ts_tundra__xlat_thread_context *context, const int dont_fragment) {
    /*
     * REQUIRED-STATE-OF-PACKET-BUFFERS:
     *
     * in_packet->packet_raw (content) -- An unfragmented IPv6 packet whose headers (base header + all extension headers, if there are any) have been validated
     * in_packet->packet_size -- The IPv6 packet's size which contains at least an ICMPv6 header (at least 48 bytes)
     * in_packet->payload_raw -- The packet's ICMPv6 payload (the pointer points to the beginning of the validated (!) 8-byte ICMPv6 header; after the header, there is likely an unvalidated payload)
     * in_packet->payload_size -- The size of the packet's ICMPv6 payload (a validated 8-byte ICMPv6 header + unvalidated payload -> at least 8 bytes)
     * in_packet->ipv6_fragment_header -- NULL
     * in_packet->ipv6_carried_protocol_field -- A pointer to the byte which contains the number of the transport protocol carried by the packet (58 - ICMPv6)
     *
     * out_packet->packet_raw (content) -- An IPv4 packet (whose header's 'protocol' field is 1 [ICMP] and 'tot_len' and 'check' fields are zero) containing a translated 8-byte ICMPv4 header
     * out_packet->packet_size -- The size of the IPv4 and ICMPv4 headers (always 28 bytes - 20-byte IPv4 header + 8-byte ICMPv4 header)
     * out_packet->payload_raw -- A pointer to the first byte after the packet's header (now pointing to the beginning of the translated 8-byte ICMPv4 header)
     * out_packet->payload_size -- 8 bytes
     * out_packet->ipv6_fragment_header -- Undefined (as the packet is IPv4)
     * out_packet->ipv6_carried_protocol_field -- Undefined (as the packet is IPv4)
     */

    // Declaration & initialization of variables
    t64ts_tundra__packet in_ipv6_carried_packet;
    T64M_UTILS__MEMORY_CLEAR(&in_ipv6_carried_packet, 1, sizeof(t64ts_tundra__packet));
    in_ipv6_carried_packet.packet_raw = (context->in_packet.payload_raw + 8);
    in_ipv6_carried_packet.packet_size = (context->in_packet.payload_size - 8);

    t64ts_tundra__packet out_ipv4_carried_packet;
    T64M_UTILS__MEMORY_CLEAR(&out_ipv4_carried_packet, 1, sizeof(t64ts_tundra__packet));
    out_ipv4_carried_packet.packet_raw = (context->out_packet.payload_raw + 8);
    out_ipv4_carried_packet.packet_size = 20;

    // Size checks
    if(in_ipv6_carried_packet.packet_size < 40)
        return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION;

    // OUT-PACKET-REMAINING-BUFFER-SIZE: at least 1520 bytes - 20 bytes IPv4 header - 8 bytes ICMP header = at least 1492 bytes free; up to 40 bytes needed (for 20-byte IPv4 header + up to 20 bytes of payload)

    // IP header - validation, evaluation and initialization
    if(in_ipv6_carried_packet.packet_ipv6hdr->version != 6)
        return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION;

    {
        t64ts_tundra__ipv6_fragment_header *fragment_header = NULL;
        uint8_t *protocol_field = &in_ipv6_carried_packet.packet_ipv6hdr->nexthdr;
        uint8_t *current_header_ptr = (in_ipv6_carried_packet.packet_raw + 40);
        ssize_t remaining_packet_size = (((ssize_t) in_ipv6_carried_packet.packet_size) - 40);

        while(
            (fragment_header == NULL) &&
            (*protocol_field == 0 || *protocol_field == 43 || *protocol_field == 44 || *protocol_field == 60)
        ) {
            if(remaining_packet_size < 8)
                return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION;

            if(*protocol_field == 44)
                fragment_header = (t64ts_tundra__ipv6_fragment_header *) current_header_ptr;

            const ssize_t current_header_size = (8 + (((ssize_t) (current_header_ptr[1])) * 8));

            protocol_field = current_header_ptr;
            current_header_ptr += current_header_size;
            remaining_packet_size -= current_header_size;
        }

        if(remaining_packet_size < 0)
            return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION;

        in_ipv6_carried_packet.payload_raw = current_header_ptr;
        in_ipv6_carried_packet.payload_size = (size_t) remaining_packet_size;
        in_ipv6_carried_packet.ipv6_fragment_header = fragment_header;
        in_ipv6_carried_packet.ipv6_carried_protocol_field = protocol_field;
    }

    // IP header - translation
    out_ipv4_carried_packet.packet_ipv4hdr->version = 4;
    out_ipv4_carried_packet.packet_ipv4hdr->ihl = 5;
    out_ipv4_carried_packet.packet_ipv4hdr->tos = (uint8_t) ((in_ipv6_carried_packet.packet_ipv6hdr->priority << 4) | (in_ipv6_carried_packet.packet_ipv6hdr->flow_lbl[0] >> 4));
    out_ipv4_carried_packet.packet_ipv4hdr->tot_len = htons(ntohs(in_ipv6_carried_packet.packet_ipv6hdr->payload_len) + 20);
    if(T64M_UTILS_IP__IS_IPV6_PACKET_FRAGMENTED(&in_ipv6_carried_packet)) {
        out_ipv4_carried_packet.packet_ipv4hdr->id = in_ipv6_carried_packet.ipv6_fragment_header->identification[1];
        out_ipv4_carried_packet.packet_ipv4hdr->frag_off = T64M_UTILS_IP__CONSTRUCT_IPV4_FRAGMENT_OFFSET_AND_FLAGS_FIELD(
            dont_fragment,
            T64M_UTILS_IP__GET_IPV6_FRAGMENT_MORE_FRAGMENTS_BIT(in_ipv6_carried_packet.ipv6_fragment_header),
            T64M_UTILS_IP__GET_IPV6_FRAGMENT_OFFSET(in_ipv6_carried_packet.ipv6_fragment_header)
        );
    } else {
        t64f_utils_ip__generate_ipv4_fragment_identifier(context, (uint8_t *) &out_ipv4_carried_packet.packet_ipv4hdr->id);
        out_ipv4_carried_packet.packet_ipv4hdr->frag_off = T64M_UTILS_IP__CONSTRUCT_IPV4_FRAGMENT_OFFSET_AND_FLAGS_FIELD(dont_fragment, 0, 0);
    }
    out_ipv4_carried_packet.packet_ipv4hdr->ttl = in_ipv6_carried_packet.packet_ipv6hdr->hop_limit;
    out_ipv4_carried_packet.packet_ipv4hdr->protocol = *in_ipv6_carried_packet.ipv6_carried_protocol_field;

    if(((*(context->addr_xlat_functions->perform_6to4_address_translation_for_icmp_error_packet))(context, (const uint8_t *) in_ipv6_carried_packet.packet_ipv6hdr->saddr.s6_addr, (const uint8_t *) in_ipv6_carried_packet.packet_ipv6hdr->daddr.s6_addr, (uint8_t *) &out_ipv4_carried_packet.packet_ipv4hdr->saddr, (uint8_t *) &out_ipv4_carried_packet.packet_ipv4hdr->daddr)) != T64TE_TUNDRA__XLAT_STATUS_CONTINUE_TRANSLATION)
        return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION;

    out_ipv4_carried_packet.payload_raw = (out_ipv4_carried_packet.packet_raw + out_ipv4_carried_packet.packet_size);
    out_ipv4_carried_packet.payload_size = 0;

    context->out_packet.packet_size += out_ipv4_carried_packet.packet_size;
    context->out_packet.payload_size += out_ipv4_carried_packet.packet_size;

    // Part of data - copy
    {
        const size_t copied_bytes = t64f_utils__secure_memcpy_with_size_clamping(
            out_ipv4_carried_packet.payload_raw,
            in_ipv6_carried_packet.payload_raw,
            in_ipv6_carried_packet.payload_size,
            (68 - context->out_packet.packet_size) // 68 bytes - 20 bytes IPv4 header - 8 bytes ICMPv4 header - 20 bytes IPv4 header "in error" = 20 bytes
        );
        out_ipv4_carried_packet.packet_size += copied_bytes;
        out_ipv4_carried_packet.payload_size = copied_bytes;
        context->out_packet.packet_size += copied_bytes;
        context->out_packet.payload_size += copied_bytes;
    }

    // Part of data - ICMP
    if(out_ipv4_carried_packet.packet_ipv4hdr->protocol == 58) { // ICMPv6
        // https://www.rfc-editor.org/rfc/rfc7915.html#page-4 -> "Fragmented ICMP/ICMPv6 packets will not be translated by IP/ICMP translators."
        /*
         * https://datatracker.ietf.org/doc/html/rfc7915#page-14 states:
         * "The translation of the inner IP header can be done by invoking the
         *  function that translated the outer IP headers.  This process MUST
         *  stop at the first embedded header and drop the packet if it contains
         *  more embedded headers."
         */
        // Echo Request and Echo Reply are the only translatable ICMP types that do not carry a packet "in error".
        if(
            (!T64MM_UTILS_IP__IS_IPV4_PACKET_FRAGMENTED(out_ipv4_carried_packet.packet_ipv4hdr)) &&
            (out_ipv4_carried_packet.payload_size >= 8) &&
            (out_ipv4_carried_packet.payload_icmpv6hdr->icmp6_type == 128 || out_ipv4_carried_packet.payload_icmpv6hdr->icmp6_type == 129) &&
            (out_ipv4_carried_packet.payload_icmpv6hdr->icmp6_code == 0)
        ) {
            out_ipv4_carried_packet.packet_ipv4hdr->protocol = 1; // ICMPv4

            if(out_ipv4_carried_packet.payload_icmpv4hdr->type == 128) // Echo Request
                out_ipv4_carried_packet.payload_icmpv4hdr->type = 8;
            else if(out_ipv4_carried_packet.payload_icmpv4hdr->type == 129) // Echo Reply
                out_ipv4_carried_packet.payload_icmpv4hdr->type = 0;

        } else {
            return T64TE_TUNDRA__XLAT_STATUS_STOP_TRANSLATION;
        }
    }

    // IP header - checksum
    out_ipv4_carried_packet.packet_ipv4hdr->check = 0; // The IPv4 header is now finished, so the checksum can be calculated...
    out_ipv4_carried_packet.packet_ipv4hdr->check = t64f_checksum__calculate_ipv4_header_checksum(out_ipv4_carried_packet.packet_ipv4hdr);

    return T64TE_TUNDRA__XLAT_STATUS_CONTINUE_TRANSLATION;
}

// Returns 255 if 'in_pointer' is invalid and the translation process shall be stopped!
static uint8_t _t64f_xlat_6to4_icmp__translate_parameter_problem_pointer_value(const uint8_t in_pointer) {
    // https://datatracker.ietf.org/doc/html/rfc7915#page-22

    if(in_pointer == 0 || in_pointer == 1)
        return in_pointer;

    if(in_pointer == 4 || in_pointer == 5)
        return 2;

    if(in_pointer == 6)
        return 9;

    if(in_pointer == 7)
        return 8;

    if(in_pointer >= 8 && in_pointer <= 23)
        return 12;

    if(in_pointer >= 24 && in_pointer <= 39)
        return 16;

    return 255; // Includes the values 2, 3
}
