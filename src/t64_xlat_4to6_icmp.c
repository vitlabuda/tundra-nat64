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
#include"t64_xlat_4to6_icmp.h"

#include"t64_utils.h"
#include"t64_utils_ip.h"
#include"t64_utils_icmp.h"
#include"t64_log.h"
#include"t64_checksum.h"
#include"t64_xlat_addr_nat64.h"
#include"t64_xlat_addr_clat.h"
#include"t64_xlat_addr_siit.h"
#include"t64_xlat_addr_external.h"


// The array must be zero-terminated, and the integers must be in descending order!
static const uint16_t _t64gc_xlat_4to6_icmp__rfc1191_plateau_mtu_values[] = {
    65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68, 0
};
static const uint16_t _t64gc_xlat_4to6_icmp__rfc1191_default_plateau_mtu_value = 68; // Used when the MTU value cannot be decided from the above defined array (for whatever reason).


static bool _t64f_xlat_4to6_icmp__translate_echo_request_or_echo_reply_message(t64ts_tundra__xlat_thread_context *context);
static bool _t64f_xlat_4to6_icmp__translate_destination_unreachable_message(t64ts_tundra__xlat_thread_context *context);
static bool _t64f_xlat_4to6_icmp__translate_time_exceeded_message(t64ts_tundra__xlat_thread_context *context);
static bool _t64f_xlat_4to6_icmp__translate_parameter_problem_message(t64ts_tundra__xlat_thread_context *context);
static bool _t64f_xlat_4to6_icmp__translate_carried_ip_header_and_part_of_data(t64ts_tundra__xlat_thread_context *context);
static uint8_t _t64f_xlat_4to6_icmp__translate_parameter_problem_pointer_value(const uint8_t in_pointer);
static uint16_t _t64f_xlat_4to6_icmp__estimate_likely_mtu_as_per_rfc1191(const t64ts_tundra__xlat_thread_context *context);


bool t64f_xlat_4to6_icmp__translate_icmpv4_to_icmpv6(t64ts_tundra__xlat_thread_context *context) {
    /*
     * REQUIRED-STATE-OF-PACKET-BUFFERS:
     *
     * in_packet->packet_raw (content) -- An IPv4 packet which carries protocol 1 (ICMP), and whose header (including IPv4 Options, if there are any) has been validated
     * in_packet->packet_size -- The IPv4 packet's size (at least 20 bytes)
     * in_packet->payload_raw -- The packet's unvalidated payload (the pointer points to the beginning of the ICMPv4 header)
     * in_packet->payload_size -- The size of the packet's unvalidated payload (zero if the packet does not carry any payload)
     * in_packet->ipv6_fragment_header -- Undefined (as the packet is IPv4)
     * in_packet->ipv6_carried_protocol_field -- Undefined (as the packet is IPv4)
     *
     * out_packet->packet_raw (content) -- An IPv6 base header (whose 'payload_len' field is zero - it is set just before the packet is sent out) + optionally a fragment extension header (if in_packet is a fragment)
     * out_packet->packet_size -- The size of the IPv6 header(s) (either 40 or 48 bytes)
     * out_packet->payload_raw -- A pointer to the first byte after the packet's header(s) (the translated payload shall be placed here)
     * out_packet->payload_size -- Zero
     * out_packet->ipv6_fragment_header -- A pointer to the fragmentation header if the packet contains it; NULL otherwise
     * out_packet->ipv6_carried_protocol_field -- A pointer to the byte which contains the number of the transport protocol carried by the packet - always set to 58 (ICMPv6)
     */

    // https://www.rfc-editor.org/rfc/rfc7915.html#page-4 -> "Fragmented ICMP/ICMPv6 packets will not be translated by IP/ICMP translators."
    if(T64MM_UTILS_IP__IS_IPV4_PACKET_FRAGMENTED(context->in_packet.packet_ipv4hdr) || T64M_UTILS_IP__IS_IPV6_PACKET_FRAGMENTED(&context->out_packet))
        return false;

    if(context->in_packet.payload_size < 8)
        return false;

    if(t64f_checksum__calculate_rfc1071_checksum(&context->in_packet, false) != 0)
        return false;

    // OUT-PACKET-REMAINING-BUFFER-SIZE: at least 1520 bytes - 40 bytes IPv6 header = at least 1480 bytes free; 8 bytes needed (for ICMPv6 header)

    switch(context->in_packet.payload_icmpv4hdr->type) {
        case 8: case 0: // Echo Request and Echo Reply
            if(!_t64f_xlat_4to6_icmp__translate_echo_request_or_echo_reply_message(context))
                return false;
            break;

        case 3: // Destination Unreachable
            if(!_t64f_xlat_4to6_icmp__translate_destination_unreachable_message(context))
                return false;
            break;

        case 11: // Time Exceeded
            if(!_t64f_xlat_4to6_icmp__translate_time_exceeded_message(context))
                return false;
            break;

        case 12: // Parameter Problem
            if(!_t64f_xlat_4to6_icmp__translate_parameter_problem_message(context))
                return false;
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

    if(context->out_packet.payload_size < 8)
        return false; // Just to make sure...

    context->out_packet.payload_icmpv6hdr->icmp6_cksum = 0;
    context->out_packet.payload_icmpv6hdr->icmp6_cksum = t64f_checksum__calculate_rfc1071_checksum(&context->out_packet, true);

    return true;
}

// Types 8 and 0 - Echo Request and Echo Reply
static bool _t64f_xlat_4to6_icmp__translate_echo_request_or_echo_reply_message(t64ts_tundra__xlat_thread_context *context) {
    /*
     * REQUIRED-STATE-OF-PACKET-BUFFERS:
     *
     * in_packet->packet_raw (content) -- An unfragmented (!) IPv4 packet which carries protocol 1 (ICMP), and whose header (including IPv4 Options, if there are any) has been validated
     * in_packet->packet_size -- The IPv4 packet's size (at least 28 bytes - at least 20-byte IPv4 header + guaranteed 8-byte ICMPv4 header)
     * in_packet->payload_raw -- The packet's unvalidated ICMPv4 payload (the pointer points to the beginning of the ICMPv4 header, which is guaranteed to be there)
     * in_packet->payload_size -- The size of the packet's unvalidated ICMPv4 payload (at least 8 bytes - an 8-byte ICMPv4 header is guaranteed to be there)
     * in_packet->ipv6_fragment_header -- Undefined (as the packet is IPv4)
     * in_packet->ipv6_carried_protocol_field -- Undefined (as the packet is IPv4)
     *
     * out_packet->packet_raw (content) -- An IPv6 base header (whose 'payload_len' field is zero - it is set just before the packet is sent out)
     * out_packet->packet_size -- The size of the IPv6 header (40 bytes)
     * out_packet->payload_raw -- A pointer to the first byte after the packet's header (the translated payload shall be placed here)
     * out_packet->payload_size -- Zero
     * out_packet->ipv6_fragment_header -- NULL
     * out_packet->ipv6_carried_protocol_field -- A pointer to the byte which contains the number of the transport protocol carried by the packet - always set to 58 (ICMPv6)
     */

    // Copy the whole packet's payload
    if(!t64f_utils__secure_memcpy(
        context->out_packet.payload_raw,
        context->in_packet.payload_raw,
        context->in_packet.payload_size,
        (T64C_TUNDRA__MAX_PACKET_SIZE - context->out_packet.packet_size)
    )) return false;

    // Adjust type
    if(context->out_packet.payload_icmpv6hdr->icmp6_type == 8) // Echo request
        context->out_packet.payload_icmpv6hdr->icmp6_type = 128;
    else if(context->out_packet.payload_icmpv6hdr->icmp6_type == 0) // Echo reply
        context->out_packet.payload_icmpv6hdr->icmp6_type = 129;
    else
        return false; // This should never happen!

    // Check code
    if(context->out_packet.payload_icmpv6hdr->icmp6_code != 0)
        return false;

    context->out_packet.packet_size += context->in_packet.payload_size;
    context->out_packet.payload_size = context->in_packet.payload_size;

    return true;
}

// Type 3 - Destination Unreachable
static bool _t64f_xlat_4to6_icmp__translate_destination_unreachable_message(t64ts_tundra__xlat_thread_context *context) {
    /*
     * REQUIRED-STATE-OF-PACKET-BUFFERS:
     *
     * in_packet->packet_raw (content) -- An unfragmented (!) IPv4 packet which carries protocol 1 (ICMP), and whose header (including IPv4 Options, if there are any) has been validated
     * in_packet->packet_size -- The IPv4 packet's size (at least 28 bytes - at least 20-byte IPv4 header + guaranteed 8-byte ICMPv4 header)
     * in_packet->payload_raw -- The packet's unvalidated ICMPv4 payload (the pointer points to the beginning of the ICMPv4 header, which is guaranteed to be there)
     * in_packet->payload_size -- The size of the packet's unvalidated ICMPv4 payload (at least 8 bytes - an 8-byte ICMPv4 header is guaranteed to be there)
     * in_packet->ipv6_fragment_header -- Undefined (as the packet is IPv4)
     * in_packet->ipv6_carried_protocol_field -- Undefined (as the packet is IPv4)
     *
     * out_packet->packet_raw (content) -- An IPv6 base header (whose 'payload_len' field is zero - it is set just before the packet is sent out)
     * out_packet->packet_size -- The size of the IPv6 header (40 bytes)
     * out_packet->payload_raw -- A pointer to the first byte after the packet's header (the translated payload shall be placed here)
     * out_packet->payload_size -- Zero
     * out_packet->ipv6_fragment_header -- NULL
     * out_packet->ipv6_carried_protocol_field -- A pointer to the byte which contains the number of the transport protocol carried by the packet - always set to 58 (ICMPv6)
     */

    switch(context->in_packet.payload_icmpv4hdr->code) {
        case 0: case 1: case 5: case 6: case 7: case 8: case 11: case 12: // Net Unreachable, Host Unreachable, Source Route Failed
            {
                // Check inbound ICMPv4 header
                if(!T64M_UTILS__MEMORY_EQUAL(context->in_packet.payload_raw + 4, "\x00\x00\x00\x00", 4))
                    return false;

                // Generate outbound ICMPv6 header
                t64f_utils_icmp__generate_basic_icmpv4v6_header_to_empty_packet_payload(&context->out_packet, 1, 0);
            }
            break;

        case 9: case 10: case 13: case 15: // Communication with Destination Host Administratively Prohibited, Communication Administratively Prohibited, Precedence cutoff in effect
            {
                // Check inbound ICMPv4 header
                if(!T64M_UTILS__MEMORY_EQUAL(context->in_packet.payload_raw + 4, "\x00\x00\x00\x00", 4))
                    return false;

                // Generate outbound ICMPv6 header
                t64f_utils_icmp__generate_basic_icmpv4v6_header_to_empty_packet_payload(&context->out_packet, 1, 1);
            }
            break;

        case 3: // Port Unreachable
            {
                // Check inbound ICMPv4 header
                if(!T64M_UTILS__MEMORY_EQUAL(context->in_packet.payload_raw + 4, "\x00\x00\x00\x00", 4))
                    return false;

                // Generate outbound ICMPv6 header
                t64f_utils_icmp__generate_basic_icmpv4v6_header_to_empty_packet_payload(&context->out_packet, 1, 4);
            }
            break;

        case 4: // Fragmentation Needed and DF was Set
            {
                // Check inbound ICMPv4 header
                if(!T64M_UTILS__MEMORY_EQUAL(context->in_packet.payload_raw + 4, "\x00\x00", 2))
                    return false;

                // Generate outbound ICMPv6 header
                t64f_utils_icmp__generate_basic_icmpv4v6_header_to_empty_packet_payload(&context->out_packet, 2, 0);

                {
                    uint16_t mtu;
                    memcpy(&mtu, context->in_packet.payload_raw + 6, 2); // This is a hack which overcomes the 2-byte alignment requirement for 16-bit values.
                    mtu = ntohs(mtu);
                    if(mtu == 0)
                        mtu = _t64f_xlat_4to6_icmp__estimate_likely_mtu_as_per_rfc1191(context);

                    // Although the minimum IPv6 MTU is 68 bytes, some networks may be broken

                    mtu = T64MM_UTILS__MINIMUM(65515, mtu); // Integer overflow prevention

                    // https://datatracker.ietf.org/doc/html/rfc7915#page-11
                    mtu = T64MM_UTILS__MINIMUM(mtu + 20, (uint16_t) context->configuration->translator_ipv6_outbound_mtu);
                    mtu = T64MM_UTILS__MINIMUM(mtu, ((uint16_t) context->configuration->translator_ipv4_outbound_mtu) + 20);
                    mtu = T64MM_UTILS__MAXIMUM(1280, mtu);

                    mtu = htons(mtu);
                    memcpy(context->out_packet.payload_raw + 6, &mtu, 2);
                }
            }
            break;

        case 2: // Protocol Unreachable
            {
                // Check inbound ICMPv4 header
                if(!T64M_UTILS__MEMORY_EQUAL(context->in_packet.payload_raw + 4, "\x00\x00\x00\x00", 4))
                    return false;

                // Generate outbound ICMPv6 header
                t64f_utils_icmp__generate_basic_icmpv4v6_header_to_empty_packet_payload(&context->out_packet, 4, 1);

                context->out_packet.payload_raw[7] = 6; // Pointer points to the "Next header" field
            }
            break;

        default:
            // All other codes, including:
            // - Code 14 (Host Precedence Violation)
            return false;
    }

    // Build carried IP header & part of data
    if(!_t64f_xlat_4to6_icmp__translate_carried_ip_header_and_part_of_data(context))
        return false;

    return true;
}

// Type 11 - Time Exceeded
static bool _t64f_xlat_4to6_icmp__translate_time_exceeded_message(t64ts_tundra__xlat_thread_context *context) {
    /*
     * REQUIRED-STATE-OF-PACKET-BUFFERS:
     *
     * in_packet->packet_raw (content) -- An unfragmented (!) IPv4 packet which carries protocol 1 (ICMP), and whose header (including IPv4 Options, if there are any) has been validated
     * in_packet->packet_size -- The IPv4 packet's size (at least 28 bytes - at least 20-byte IPv4 header + guaranteed 8-byte ICMPv4 header)
     * in_packet->payload_raw -- The packet's unvalidated ICMPv4 payload (the pointer points to the beginning of the ICMPv4 header, which is guaranteed to be there)
     * in_packet->payload_size -- The size of the packet's unvalidated ICMPv4 payload (at least 8 bytes - an 8-byte ICMPv4 header is guaranteed to be there)
     * in_packet->ipv6_fragment_header -- Undefined (as the packet is IPv4)
     * in_packet->ipv6_carried_protocol_field -- Undefined (as the packet is IPv4)
     *
     * out_packet->packet_raw (content) -- An IPv6 base header (whose 'payload_len' field is zero - it is set just before the packet is sent out)
     * out_packet->packet_size -- The size of the IPv6 header (40 bytes)
     * out_packet->payload_raw -- A pointer to the first byte after the packet's header (the translated payload shall be placed here)
     * out_packet->payload_size -- Zero
     * out_packet->ipv6_fragment_header -- NULL
     * out_packet->ipv6_carried_protocol_field -- A pointer to the byte which contains the number of the transport protocol carried by the packet - always set to 58 (ICMPv6)
     */

    // Check inbound ICMPv4 header
    if(context->in_packet.payload_icmpv4hdr->code != 0 && context->in_packet.payload_icmpv4hdr->code != 1)
        return false;

    if(!T64M_UTILS__MEMORY_EQUAL(context->in_packet.payload_raw + 4, "\x00\x00\x00\x00", 4))
        return false;

    // Generate outbound ICMPv6 header
    t64f_utils_icmp__generate_basic_icmpv4v6_header_to_empty_packet_payload(&context->out_packet, 3, context->in_packet.payload_icmpv4hdr->code);

    // Build carried IP header & part of data
    if(!_t64f_xlat_4to6_icmp__translate_carried_ip_header_and_part_of_data(context))
        return false;

    return true;
}

// Type 12 - Parameter Problem
static bool _t64f_xlat_4to6_icmp__translate_parameter_problem_message(t64ts_tundra__xlat_thread_context *context) {
    /*
     * REQUIRED-STATE-OF-PACKET-BUFFERS:
     *
     * in_packet->packet_raw (content) -- An unfragmented (!) IPv4 packet which carries protocol 1 (ICMP), and whose header (including IPv4 Options, if there are any) has been validated
     * in_packet->packet_size -- The IPv4 packet's size (at least 28 bytes - at least 20-byte IPv4 header + guaranteed 8-byte ICMPv4 header)
     * in_packet->payload_raw -- The packet's unvalidated ICMPv4 payload (the pointer points to the beginning of the ICMPv4 header, which is guaranteed to be there)
     * in_packet->payload_size -- The size of the packet's unvalidated ICMPv4 payload (at least 8 bytes - an 8-byte ICMPv4 header is guaranteed to be there)
     * in_packet->ipv6_fragment_header -- Undefined (as the packet is IPv4)
     * in_packet->ipv6_carried_protocol_field -- Undefined (as the packet is IPv4)
     *
     * out_packet->packet_raw (content) -- An IPv6 base header (whose 'payload_len' field is zero - it is set just before the packet is sent out)
     * out_packet->packet_size -- The size of the IPv6 header (40 bytes)
     * out_packet->payload_raw -- A pointer to the first byte after the packet's header (the translated payload shall be placed here)
     * out_packet->payload_size -- Zero
     * out_packet->ipv6_fragment_header -- NULL
     * out_packet->ipv6_carried_protocol_field -- A pointer to the byte which contains the number of the transport protocol carried by the packet - always set to 58 (ICMPv6)
     */

    // Check inbound ICMPv4 header
    if(context->in_packet.payload_icmpv4hdr->code != 0 && context->in_packet.payload_icmpv4hdr->code != 2)
        return false;

    if(!T64M_UTILS__MEMORY_EQUAL(context->in_packet.payload_raw + 5, "\x00\x00\x00", 3))
        return false;

    // Generate outbound ICMPv6 header
    t64f_utils_icmp__generate_basic_icmpv4v6_header_to_empty_packet_payload(&context->out_packet, 4, 0);

    {
        const uint8_t out_pointer = _t64f_xlat_4to6_icmp__translate_parameter_problem_pointer_value(context->in_packet.payload_raw[4]);
        if(out_pointer == 255)
            return false;

        context->out_packet.payload_raw[7] = out_pointer;
    }

    // Build carried IP header & part of data
    if(!_t64f_xlat_4to6_icmp__translate_carried_ip_header_and_part_of_data(context))
        return false;

    return true;
}

static bool _t64f_xlat_4to6_icmp__translate_carried_ip_header_and_part_of_data(t64ts_tundra__xlat_thread_context *context) {
    /*
     * REQUIRED-STATE-OF-PACKET-BUFFERS:
     *
     * in_packet->packet_raw (content) -- An unfragmented IPv4 packet which carries protocol 1 (ICMP; a validated 8-byte ICMPv4 header is present in the packet's payload), and whose header (including IPv4 Options, if there are any) has been validated
     * in_packet->packet_size -- The IPv4 packet's size (at least 28 bytes - at least 20-byte IPv4 header + 8-byte ICMPv4 header)
     * in_packet->payload_raw -- The packet's ICMPv4 payload (the pointer points to the beginning of the validated (!) 8-byte ICMPv4 header; after the header, there is likely an unvalidated payload)
     * in_packet->payload_size -- The size of the packet's ICMPv4 payload (a validated 8-byte ICMPv4 header + unvalidated payload -> at least 8 bytes)
     * in_packet->ipv6_fragment_header -- Undefined (as the packet is IPv4)
     * in_packet->ipv6_carried_protocol_field -- Undefined (as the packet is IPv4)
     *
     * out_packet->packet_raw (content) -- An IPv6 packet (whose header's 'payload_len' field is zero) containing a translated 8-byte ICMPv6 header
     * out_packet->packet_size -- The size of the IPv6 and ICMPv6 headers (48 bytes - 40-byte IPv6 base header + 8-byte ICMPv6 header)
     * out_packet->payload_raw -- A pointer to the first byte after the packet's header (now pointing to the beginning of the translated ICMPv6 header)
     * out_packet->payload_size -- 8 bytes
     * out_packet->ipv6_fragment_header -- NULL
     * out_packet->ipv6_carried_protocol_field -- A pointer to the byte which contains the number of the transport protocol carried by the packet - always set to 58 (ICMPv6)
     */

    // Declaration & initialization of variables
    t64ts_tundra__packet in_ipv4_carried_packet;
    T64M_UTILS__MEMORY_ZERO_OUT(&in_ipv4_carried_packet, sizeof(t64ts_tundra__packet));
    in_ipv4_carried_packet.packet_raw = (context->in_packet.payload_raw + 8);
    in_ipv4_carried_packet.packet_size = (context->in_packet.payload_size - 8);

    t64ts_tundra__packet out_ipv6_carried_packet;
    T64M_UTILS__MEMORY_ZERO_OUT(&out_ipv6_carried_packet, sizeof(t64ts_tundra__packet));
    out_ipv6_carried_packet.packet_raw = (context->out_packet.payload_raw + 8);
    out_ipv6_carried_packet.packet_size = 40;

    // Size checks
    if(in_ipv4_carried_packet.packet_size < 20)
        return false;

    // OUT-PACKET-REMAINING-BUFFER-SIZE: at least 1520 bytes - 40 bytes IPv6 header - 8 bytes ICMPv6 header = at least 1472 bytes free; up to 1240 bytes needed (for IPv6 header + optionally IPv6 fragmentation header + up to 1192 bytes payload)

    // IP header - validation, evaluation and initialization
    if(in_ipv4_carried_packet.packet_ipv4hdr->version != 4)
        return false;

    const size_t in_ipv4_carried_packet_header_length = (in_ipv4_carried_packet.packet_ipv4hdr->ihl * 4);
    if(in_ipv4_carried_packet_header_length < 20 || in_ipv4_carried_packet_header_length > in_ipv4_carried_packet.packet_size)
        return false;

    in_ipv4_carried_packet.payload_raw = (in_ipv4_carried_packet.packet_raw + in_ipv4_carried_packet_header_length);
    in_ipv4_carried_packet.payload_size = (in_ipv4_carried_packet.packet_size - in_ipv4_carried_packet_header_length);

    // IP header - translation
    out_ipv6_carried_packet.packet_ipv6hdr->version = 6;
    out_ipv6_carried_packet.packet_ipv6hdr->priority = (uint8_t) (in_ipv4_carried_packet.packet_ipv4hdr->tos >> 4);
    out_ipv6_carried_packet.packet_ipv6hdr->flow_lbl[0] = (uint8_t) (in_ipv4_carried_packet.packet_ipv4hdr->tos << 4);
    out_ipv6_carried_packet.packet_ipv6hdr->flow_lbl[1] = 0;
    out_ipv6_carried_packet.packet_ipv6hdr->flow_lbl[2] = 0;
    out_ipv6_carried_packet.packet_ipv6hdr->payload_len = htons(ntohs(in_ipv4_carried_packet.packet_ipv4hdr->tot_len) - ((uint16_t) in_ipv4_carried_packet_header_length));
    out_ipv6_carried_packet.packet_ipv6hdr->hop_limit = in_ipv4_carried_packet.packet_ipv4hdr->ttl;

    // It would be possible to decide which function to use beforehand and then call it indirectly using a function
    //  pointer, but indirect function calls are usually slow.
    switch(context->configuration->addressing_mode) {
        case T64TE_TUNDRA__ADDRESSING_MODE_NAT64:
            if(!t64f_xlat_addr_nat64__perform_4to6_address_translation_for_icmp_error_packet(context, (const uint8_t *) &in_ipv4_carried_packet.packet_ipv4hdr->saddr, (const uint8_t *) &in_ipv4_carried_packet.packet_ipv4hdr->daddr, (uint8_t *) out_ipv6_carried_packet.packet_ipv6hdr->saddr.s6_addr, (uint8_t *) out_ipv6_carried_packet.packet_ipv6hdr->daddr.s6_addr))
                return false;
            break;

        case T64TE_TUNDRA__ADDRESSING_MODE_CLAT:
            if(!t64f_xlat_addr_clat__perform_4to6_address_translation_for_icmp_error_packet(context, (const uint8_t *) &in_ipv4_carried_packet.packet_ipv4hdr->saddr, (const uint8_t *) &in_ipv4_carried_packet.packet_ipv4hdr->daddr, (uint8_t *) out_ipv6_carried_packet.packet_ipv6hdr->saddr.s6_addr, (uint8_t *) out_ipv6_carried_packet.packet_ipv6hdr->daddr.s6_addr))
                return false;
            break;

        case T64TE_TUNDRA__ADDRESSING_MODE_SIIT:
            if(!t64f_xlat_addr_siit__perform_4to6_address_translation_for_icmp_error_packet(context, (const uint8_t *) &in_ipv4_carried_packet.packet_ipv4hdr->saddr, (const uint8_t *) &in_ipv4_carried_packet.packet_ipv4hdr->daddr, (uint8_t *) out_ipv6_carried_packet.packet_ipv6hdr->saddr.s6_addr, (uint8_t *) out_ipv6_carried_packet.packet_ipv6hdr->daddr.s6_addr))
                return false;
            break;

        case T64TE_TUNDRA__ADDRESSING_MODE_EXTERNAL:
            if(!t64f_xlat_addr_external__perform_4to6_address_translation_for_icmp_error_packet(context, (const uint8_t *) &in_ipv4_carried_packet.packet_ipv4hdr->saddr, (const uint8_t *) &in_ipv4_carried_packet.packet_ipv4hdr->daddr, (uint8_t *) out_ipv6_carried_packet.packet_ipv6hdr->saddr.s6_addr, (uint8_t *) out_ipv6_carried_packet.packet_ipv6hdr->daddr.s6_addr))
                return false;
            break;

        default:
            t64f_log__thread_crash_invalid_internal_state(context->thread_id, "Invalid addressing mode");
    }

    if(T64MM_UTILS_IP__IS_IPV4_PACKET_FRAGMENTED(in_ipv4_carried_packet.packet_ipv4hdr)) {
        out_ipv6_carried_packet.packet_ipv6hdr->nexthdr = 44;

        t64ts_tundra__ipv6_fragment_header *ipv6_fragment_header = (t64ts_tundra__ipv6_fragment_header *) (out_ipv6_carried_packet.packet_raw + out_ipv6_carried_packet.packet_size);
        ipv6_fragment_header->next_header = in_ipv4_carried_packet.packet_ipv4hdr->protocol;
        ipv6_fragment_header->reserved = 0;
        ipv6_fragment_header->offset_and_flags = T64M_UTILS_IP__CONSTRUCT_IPV6_FRAGMENT_OFFSET_AND_FLAGS_FIELD(
            T64M_UTILS_IP__GET_IPV4_FRAGMENT_OFFSET(in_ipv4_carried_packet.packet_ipv4hdr),
            T64M_UTILS_IP__GET_IPV4_MORE_FRAGMENTS_BIT(in_ipv4_carried_packet.packet_ipv4hdr)
        );
        ipv6_fragment_header->identification[0] = 0;
        ipv6_fragment_header->identification[1] = in_ipv4_carried_packet.packet_ipv4hdr->id;

        out_ipv6_carried_packet.packet_size += 8;
        out_ipv6_carried_packet.ipv6_fragment_header = ipv6_fragment_header;
        out_ipv6_carried_packet.ipv6_carried_protocol_field = &ipv6_fragment_header->next_header;
    } else {
        out_ipv6_carried_packet.packet_ipv6hdr->nexthdr = in_ipv4_carried_packet.packet_ipv4hdr->protocol;

        out_ipv6_carried_packet.ipv6_fragment_header = NULL;
        out_ipv6_carried_packet.ipv6_carried_protocol_field = &out_ipv6_carried_packet.packet_ipv6hdr->nexthdr;
    }
    out_ipv6_carried_packet.payload_raw = (out_ipv6_carried_packet.packet_raw + out_ipv6_carried_packet.packet_size);
    out_ipv6_carried_packet.payload_size = 0;

    context->out_packet.packet_size += out_ipv6_carried_packet.packet_size;
    context->out_packet.payload_size += out_ipv6_carried_packet.packet_size;

    // Part of data - copy
    {
        const size_t copied_bytes = t64f_utils__secure_memcpy_with_size_clamping(
            out_ipv6_carried_packet.payload_raw,
            in_ipv4_carried_packet.payload_raw,
            in_ipv4_carried_packet.payload_size,
            (1280 - context->out_packet.packet_size) // 1280 bytes - 40 bytes IPv6 header - 8 bytes ICMPv6 header - 40 or 48 bytes IPv6 header "in error" = 1192 or 1184 bytes
        );
        out_ipv6_carried_packet.packet_size += copied_bytes;
        out_ipv6_carried_packet.payload_size = copied_bytes;
        context->out_packet.packet_size += copied_bytes;
        context->out_packet.payload_size += copied_bytes;
    }

    // Part of data - ICMP
    if(*out_ipv6_carried_packet.ipv6_carried_protocol_field == 1) { // ICMPv4
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
            (!T64M_UTILS_IP__IS_IPV6_PACKET_FRAGMENTED(&out_ipv6_carried_packet)) &&
            (out_ipv6_carried_packet.payload_size >= 8) &&
            (out_ipv6_carried_packet.payload_icmpv4hdr->type == 8 || out_ipv6_carried_packet.payload_icmpv4hdr->type == 0) &&
            (out_ipv6_carried_packet.payload_icmpv4hdr->code == 0)
        ) {
            *out_ipv6_carried_packet.ipv6_carried_protocol_field = 58; // ICMPv6

            if(out_ipv6_carried_packet.payload_icmpv6hdr->icmp6_type == 8) // Echo Request
                out_ipv6_carried_packet.payload_icmpv6hdr->icmp6_type = 128;
            else if(out_ipv6_carried_packet.payload_icmpv6hdr->icmp6_type == 0) // Echo Reply
                out_ipv6_carried_packet.payload_icmpv6hdr->icmp6_type = 129;

        } else {
            return false;
        }
    }

    return true;
}

// Returns 255 if 'in_pointer' is invalid and the translation process shall be stopped!
static uint8_t _t64f_xlat_4to6_icmp__translate_parameter_problem_pointer_value(const uint8_t in_pointer) {
    // https://datatracker.ietf.org/doc/html/rfc7915#page-13

    if(in_pointer == 0 || in_pointer == 1)
        return in_pointer;

    if(in_pointer == 2 || in_pointer == 3)
        return 4;

    if(in_pointer == 8)
        return 7;

    if(in_pointer == 9)
        return 6;

    if(in_pointer >= 12 && in_pointer <= 15)
        return 8;

    if(in_pointer >= 16 && in_pointer <= 19)
        return 24;

    return 255; // Includes the values 4, 5, 6, 7, 10, 11
}

static uint16_t _t64f_xlat_4to6_icmp__estimate_likely_mtu_as_per_rfc1191(const t64ts_tundra__xlat_thread_context *context) {
    if(context->in_packet.payload_size < 28) // ICMPv4 header (8 bytes) + basic IPv4 header (20 bytes) = 28 bytes
        return _t64gc_xlat_4to6_icmp__rfc1191_default_plateau_mtu_value;

    const struct iphdr *packet_in_error = (const struct iphdr *) (context->in_packet.payload_raw + 8);
    const uint16_t packet_in_error_total_length = ntohs(packet_in_error->tot_len);

    for(size_t i = 0; _t64gc_xlat_4to6_icmp__rfc1191_plateau_mtu_values[i] != 0; i++) {
        if(_t64gc_xlat_4to6_icmp__rfc1191_plateau_mtu_values[i] < packet_in_error_total_length)
            return _t64gc_xlat_4to6_icmp__rfc1191_plateau_mtu_values[i];
    }

    return _t64gc_xlat_4to6_icmp__rfc1191_default_plateau_mtu_value;
}
