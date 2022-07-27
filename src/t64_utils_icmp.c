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
#include"t64_utils_icmp.h"

#include"t64_utils.h"


/*
 * Puts the supplied 'icmp_type' to the first byte and 'icmp_code' to the second byte of the packet's payload and zeroes
 *  out the remaining 6 bytes. After that, it increments 'packet->packet_size' by 8 and sets 'packet->payload_size'
 *  to 8. This function does not perform any boundary checks - it is assumed that there are at least 8 bytes free in the
 *  packet buffer!
 * Keep in mind that you need to compute the checksum yourself after you generate the final form of the ICMPv4/v6 message!
 */
void t64f_utils_icmp__generate_basic_icmpv4v6_header_to_empty_packet_payload(t64ts_tundra__packet *packet, const uint8_t icmp_type, const uint8_t icmp_code) {
    packet->payload_raw[0] = icmp_type;
    packet->payload_raw[1] = icmp_code;
    T64M_UTILS__MEMORY_ZERO_OUT(packet->payload_raw + 2, 6);

    packet->packet_size += 8;
    packet->payload_size = 8;
}
