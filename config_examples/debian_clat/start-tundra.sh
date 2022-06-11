#!/bin/bash

function exit_with_error() {
  echo "ERROR: $1"
  exit 1
}


TUNDRA_EXECUTABLE="/usr/local/sbin/tundra-nat64"
TUNDRA_CONFIG_FILE="/usr/local/etc/tundra-clat/tundra-clat.conf"
TUNDRA_INTERFACE="clat"
TUNDRA_IPV4="10.46.46.2/24"
TUNDRA_IPV6="fdff:10:46:46::fffe/64"
TUNDRA_IPV6_SUBNET="fdff:10:46:46::/64"


${TUNDRA_EXECUTABLE} --config-file="${TUNDRA_CONFIG_FILE}" mktun || exit_with_error "Failed to create the TUN device!"

/bin/ip link set dev "${TUNDRA_INTERFACE}" up || exit_with_error "Failed to set the TUN device up!"
/bin/ip -4 addr add "${TUNDRA_IPV4}" dev "${TUNDRA_INTERFACE}" || exit_with_error "Failed to set the TUN device's IPv4 address!"
/bin/ip -6 addr add "${TUNDRA_IPV6}" dev "${TUNDRA_INTERFACE}" || exit_with_error "Failed to set the TUN device's IPv6 address!"
/bin/ip -4 route add default dev "${TUNDRA_INTERFACE}" || exit_with_error "Failed to set the TUN device as default route!"
/sbin/ip6tables -t nat -A POSTROUTING -s "${TUNDRA_IPV6_SUBNET}" '!' -d "${TUNDRA_IPV6_SUBNET}" -j MASQUERADE || exit_with_error "Failed to set up IPv6 NAT masquerading!"

${TUNDRA_EXECUTABLE} --config-file="${TUNDRA_CONFIG_FILE}" translate
