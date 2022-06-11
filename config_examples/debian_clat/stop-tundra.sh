#!/bin/bash

function exit_with_error() {
  echo "ERROR: $1"
  exit 1
}


TUNDRA_EXECUTABLE="/usr/local/sbin/tundra-nat64"
TUNDRA_CONFIG_FILE="/usr/local/etc/tundra-clat/tundra-clat.conf"
TUNDRA_IPV6_SUBNET="fdff:10:46:46::/64"


if [ -z "${MAINPID}" ]; then
	exit_with_error "The MAINPID environment variable is not set!"
fi


/bin/kill -TERM "${MAINPID}" || exit_with_error "Failed to terminate Tundra!"
/bin/sleep 2 || exit_with_error "Failed to wait for a bit of time!"

/sbin/ip6tables -t nat -D POSTROUTING -s "${TUNDRA_IPV6_SUBNET}" '!' -d "${TUNDRA_IPV6_SUBNET}" -j MASQUERADE || exit_with_error "Failed to unset IPv6 NAT masquerading!"

${TUNDRA_EXECUTABLE} --config-file="${TUNDRA_CONFIG_FILE}" rmtun || exit_with_error "Failed to remove the TUN device!"
