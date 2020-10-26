/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>

typedef enum {
	KNOT_XDP_IPV6   = (1 << 0), /*!< This packet is a IPv6 (IPv4 otherwise). */
	KNOT_XDP_TCP    = (1 << 1), /*!< This packet is a TCP (UDP otherwise). */
	KNOT_XDP_SYN    = (1 << 2), /*!< SYN flag set (TCP only). */
	KNOT_XDP_ACK    = (1 << 3), /*!< ACK flag set (TCP only). */
	KNOT_XDP_FIN    = (1 << 4), /*!< FIN flag set (TCP only). */
} knot_xdp_flags_t;

/*! \brief A packet with src & dst MAC & IP addrs + UDP payload. */
typedef struct knot_xdp_msg knot_xdp_msg_t;
struct knot_xdp_msg {
	struct sockaddr_in6 ip_from;
	struct sockaddr_in6 ip_to;
	uint8_t eth_from[ETH_ALEN]; // TODO note this changed from a pointer
	uint8_t eth_to[ETH_ALEN];
	knot_xdp_flags_t flags;
	uint32_t seqno;
	uint32_t ackno;
	struct iovec payload;
};

typedef enum {
	KNOT_XDP_DNS_MSG,                              // payload is a single DNS message
	KNOT_XDP_DNS_PAYLOAD,                          // payload is a fraction of s data stream formed from DNS messages
	KNOT_XDP_ETHH,                                 // ethernet frame
	KNOT_XDP_IPV4H = __constant_htons(ETH_P_IP),   // IPv4 frame
	KNOT_XDP_IPV6H = __constant_htons(ETH_P_IPV6), // IPv6 frame
	KNOT_XDP_UDPH = IPPROTO_UDP,                   // UDP frame
	KNOT_XDP_TCPH = IPPROTO_TCP,                   // TCP frame
} knot_xdp_proto_t;

typedef struct {
	void *buf;
	size_t len;
	int err;
	uint16_t next_proto;
} knot_xdp_payload_t;


