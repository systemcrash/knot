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

#include "libknot/xdp/protocols.h"

#include <assert.h>
#include <errno.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libknot/attribute.h"
#include "libknot/endian.h"
#include "libknot/errcode.h"
#include "contrib/macros.h"

#define check_payload(p, proto, minlen) \
	do { if ((p).err != KNOT_EOK) { return (p); } \
	     if ((p).next_proto != (proto)) { (p).err = KNOT_EINVAL; return (p); } \
	     if ((p).len < (minlen)) { (p).err = KNOT_EMALF; return (p); } \
	} while (0)

knot_xdp_payload_t knot_xdp_read_eth(knot_xdp_payload_t p, knot_xdp_msg_t *msg)
{
	check_payload(p, KNOT_XDP_ETHH, sizeof(struct ethhdr));

	knot_xdp_payload_t res = { 0 };

	const struct ethhdr *eth = p.buf;

	if (msg != NULL) {
		memcpy(msg->eth_from, eth->h_source, ETH_ALEN);
		memcpy(msg->eth_to, eth->h_dest, ETH_ALEN);
	}

	res.next_proto = eth->h_proto;
	res.buf = p.buf + sizeof(*eth);
	res.len = p.len - sizeof(*eth);

	return res;
}

knot_xdp_payload_t knot_xdp_read_ipv4(knot_xdp_payload_t p, knot_xdp_msg_t *msg)
{
	check_payload(p, KNOT_XDP_IPV4H, sizeof(struct iphdr));

	knot_xdp_payload_t res = { 0 };

	const struct iphdr *ip4 = p.buf;

	// those asserts are ensured by the BPF filter that does not let the packet through otherwise
	assert(ip4->version == 4);
	assert(ip4->frag_off == 0 || ip4->frag_off == __constant_htons(IP_DF));

	if (msg != NULL) {
		msg->flags &= ~KNOT_XDP_IPV6;

		struct sockaddr_in *src_v4 = (struct sockaddr_in *)&msg->ip_from;
		struct sockaddr_in *dst_v4 = (struct sockaddr_in *)&msg->ip_to;
		memcpy(&src_v4->sin_addr, &ip4->saddr, sizeof(src_v4->sin_addr));
		memcpy(&dst_v4->sin_addr, &ip4->daddr, sizeof(dst_v4->sin_addr));
		src_v4->sin_family = AF_INET;
		dst_v4->sin_family = AF_INET;
	}

	res.next_proto = ip4->protocol;
	res.buf = p.buf + ip4->ihl * 4;
	res.len = be16toh(ip4->tot_len) - ip4->ihl * 4;

	return res;
}

knot_xdp_payload_t knot_xdp_read_ipv6(knot_xdp_payload_t p, knot_xdp_msg_t *msg)
{
	check_payload(p, KNOT_XDP_IPV6H, sizeof(struct ip6hdr));

	knot_xdp_payload_t res = { 0 };

	const struct ipv6hdr *ip6 = p.buf;

	assert(ip6->version == 6);

	if (msg != NULL) {
		msg->flags |= KNOT_XDP_IPV6;

		struct sockaddr_in6 *src_v6 = (struct sockaddr_in6 *)&msg->ip_from;
		struct sockaddr_in6 *dst_v6 = (struct sockaddr_in6 *)&msg->ip_to;
		memcpy(&src_v6->sin6_addr, &ip6->saddr, sizeof(src_v6->sin6_addr));
		memcpy(&dst_v6->sin6_addr, &ip6->daddr, sizeof(dst_v6->sin6_addr));
		src_v6->sin6_family = AF_INET6;
		dst_v6->sin6_family = AF_INET6;
		// Flow label is ignored.
	}

	res.next_proto = ip6->nexthdr;
	res.buf = p.buf + sizeof(struct ipv6hdr);
	res.len = be16toh(ip6->payload_len);

	return res;
}

knot_xdp_payload_t knot_xdp_read_udp(knot_xdp_payload_t p, knot_xdp_msg_t *msg)
{
	check_payload(p, KNOT_XDP_UDPH, sizeof(struct udphdr));

	knot_xdp_payload_t res = { 0 };

	const struct udphdr *udp = p.buf;

	assert(p.len == be16toh(udp->len));
	// NOTICE: UDP checksum is not verified

	if (msg != NULL) {
		msg->flags &= ~KNOT_XDP_TCP;

		if (!(msg->flags & KNOT_XDP_IPV6)) {
			((struct sockaddr_in *)&msg->ip_from)->sin_port = be16toh(udp->source);
			((struct sockaddr_in *)&msg->ip_to)->sin_port = be16toh(udp->dest);
		} else {
			((struct sockaddr_in6 *)&msg->ip6_from)->sin_port = be16toh(udp->source);
			((struct sockaddr_in6 *)&msg->ip6_to)->sin_port = be16toh(udp->dest);
		}
	}

	res.next_proto = KNOT_XDP_DNS_MSG;
	res.buf = p.buf + sizeof(struct udphdr);
	res.len = p.len - sizeof(struct udphdr);

	return res;
}

knot_xdp_payload_t knot_xdp_read_tcp(knot_xdp_payload_t p, knot_xdp_msg_t *msg)
{
	check_payload(p, KNOT_XDP_TCPH, sizeof(struct tcphdr));

	knot_xdp_payload_t res = { 0 };

	const struct tcphdr *tcp = p.buf;

	if (msg != NULL) {
		msg->flags |= KNOT_XDP_TCP;
		if (tcp->syn) {
			msg->flags |= KNOT_XDP_SYN;
		}
		if (tcp->ack) {
			msg->flags |= KNOT_XDP_ACK;
		}
		if (tcp->fin) {
			msg->flags |= KNOT_XDP_FIN;
		}
		msg->seqno = be32toh(tcp->seq);
		msg->ackno = be32toh(tcp->ack_seq);

		if (!(msg->flags & KNOT_XDP_IPV6)) {
			((struct sockaddr_in *)&msg->ip_from)->sin_port = be16toh(tcp->source);
			((struct sockaddr_in *)&msg->ip_to)->sin_port = be16toh(tcp->dest);
		} else {
			((struct sockaddr_in6 *)&msg->ip6_from)->sin_port = be16toh(tcp->source);
			((struct sockaddr_in6 *)&msg->ip6_to)->sin_port = be16toh(tcp->dest);
		}
	}

	res.next_proto = KNOT_XDP_DNS_PAYLOAD;
	res.buf = p.buf + tcp->doff * 4;
	res.len = p.len - tcp->doff * 4;

	return res;
}

// this function is based on the (FIXME!) assumption that a TCP packet contains one whole DNS msg
knot_xdp_payload_t knot_xdp_read_payload(knot_xdp_payload_t p, knot_xdp_msg_t *msg)
{
	UNUSED(msg);

	// special case: empty packet means empty DNS msg
	if (p.len == 0) {
		p.next_proto = KNOT_XDP_DNS_MSG;
		return p;
	}

	check_payload(p, KNOT_XDP_DNS_PAYLOAD, sizeof(uint16_t));

	knot_xdp_payload_t res = { 0 };

	uint16_t len = be16toh(*(uint16_t *)p.buf);

	if (len != p.len - sizeof(uint16_t)) {
		res.err = KNOT_ENOTSUP;
	} else {
		res.next_proto = KNOT_XDP_DNS_MSG;
		res.buf = p.buf + sizeof(uint16_t);
		res.len = p.len - sizeof(uint16_t);
	}

	return res;
}

#define ret_err(p, errcode) do { if ((p).err == KNOT_EOK) { (p).err = (errcode); } return (p); } while (0)

knot_xdp_payload_t knot_xdp_read_all(knot_xdp_payload_t p, knot_xdp_msg_t *msg)
{
	p = knot_xdp_read_eth(p, msg);
	switch (p.next_proto) {
	case KNOT_XDP_IPV4H:
		p = knot_xdp_read_ipv4(p, msg);
		break;
	case KNOT_XDP_IPV6H:
		p = knot_xdp_read_ipv6(p, msg);
		break;
	default:
		ret_err(p, KNOT_EMALF);
	}
	switch (p.next_proto) {
	case KNOT_XDP_UDPH:
		p = knot_xdp_read_udp(p, msg);
		break;
	case KNOT_XDP_TCPH:
		p = knot_xdp_read_tcp(p, msg);
		p = knot_xdp_read_payload(p, msg);
		break;
	default:
		ret_err(p, KNOT_EMALF);
	}

	if (p.err == KNOT_EOK) {
		assert(p.next_proto == KNOT_XDP_DNS_MSG);
	}
	return p;
}
