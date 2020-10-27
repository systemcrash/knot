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
	check_payload(p, KNOT_XDP_H_ETH, sizeof(struct ethhdr));

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
	check_payload(p, KNOT_XDP_H_IPV4, sizeof(struct iphdr));

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
	check_payload(p, KNOT_XDP_H_IPV6, sizeof(struct ip6hdr));

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
	check_payload(p, KNOT_XDP_H_UDP, sizeof(struct udphdr));

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

	res.next_proto = KNOT_XDP_H_DNS_MSG;
	res.buf = p.buf + sizeof(struct udphdr);
	res.len = p.len - sizeof(struct udphdr);

	return res;
}

knot_xdp_payload_t knot_xdp_read_tcp(knot_xdp_payload_t p, knot_xdp_msg_t *msg)
{
	check_payload(p, KNOT_XDP_H_TCP, sizeof(struct tcphdr));

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

	res.next_proto = KNOT_XDP_H_DNS_PAYLOAD;
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
		p.next_proto = KNOT_XDP_H_DNS_MSG;
		return p;
	}

	check_payload(p, KNOT_XDP_H_DNS_PAYLOAD, sizeof(uint16_t));

	knot_xdp_payload_t res = { 0 };

	uint16_t len = be16toh(*(uint16_t *)p.buf);

	if (len != p.len - sizeof(uint16_t)) {
		res.err = KNOT_ENOTSUP;
	} else {
		res.next_proto = KNOT_XDP_H_DNS_MSG;
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
	case KNOT_XDP_H_IPV4:
		p = knot_xdp_read_ipv4(p, msg);
		break;
	case KNOT_XDP_H_IPV6:
		p = knot_xdp_read_ipv6(p, msg);
		break;
	default:
		ret_err(p, KNOT_EMALF);
	}
	switch (p.next_proto) {
	case KNOT_XDP_H_UDP:
		p = knot_xdp_read_udp(p, msg);
		break;
	case KNOT_XDP_H_TCP:
		p = knot_xdp_read_tcp(p, msg);
		p = knot_xdp_read_payload(p, msg);
		break;
	default:
		ret_err(p, KNOT_EMALF);
	}

	if (p.err == KNOT_EOK) {
		assert(p.next_proto == KNOT_XDP_H_DNS_MSG);
	}
	return p;
}

inline static uint16_t flags_ip(knot_xdp_flags_t flags)
{
	return ((flags & KNOT_XDP_IPV6) ? KNOT_XDP_H_IPV6 : KNOT_XDP_H_IPV4);
}

inline static uint8_t flags_p(knot_xdp_flags_t flags)
{
	return ((flags & KNOT_XDP_TCP) ? KNOT_XDP_H_TCP : KNOT_XDP_H_UDP);
}

void *knot_xdp_reserve_eth(void *buf, knot_xdp_flags_t flags)
{
	const struct ethhdr *eth = buf;
	eth->h_proto = flags_ip(flags);
	return eth + 1;
}

void *knot_xdp_reserve_ip(void *buf, knot_xdp_flags_t flags)
{
	if (!(flags & KNOT_XDP_IPV6)) {
		const struct iphdr *ip4 = buf;
		ip4->protocol = flags_p(flags);
		return ip4 + 1;
	} else {
		const struct iphdr *ip6 = p.buf;
		ip6->nexthdr = flags_p(flags);
		return ip6 + 1;
	}
}

void *knot_xdp_reserve(void *buf, knot_xdp_flags_t flags)
{
	buf = knot_xdp_reserve_eth(buf, flags);
	buf = knot_xdp_reserve_ip(buf, flags);
	if (!(flags & KNOT_XDP_TCP)) {
		buf += sizeof(struct udphdr);
	} else {
		buf += sizeof(struct tcphdr);
		buf += 2; // DNS message size
	}
	return buf;
}

knot_xdp_payload_t knot_xdp_write_eth(knot_xdp_payload_t p, knot_xdp_msg_t *msg)
{
	const struct ethhdr *eth = p.buf;

	check_payload(p, KNOT_XDP_H_NONE, sizeof(*eth));

	memcpy(eth->h_source, msg->eth_from, ETH_ALEN);
	memcpy(eth->h_dest, msg->eth_to, ETH_ALEN);
	eth->h_proto = flags_ip(msg->flags);

	p.buf += sizeof(*eth);
	p.len -= sizeof(*eth);

	return p;
}

static uint16_t from32to16(uint32_t sum)
{
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return sum;
}

static uint16_t ipv4_checksum(const uint16_t *ipv4_hdr)
{
	uint32_t sum32 = 0;
	for (int i = 0; i < 10; ++i) {
		if (i != 5) {
			sum32 += ipv4_hdr[i];
		}
	}
	return ~from32to16(sum32);
}

knot_xdp_payload_t knot_xdp_write_ipv4(knot_xdp_payload_t p, knot_xdp_msg_t *msg)
{
	const struct iphdr *ip4 = p.buf;

	check_payload(p, KNOT_XDP_H_NONE, sizeof(*ip4));

	ip4->version  = 4;
	ip4->ihl      = 5;
	ip4->tos      = 0;
	ip4->tot_len  = htobe16(5 * 4 + udp_len);
	ip4->id       = 0;
	ip4->frag_off = 0;
	ip4->ttl      = IPDEFTTL;
	ip4->protocol = flags_p(msg->flags);

	const struct sockaddr_in *src_v4 = (const struct sockaddr_in *)&msg->ip_from;
	const struct sockaddr_in *dst_v4 = (const struct sockaddr_in *)&msg->ip_to;
	memcpy(&ip4->saddr, &src_v4->sin_addr, sizeof(src_v4->sin_addr));
	memcpy(&ip4->daddr, &dst_v4->sin_addr, sizeof(dst_v4->sin_addr));

	ip4->check = ipv4_checksum(p.buf);

	p.buf += sizeof(*ip4);
	p.len -= sizeof(*ip4);

	return p;
}

knot_xdp_payload_t knot_xdp_write_ipv6(knot_xdp_payload_t p, knot_xdp_msg_t *msg)
{
	const struct iphdr *ip6 = p.buf;

	check_payload(p, KNOT_XDP_H_NONE, sizeof(*ip6));

	ip6->version     = 6;
	ip6->priority    = 0;
	ip6->payload_len = htobe16(p.len - sizeof(*ip6)); // == p.len afterwards
	ip6->nexthdr     = flags_p(msg->flags);
	ip6->hop_limit   = IPDEFTTL;
	memset(ip6->flow_lbl, 0, sizeof(ip6->flow_lbl));

	const struct sockaddr_in6 *src_v6 = (const struct sockaddr_in6 *)&msg->ip_from;
	const struct sockaddr_in6 *dst_v6 = (const struct sockaddr_in6 *)&msg->ip_to;

	memcpy(&ip6->saddr, &src_v6->sin6_addr, sizeof(src_v6->sin6_addr));
	memcpy(&ip6->daddr, &dst_v6->sin6_addr, sizeof(dst_v6->sin6_addr));

	p.buf += sizeof(*ip6);
	p.len -= sizeof(*ip6);

	return p;
}

/* Checksum endianness implementation notes for ipv4_checksum() and checksum().
 *
 * The basis for checksum is addition on big-endian 16-bit words, with bit 16 carrying
 * over to bit 0.  That can be viewed as first byte carrying to the second and the
 * second one carrying back to the first one, i.e. a symmetrical situation.
 * Therefore the result is the same even when arithmetics is done on litte-endian (!)
 */

static void checksum(uint32_t *result, const void *_data, uint32_t _data_len)
{
	assert(!(_data_len & 1));
	const uint16_t *data = _data;
	uint32_t len = _data_len / 2;
	while (len-- > 0) {
		*result += *data++;
	}
}

static void checksum_uint16(uint32_t *result, uint16_t x)
{
	checksum(result, &x, sizeof(x));
}

static uint16_t checksum_finish(uint32_t result, bool nonzero)
{
	while (result > 0xffff) {
		result = (result & 0xffff) + (result >> 16);
	}
	if (!nonzero || result != 0xffff) {
		result = ~result;
	}
	return result;
}

static void checksum_payload(uint32_t *result, knot_xdp_payload_t p,
                             knot_xdp_msg_t *msg, size_t hdr_len)
{
	void *payload = p.buf + hdr_len;
	assert(payload == msg->payload.iov_base);
	size_t paylen = p.len - hdr_len;
	assert(paylen == msg->payload.iov_len);
	if (paylen & 1) {
		((uint8_t *)payload)[paylen++] = 0;
	}
	checksum(result, payload, paylen);
}

knot_xdp_payload_t knot_xdp_write_udp(knot_xdp_payload_t p, knot_xdp_msg_t *msg)
{
	const struct udphdr *udp = p.buf;

	check_payload(p, KNOT_XDP_H_NONE, sizeof(*udp));

	udp->len = htobe16(p.len);

	if (!(msg->flags & KNOT_XDP_IPV6)) {
		udp->source = htobe16(((struct sockaddr_in *)&msg->ip_from)->sin_port);
		udp->dest   = htobe16(((struct sockaddr_in *)&msg->ip_to)->sin_port);
		udp->check  = 0; // UDP over IPv4 doesn't require checksum
	} else {
		udp->source = htobe16(msg->ip_from.sin6_port);
		udp->dest   = htobe16(msg->ip_to.sin6_port);
		udp->check  = 0; // temporarily to enable checksum calculation

		uint32_t chk = 0;
		checksum(&chk, &msg->ip_from.sin6_addr, sizeof(msg->ip_from.sin6_addr));
		checksum(&chk, &msg->ip_to.sin6_addr,   sizeof(msg->ip_to.sin6_addr));
		checksum(&chk, &udp->len, sizeof(udp->len));
		checksum_uint16(&chk, htobe16(KNOT_XDP_H_UDP));
		checksum(&chk, udp, sizeof(*udp));
		checksum_payload(&chk, p, msg, sizeof(*udp));
		checksum_finish(&chk, true);
		udp->check = chk;
	}

	p.buf += sizeof(*udp);
	p.len -= sizeof(*udp);

	return p;
}

knot_xdp_payload_t knot_xdp_write_tcp(knot_xdp_payload_t p, knot_xdp_msg_t *msg)
{
	const struct tcphdr *tcp = p.buf;

	check_payload(p, KNOT_XDP_H_NONE, sizeof(*tcp));

	if (!(msg->flags & KNOT_XDP_IPV6)) {
		tcp->source = htobe16(((struct sockaddr_in *)&msg->ip_from)->sin_port);
		tcp->dest   = htobe16(((struct sockaddr_in *)&msg->ip_to)->sin_port);
	} else {
		tcp->source = htobe16(msg->ip_from.sin6_port);
		tcp->dest   = htobe16(msg->ip_to.sin6_port);
	}

	tcp->doff   = 5; // size of TCP hdr with no options in 32bit dwords

	tcp->seq = htobe32(msg->seqno);
	tcp->ack_seq = htobe32(msg->ackno);

	tcp->syn = ((msg->flags & KNOT_XDP_SYN) ? 1 : 0);
	tcp->ack = ((msg->flags & KNOT_XDP_ACK) ? 1 : 0);
	tcp->fin = ((msg->flags & KNOT_XDP_FIN) ? 1 : 0);
	tcp->psh = ((msg->payload.iov_len > 0) ? 1 : 0);

	tcp->window = htobe16(0x8000); // FIXME ???
	udp->check  = 0; // temporarily to enable checksum calculation

	uint32_t chk = 0;
	if (!(msg->flags & KNOT_XDP_IPV6)) {
		checksum(&chk, &((struct sockaddr_in *)&msg->ip_from)->sin_addr, sizeof(struct in_addr));
		checksum(&chk, &((struct sockaddr_in *)&msg->ip_to)->sin_addr,   sizeof(struct in_addr));
	} else {
		checksum(&chk, &msg->ip_from.sin6_addr, sizeof(msg->ip_from.sin6_addr));
		checksum(&chk, &msg->ip_to.sin6_addr,   sizeof(msg->ip_to.sin6_addr));
	}
	checksum_uint16(&chk, htobe16(ht->ipv4.protocol));
	checksum_uint16(&chk, htobe16(p.len));
	checksum(&chk, tcp, sizeof(*tcp));
	checksum_payload(&chk, p, msg, sizeof(*tcp));
	checksum_finish(&chk, false);
	tcp->check = chk;

	p.buf += sizeof(*tcp);
	p.len -= sizeof(*tcp);

	return p;
}

knot_xdp_payload_t knot_xdp_write_payl(knot_xdp_payload_t p, knot_xdp_msg_t *msg)
{
	UNUSED(msg);

	uint16_t len = p.len - sizeof(len);

	check_payload(p, KNOT_XDP_H_NONE, sizeof(len));

	*(uint16_t *)p.buf = len;

	p.buf += sizeof(len);
	p.len -= sizeof(len);

	return p;
}

int knot_xdp_write_all(knot_xdp_payload_t p, knot_xdp_msg_t *msg)
{
	p = knot_xdp_write_eth(p, msg);

	if (!(msg->flags & KNOT_XDP_IPV6)) {
		p = knot_xdp_write_ipv4(p, msg);
	} else {
		p = knot_xdp_write_ipv6(p, msg);
	}

	if (!(msg->flags & KNOT_XDP_TCP)) {
		p = knot_xdp_write_udp(p, msg);
	} else {
		p = knot_xdp_write_tcp(p, msg);
		p = knot_xdp_write_payl(p, msg);
	}

	if (p.err == KNOT_EOK) {
		assert(p.buf == msg->payload.iov_base);
		assert(p.len == msg->payload.iov_len);
	}

	return p.err;
}

bool knot_xdp_empty_msg(knot_xdp_msg_t *msg)
{
	if (msg->payload.iov_len > 0) {
		return false;
	}
	if (msg->flags & (KNOT_XDP_SYN | KNOT_XDP_ACK | KNOT_XDP_FIN)) {
		assert(msg->flags & KNOT_XDP_TCP);
		return false;
	}
	return true;
}

bool knot_xdp_zero_header(void *hdr)
{
	struct ethhdr *eth = hdr;
	return eth->h_proto == 0;
}

// FIXME do we care for better random?
static uint32_t rnd_uint32(void)
{
	uint32_t res = rand() & 0xffff;
	res <<= 16;
	res |= rand() & 0xffff;
	return res;
}

static void knot_xdp_msg_init_base(knot_xdp_msg_t *msg, void *buf, size_t buf_size, knot_xdp_flags_t flags)
{
	memset(msg, 0, sizeof(*msg));

	msg->flags = flags;

	struct ethhdr *eth = buf;
	assert(buf_size >= sizeof(*eth));

	msg->eth_from = (void *)&eth->h_source;
	msg->eth_to = (void *)&eth->h_dest;

	msg->payload.iov_base = knot_xdp_reserve(buf, flags);
	assert(buf_size >= msg->payload.iov_base - buf);
	msg->payload.iov_len = buf_size - msg->payload.iov_base - buf;
}

void knot_xdp_msg_init(knot_xdp_msg_t *msg, void *buf, size_t buf_size, knot_xdp_flags_t flags)
{
	knot_xdp_msg_init_base(msg, buf, buf_size, flags);

	if (flags & KNOT_XDP_TCP) {
		out->ackno = 0;
		out->seqno = rnd_uint32();
	}
}

void knot_xdp_msg_answer(knot_xdp_msg_t *msg, void *buf, size_t buf_size, knot_xdp_msg_t *from)
{
	knot_xdp_msg_init_base(msg, buf, buf_size, from->flags);

	memcpy(msg->eth_from, from->eth_to, ETH_ALEN);
	memcpy(msg->eth_to,   from->eth_from, ETH_ALEN);

	memcpy(&msg->ip_from, &from->ip_to, sizeof(msg->ip_from));
	memcpy(&msg->ip_to, &from->ip_from, sizeof(msg->ip_to));

	if (flags & KNOT_XDP_TCP) {
		assert(from->flags & KNOT_XDP_TCP);
		msg->ackno = from->seqno;
		msg->ackno += from->payload.iov_len;
		if (from->flags & (KNOT_XDP_SYN | KNOT_XDP_FIN)) {
			msg->ackno++;
		}
		msg->seqno = from->ackno;
		if (msg->seqno == 0) {
			msg->seqno = rnd_uint32();
		}
	}
}
