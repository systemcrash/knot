/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "libknot/consts.h"
#include "libknot/common.h"
#include "libknot/mempattern.h"
#include "libknot/rrset.h"
#include "libknot/rrset-dump.h"
#include "libknot/descriptor.h"
#include "common/debug.h"
#include "libknot/util/utils.h"
#include "libknot/packet/wire.h"
#include "libknot/packet/pkt.h"
#include "libknot/dname.h"

/*!
 * \brief Get maximal size of a domain name in a wire with given capacity.
 */
#define dname_max(wire_capacity) MIN(wire_capacity, KNOT_DNAME_MAXLEN)

/*!
 * \brief Get compression pointer for a given hint.
 */
static uint16_t compr_get_ptr(knot_compr_t *compr, int hint)
{
	if (compr == NULL) {
		return 0;
	}

	return compr->rrinfo->compress_ptr[hint];
}

/*!
 * \brief Set compression pointer for a given hint.
 */
static void compr_set_ptr(knot_compr_t *compr, int hint,
                          const uint8_t *written_at, uint16_t written_size)
{
	if (compr == NULL) {
		return;
	}

	assert(written_at >= compr->wire);

	uint16_t offset = written_at - compr->wire;

	knot_pkt_compr_hint_set(compr->rrinfo, hint, offset, written_size);
}

/*!
 * \brief Write RR owner to wire.
 */
static int write_owner(const knot_rrset_t *rrset,
                       uint8_t **wire, size_t *capacity,
                       knot_compr_t *compr, knot_rrset_wire_flags_t flags)
{
	assert(rrset);
	assert(wire && *wire);
	assert(capacity);

	uint16_t owner_pointer = compr_get_ptr(compr, COMPR_HINT_OWNER);

	/* Check size */

	size_t owner_size = 0;
	if (owner_pointer > 0) {
		owner_size = sizeof(uint16_t);
	} else {
		owner_size = knot_dname_size(rrset->owner);
	}

	if (owner_size > *capacity) {
		return KNOT_ESPACE;
	}

	/* Write result */

	if (owner_pointer > 0) {
		knot_wire_put_pointer(*wire, owner_pointer);
	} else {
		int written = knot_compr_put_dname(rrset->owner, *wire,
		                                   dname_max(*capacity), compr);
		if (written < 0) {
			return written;
		}

		if (flags & KNOT_RRSET_WIRE_CANONICAL) {
			assert(compr == NULL);
			knot_dname_to_lower(*wire);
		}

		compr_set_ptr(compr, COMPR_HINT_OWNER, *wire, written);
		owner_size = written;
	}

	/* Update buffer */

	*wire += owner_size;
	*capacity -= owner_size;

	return KNOT_EOK;
}

/*!
 * \brief Write RR type, class, and TTL to wire.
 */
static int write_fixed_header(const knot_rrset_t *rrset, uint16_t rrset_index,
                              uint8_t **wire, size_t *capacity)
{
	assert(rrset);
	assert(rrset_index < rrset->rrs.rr_count);
	assert(wire && *wire);
	assert(capacity);

	/* Check capacity */

	size_t size = sizeof(uint16_t)  // type
		    + sizeof(uint16_t)  // class
		    + sizeof(uint32_t); // ttl

	if (size > *capacity) {
		return KNOT_ESPACE;
	}

	/* Write result */

	uint32_t ttl = knot_rdata_ttl(knot_rdataset_at(&rrset->rrs, rrset_index));
	uint8_t *write = *wire;

	knot_wire_write_u16(write, rrset->type);
	write += sizeof(uint16_t);
	knot_wire_write_u16(write, rrset->rclass);
	write += sizeof(uint16_t);
	knot_wire_write_u32(write, ttl);
	write += sizeof(uint32_t);
	assert(write == *wire + size);

	/* Update buffer */

	*wire = write;
	*capacity -= size;

	return KNOT_EOK;
}

/*!
 * \brief Write RDATA DNAME to wire.
 */
static int write_rdata_dname(uint8_t **src, size_t *src_avail,
                             uint8_t **wire, size_t *capacity,
                             knot_compr_t *compr, int compr_hint, bool compress,
                             knot_rrset_wire_flags_t flags)
{
	assert(src && *src);
	assert(src_avail);
	assert(wire && *wire);
	assert(capacity);

	/* Source domain name */

	const knot_dname_t *dname = *src;
	size_t dname_size = knot_dname_size(dname);

	/* Output domain name */

	int written = knot_compr_put_dname(dname, *wire, dname_max(*capacity),
	                                   compress ? compr : NULL);
	if (written < 0) {
		assert(written == KNOT_ESPACE);
		return written;
	}

	/* Post-processing */

	if (flags & KNOT_RRSET_WIRE_CANONICAL) {
		assert(compr == NULL);
		knot_dname_to_lower(*wire);
	}

	/* Update compression hints */

	if (compr_get_ptr(compr, compr_hint) == 0) {
		compr_set_ptr(compr, compr_hint, *wire, written);
	}

	/* Update buffers */

	*wire += written;
	*capacity -= written;

	*src += dname_size;
	*src_avail -= dname_size;

	return KNOT_EOK;
}

/*!
 * \brief Write a fixed block of binary data to wire.
 */
static int write_rdata_fixed(uint8_t **src, size_t *src_avail,
                             uint8_t **wire, size_t *capacity,
                             size_t size)
{
	assert(src && *src);
	assert(src_avail);
	assert(wire && *wire);
	assert(capacity);

	/* Check input/output buffer boundaries */

	if (size > *src_avail) {
		return KNOT_EMALF;
	}

	if (size > *capacity) {
		return KNOT_ESPACE;
	}

	/* Data binary copy */

	memcpy(*wire, *src, size);

	/* Update buffers */

	*src += size;
	*src_avail -= size;

	*wire += size;
	*capacity -= size;

	return KNOT_EOK;
}

/*!
 * \brief Write RDATA NAPTR header to wire.
 */
static int write_rdata_naptr(uint8_t **src, size_t *src_avail,
                             uint8_t **wire, size_t *capacity)
{
	assert(src && *src);
	assert(src_avail);
	assert(wire && *wire);
	assert(capacity);

	size_t size = 0;

	/* Fixed fields size (order, preference) */

	size += 2 * sizeof(uint16_t);

	/* Variable fields size (flags, services, regexp) */

	for (int i = 0; i < 3; i++) {
		uint8_t *len_ptr = *src + size;
		if (len_ptr >= *src + *src_avail) {
			return KNOT_EMALF;
		}

		size += 1 + *len_ptr;
	}

	/* Copy result */

	return write_rdata_fixed(src, src_avail, wire, capacity, size);
}

static int compress_dname(uint8_t **src, size_t *src_avail,
                          uint8_t **dst, size_t *dst_avail,
                          knot_compr_t *compr, int compr_hint, int type,
                          knot_rrset_wire_flags_t flags,
                          const uint8_t *pkt_wire)
{
	bool compress = (type == KNOT_RDATA_WF_COMPRESSIBLE_DNAME);

	UNUSED(pkt_wire);

	return write_rdata_dname(src, src_avail, dst, dst_avail, compr,
	                         compr_hint, compress, flags);
}

static int decompress_dname(uint8_t **src, size_t *src_avail,
                            uint8_t **dst, size_t *dst_avail,
                            knot_compr_t *compr, int compr_hint, int type,
                            knot_rrset_wire_flags_t flags,
                            const uint8_t *pkt_wire)
{
	UNUSED(compr);
	UNUSED(compr_hint);

	bool decompress = (type == KNOT_RDATA_WF_COMPRESSIBLE_DNAME
	                   || type == KNOT_RDATA_WF_DECOMPRESSIBLE_DNAME);

	int ret = knot_dname_wire_check(*src, *src + *src_avail, pkt_wire);
	if (ret <= 0) {
		return KNOT_EMALF;
	}

	size_t dname_size = ret;
	int written = dname_size;

	if (decompress) {
		int ret = knot_dname_unpack(*dst, *src, *dst_avail, pkt_wire);
		if (ret <= 0) {
			return ret;
		}
		written = ret;
	} else if (dname_size > *dst_avail) {
		return KNOT_ESPACE;
	} else {
		memcpy(*dst, *src, dname_size);
	}

	/* Post-processing */

	if (flags & KNOT_RRSET_WIRE_CANONICAL) {
		knot_dname_to_lower(*dst);
	}

	/* Update buffers */

	*dst += written;
	*dst_avail -= written;

	*src += dname_size;
	*src_avail -= dname_size;

	return KNOT_EOK;
}

typedef int (*dname_callback_t)(uint8_t **, size_t *, uint8_t **, size_t *,
                                knot_compr_t *, int, int,
                                knot_rrset_wire_flags_t, const uint8_t *);

static int traverse_rdata(const rdata_descriptor_t *desc, uint8_t **src,
                          size_t *src_avail, uint8_t **wire, size_t *capacity,
                          knot_compr_t *compr, int compr_hint,
                          knot_rrset_wire_flags_t flags, const uint8_t *pkt_wire,
                          dname_callback_t dname_callback)
{
	int ret = KNOT_EOK;

	for (int i = 0; desc->block_types[i] != KNOT_RDATA_WF_END; i++) {
		int type = desc->block_types[i];

		switch (type) {
		case KNOT_RDATA_WF_COMPRESSIBLE_DNAME:
		case KNOT_RDATA_WF_DECOMPRESSIBLE_DNAME:
		case KNOT_RDATA_WF_FIXED_DNAME:
			ret = dname_callback(src, src_avail, wire, capacity,
			                     compr, compr_hint, type, flags,
			                     pkt_wire);
			break;
		case KNOT_RDATA_WF_NAPTR_HEADER:
			ret = write_rdata_naptr(src, src_avail, wire, capacity);
			break;
		case KNOT_RDATA_WF_REMAINDER:
			ret = write_rdata_fixed(src, src_avail, wire, capacity,
			                        *src_avail);
			break;
		default:
			/* Fixed size block */
			assert(type > 0);
			ret = write_rdata_fixed(src, src_avail, wire, capacity,
			                        type);
		}

		/* TODO: unify the write_rdata_... functions - do the copying
		 * after the switch, before that just count the size.
		 */

		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

/*!
 * \brief Write RDLENGTH and RDATA fields of a RR in a wire.
 */
static int write_rdata(const knot_rrset_t *rrset, uint16_t rrset_index,
                       uint8_t **wire, size_t *capacity,
                       knot_compr_t *compr, knot_rrset_wire_flags_t flags)
{
	assert(rrset);
	assert(rrset_index < rrset->rrs.rr_count);
	assert(wire && *wire);
	assert(capacity);

	const knot_rdata_t *rdata = knot_rdataset_at(&rrset->rrs, rrset_index);

	/* Reserve space for RDLENGTH */

	size_t rdlength_size = sizeof(uint16_t);
	if (rdlength_size > *capacity) {
		return KNOT_ESPACE;
	}

	uint8_t *wire_rdlength = *wire;
	*wire += rdlength_size;
	*capacity -= rdlength_size;

	/* Write RDATA */

	uint8_t *wire_rdata_begin = *wire;
	int compr_hint = COMPR_HINT_RDATA + rrset_index;

	uint8_t *src = knot_rdata_data(rdata);
	size_t src_avail = knot_rdata_rdlen(rdata);
	if (src_avail > 0) {
		/* Only write non-empty data. */
		const rdata_descriptor_t *desc =
			knot_get_rdata_descriptor(rrset->type);
		int ret = traverse_rdata(desc, &src, &src_avail, wire,
		                         capacity, compr, compr_hint, flags,
		                         NULL, compress_dname);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	if (src_avail > 0) {
		/* Trailing data in the message. */
		return KNOT_EMALF;
	}

	/* Write final RDLENGTH */

	size_t rdlength = *wire - wire_rdata_begin;
	knot_wire_write_u16(wire_rdlength, rdlength);

	return KNOT_EOK;
}

/*!
 * Write one RR from a RR Set to wire.
 */
static int write_rr(const knot_rrset_t *rrset, uint16_t rrset_index,
                    uint8_t **wire, size_t *capacity, knot_compr_t *compr,
                    knot_rrset_wire_flags_t flags)
{
	int ret;

	ret = write_owner(rrset, wire, capacity, compr, flags);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = write_fixed_header(rrset, rrset_index, wire, capacity);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = write_rdata(rrset, rrset_index, wire, capacity, compr, flags);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return KNOT_EOK;
}

int knot_rrset_to_wire(const knot_rrset_t *rrset, uint8_t *wire, uint16_t max_size,
                       knot_compr_t *compr, knot_rrset_wire_flags_t flags)
{
	if (!rrset || !wire) {
		return KNOT_EINVAL;
	}

	if (flags & KNOT_RRSET_WIRE_CANONICAL) {
		compr = NULL;
	}

	uint8_t *write = wire;
	size_t capacity = max_size;

	for (uint16_t i = 0; i < rrset->rrs.rr_count; i++) {
		int ret = write_rr(rrset, i, &write, &capacity, compr, flags);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	size_t written = write - wire;

	return written;
}

knot_rrset_t *knot_rrset_new(const knot_dname_t *owner, uint16_t type,
                             uint16_t rclass, mm_ctx_t *mm)
{
	knot_dname_t *owner_cpy = knot_dname_copy(owner, mm);
	if (owner_cpy == NULL) {
		return NULL;
	}

	knot_rrset_t *ret = mm_alloc(mm, sizeof(knot_rrset_t));
	if (ret == NULL) {
		ERR_ALLOC_FAILED;
		knot_dname_free(&owner_cpy, mm);
		return NULL;
	}

	knot_rrset_init(ret, owner_cpy, type, rclass);

	return ret;
}

void knot_rrset_init(knot_rrset_t *rrset, knot_dname_t *owner, uint16_t type,
                     uint16_t rclass)
{
	rrset->owner = owner;
	rrset->type = type;
	rrset->rclass = rclass;
	knot_rdataset_init(&rrset->rrs);
	rrset->additional = NULL;
}

void knot_rrset_init_empty(knot_rrset_t *rrset)
{
	knot_rrset_init(rrset, NULL, 0, KNOT_CLASS_IN);
}

knot_rrset_t *knot_rrset_copy(const knot_rrset_t *src, mm_ctx_t *mm)
{
	if (src == NULL) {
		return NULL;
	}

	knot_rrset_t *rrset = knot_rrset_new(src->owner, src->type,
	                                     src->rclass, mm);
	if (rrset == NULL) {
		return NULL;
	}

	int ret = knot_rdataset_copy(&rrset->rrs, &src->rrs, mm);
	if (ret != KNOT_EOK) {
		knot_rrset_free(&rrset, mm);
		return NULL;
	}

	return rrset;
}

void knot_rrset_free(knot_rrset_t **rrset, mm_ctx_t *mm)
{
	if (rrset == NULL || *rrset == NULL) {
		return;
	}

	knot_rrset_clear(*rrset, mm);

	mm_free(mm, *rrset);
	*rrset = NULL;
}

void knot_rrset_clear(knot_rrset_t *rrset, mm_ctx_t *mm)
{
	if (rrset) {
		knot_rdataset_clear(&rrset->rrs, mm);
		knot_dname_free(&rrset->owner, mm);
	}
}

static bool allow_zero_rdata(const knot_rrset_t *rr, const rdata_descriptor_t *desc)
{
	return rr->rclass != KNOT_CLASS_IN ||  // NONE and ANY for DDNS
	       rr->type == KNOT_RRTYPE_APL ||  // APLs can have 0 RDLENGTH
	       desc->type_name == NULL;        // Unknown RR types can have 0 RDLENGTH
}

int knot_rrset_rdata_from_wire_one(knot_rrset_t *rrset,
                                   const uint8_t *wire, size_t *pos,
                                   size_t total_size, uint32_t ttl,
                                   size_t rdlength,
                                   mm_ctx_t *mm)
{
	if (rrset == NULL || wire == NULL || pos == NULL) {
		return KNOT_EINVAL;
	}

	if (total_size - *pos < rdlength) {
		return KNOT_EMALF;
	}

	const rdata_descriptor_t *desc = knot_get_rdata_descriptor(rrset->type);

	/* Check for obsolete record. */
	if (desc->type_name == NULL) {
		desc = knot_get_obsolete_rdata_descriptor(rrset->type);
	}

	if (rdlength == 0) {
		if (allow_zero_rdata(rrset, desc)) {
			return knot_rrset_add_rdata(rrset, NULL, 0, ttl, mm);
		} else {
			return KNOT_EMALF;
		}
	}

	size_t dst_avail = rdlength + KNOT_DNAME_MAXLEN;
	uint8_t rdata_buffer[dst_avail];
	memset(rdata_buffer, 0, dst_avail);

	/* TODO: resolve the consts. */
	uint8_t *src = wire + *pos;
	size_t src_avail = rdlength;
	uint8_t *dst = rdata_buffer;

	int ret = traverse_rdata(desc, &src, &src_avail, &dst, &dst_avail,
	                         NULL, 0, KNOT_RRSET_WIRE_NONE, wire,
	                         decompress_dname);
	if (ret != KNOT_EOK) {
		return ret;
	}

	assert(src_avail == 0);
	*pos += rdlength;

	size_t dst_size = dst - rdata_buffer;
	assert(dst_size == rdlength + KNOT_DNAME_MAXLEN - dst_avail);

	return knot_rrset_add_rdata(rrset, rdata_buffer, dst_size, ttl, mm);
}

int knot_rrset_add_rdata(knot_rrset_t *rrset,
                         const uint8_t *rdata, const uint16_t size,
                         const uint32_t ttl, mm_ctx_t *mm)
{
	if (rrset == NULL || (rdata == NULL && size > 0)) {
		return KNOT_EINVAL;
	}

	knot_rdata_t rr[knot_rdata_array_size(size)];
	knot_rdata_init(rr, size, rdata, ttl);

	return knot_rdataset_add(&rrset->rrs, rr, mm);
}

bool knot_rrset_equal(const knot_rrset_t *r1,
                      const knot_rrset_t *r2,
                      knot_rrset_compare_type_t cmp)
{
	if (cmp == KNOT_RRSET_COMPARE_PTR) {
		return r1 == r2;
	}

	if (r1->type != r2->type) {
		return false;
	}

	if (r1->owner && r2->owner) {
		if (!knot_dname_is_equal(r1->owner, r2->owner)) {
			return false;
		}
	} else if (r1->owner != r2->owner) { // At least one is NULL.
		return false;
	}

	if (cmp == KNOT_RRSET_COMPARE_WHOLE) {
		return knot_rdataset_eq(&r1->rrs, &r2->rrs);
	}

	return true;
}

bool knot_rrset_empty(const knot_rrset_t *rrset)
{
	if (rrset) {
		uint16_t rr_count = rrset->rrs.rr_count;
		return rr_count == 0;
	} else {
		return true;
	}
}

uint32_t knot_rrset_ttl(const knot_rrset_t *rrset)
{
	return knot_rdata_ttl(knot_rdataset_at(&(rrset->rrs), 0));
}

