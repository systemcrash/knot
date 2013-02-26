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

#ifndef _KNOT_SIGN_KEY_H_
#define _KNOT_SIGN_KEY_H_

#include "tsig.h"

enum knot_key_type {
	KNOT_KEY_UNKNOWN = 0,
	KNOT_KEY_DNSSEC, //!< DNSSEC key. Described in RFC 2535 and RFC 4034.
	KNOT_KEY_TSIG,   //!< Transaction Signature. Described in RFC 2845.
	KNOT_KEY_TKEY    //!< Transaction Key. Described in RFC 2930.
};

enum knot_key_usage {
	KNOT_KEY_USAGE_NONE = 0,
	KNOT_KEY_USAGE_ZONE_SIGN = 1,
	KNOT_KEY_USAGE_TRANSACTION_SIGN = 2
};

/*!
 * \brief Key attributes loaded from keyfile.
 */
struct knot_key_params {
	char *name;
	int algorithm;
	// parameters for symmetric cryptography
	char *secret;
	// parameters for public key cryptography
	char *modulus;
	char *public_exponent;
	char *private_exponent;
	char *prime_one;
	char *prime_two;
	char *exponent_one;
	char *exponent_two;
	char *coefficient;
};

typedef struct knot_key_params knot_key_params_t;

int knot_load_key_params(const char *filename, knot_key_params_t *key_params);
int knot_free_key_params(knot_key_params_t *key_params);

int knot_tsig_key_from_key_params(const knot_key_params_t *params, knot_key_t *key);
//int knot_dnssec_key_from_key_params(const knot_key_params_t *params, knot_dnssec_key_t *key);

#endif // _KNOT_SIGN_KEY_H_
