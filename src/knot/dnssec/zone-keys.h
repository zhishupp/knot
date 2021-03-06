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
/*!
 * \file zone-keys.h
 *
 * \brief Loading of zone keys.
 *
 * \addtogroup dnssec
 * @{
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "dnssec/kasp.h"
#include "dnssec/keystore.h"
#include "dnssec/sign.h"

/*!
 * \brief Zone key context used during signing.
 */
struct zone_key {
	const char *id;
	dnssec_key_t *key;
	dnssec_sign_ctx_t *ctx;

	time_t next_event;

	bool is_ksk;
	bool is_zsk;
	bool is_active;
	bool is_public;
};

typedef struct zone_key zone_key_t;

struct zone_keyset {
	size_t count;
	zone_key_t *keys;
};

typedef struct zone_keyset zone_keyset_t;

/*!
 * \brief Load zone keys and init cryptographic context.
 *
 * \param zone           KASP zone.
 * \param keystore       KASP key store.
 * \param nsec3_enabled  Zone uses NSEC3 for authenticated denial.
 * \param now            Current time.
 * \param keyset         Resulting zone keyset.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int load_zone_keys(dnssec_kasp_zone_t *zone, dnssec_keystore_t *store,
                   bool nsec3_enabled, time_t now, zone_keyset_t *keyset_ptr);

/*!
 * \brief Get zone key by a keytag.
 *
 * \param keys    Zone keys.
 * \param keytag  Keytag to lookup a key for.
 *
 * \return Pointer to key or NULL if not found.
 */
const zone_key_t *get_zone_key(const zone_keyset_t *keyset, uint16_t keytag);

/*!
 * \brief Free structure with zone keys and associated DNSSEC contexts.
 *
 * \param keys    Zone keys.
 */
void free_zone_keys(zone_keyset_t *keyset);

/*!
 * \brief Get timestamp of next key event.
 *
 * \param keys  Zone keys.
 *
 * \return Timestamp of next key event.
 */
time_t knot_get_next_zone_key_event(const zone_keyset_t *keyset);

/*! @} */
