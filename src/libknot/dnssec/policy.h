/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \file policy.h
 *
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 *
 * \brief Policy for handling of DNSSEC signatures and keys.
 *
 * \addtogroup dnssec
 * @{
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef enum knot_update_serial {
	KNOT_SOA_SERIAL_UPDATE = 1 << 0,
	KNOT_SOA_SERIAL_KEEP = 1 << 1
} knot_update_serial_t;

typedef struct {
	uint32_t count;             //! Count of signing batches.
	uint32_t cur_nr;            //! Current batch number. Counted from 1.
	uint32_t first;             //! Expiration of the first batch (absolute).
	uint32_t current;           //! Expiration of the current batch (absolute)
} knot_dnssec_batch_t;

typedef struct {
	uint32_t now;               //! Current time.

	/*! Plan next resign this time before earliest expiration.
	 *  Also renew signatures expiring before 'refresh' from 'now'.
	 */
	uint32_t refresh;
	uint32_t sign_lifetime;     //! Signature life time.
	knot_dnssec_batch_t *batch; //! Batch info
	bool forced_sign;           //! Drop valid signatures as well.
	knot_update_serial_t soa_up;//! Policy for serial updating.
} knot_dnssec_policy_t;

#define KNOT_DNSSEC_DEFAULT_LIFETIME 2592000	// 30 days
#define KNOT_DNSSEC_DEFAULT_BATCH_COUNT 10	// one batch every 3 days
#define KNOT_DNSSEC_MIN_BATCH_INTERVAL 259200	// 3 days
#define KNOT_DNSSEC_MIN_REFRESH 86400		// 1 day

/*!
 * \brief Initialize default signing policy.
 */
void knot_dnssec_init_default_policy(knot_dnssec_policy_t *policy);

/*!
 * \brief Set policy timing data according to requested signature lifetime.
 */
void knot_dnssec_policy_set_sign_lifetime(knot_dnssec_policy_t *policy,
                                          uint32_t sign_lifetime,
                                          uint32_t refresh);

/*!
 * \brief Get signature refresh time from the earliest expiration time.
 *
 * \note \a earliest_expiration must be an absolute value.
 */
uint32_t knot_dnssec_policy_refresh_time(const knot_dnssec_policy_t *policy,
                                         uint32_t earliest_expiration);


/*! @} */
