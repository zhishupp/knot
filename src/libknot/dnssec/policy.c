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

#include <stdint.h>
#include <string.h>
#include <time.h>

#include <stdio.h>

#include "libknot/dnssec/policy.h"
#include "libknot/internal/macros.h"

/*! \todo Value 0 does not make sense as the return value should be an
 *        absolute time. If resign is planned for time '0', it never happens.
 *        The return value should either be checked in the caller function
 *        or this function should always return valid time, i.e. probably
 *        policy->now.
 */
_public_
uint32_t knot_dnssec_policy_refresh_time(const knot_dnssec_policy_t *policy,
                                         uint32_t earliest_expiration)
{
	if (policy == NULL) {
		return 0;
	}

	printf("Counting refresh time. Earliest expiration: %u.\n",
	       earliest_expiration - policy->now);

	/* TODO[jitter] This must be counted from batch interval probably.
	 *              Otherwise it may be larger than batch.
	 */
	uint32_t signature_safety = policy->sign_lifetime / 10;

	if (policy->sign_lifetime > 2 * KNOT_DNSSEC_MIN_REFRESH) {
		signature_safety = MAX(signature_safety, KNOT_DNSSEC_MIN_REFRESH);
	}

	if (earliest_expiration <= policy->now + signature_safety) {
		return 0;
	}

	return earliest_expiration - signature_safety;
}

_public_
void knot_dnssec_policy_set_sign_lifetime(knot_dnssec_policy_t *policy,
                                          uint32_t sign_lifetime)
{
	if (policy == NULL || policy->batch == NULL) {
		return;
	}

	policy->sign_lifetime = sign_lifetime;

	if (policy->batch->count == 0) {
		policy->batch->count = KNOT_DNSSEC_DEFAULT_BATCH_COUNT;
	}

	/* Batches must have some minimal interval between them. */
	if (sign_lifetime / policy->batch->count
	    < KNOT_DNSSEC_MIN_BATCH_INTERVAL) {
		policy->batch->count =
		                 sign_lifetime / KNOT_DNSSEC_MIN_BATCH_INTERVAL;
		if (policy->batch->count == 0) {
			policy->batch->count = 1;
		}
	}

	/* Resign only signatures from the next batch. */
	policy->refresh_before = policy->now
	                         + sign_lifetime / policy->batch->count;
}

_public_
void knot_dnssec_init_default_policy(knot_dnssec_policy_t *policy)
{
	if (policy == NULL || policy->batch == NULL) {
		return;
	}

	policy->forced_sign = false;
	policy->now = time(NULL);
	policy->soa_up = KNOT_SOA_SERIAL_UPDATE;
	policy->batch->count = KNOT_DNSSEC_DEFAULT_BATCH_COUNT;

	knot_dnssec_policy_set_sign_lifetime(policy, KNOT_DNSSEC_DEFAULT_LIFETIME);
}
