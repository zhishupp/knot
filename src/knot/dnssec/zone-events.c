/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <time.h>

#include "libknot/internal/mem.h"
#include "knot/conf/conf.h"
#include "libknot/dnssec/policy.h"
#include "knot/dnssec/zone-events.h"
#include "knot/dnssec/zone-keys.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/dnssec/zone-sign.h"
#include "knot/common/debug.h"
#include "knot/zone/zone.h"
#include "libknot/rrtype/rrsig.h"

static uint32_t get_first_batch(const knot_dnssec_policy_t *policy,
                                const zone_contents_t *zone, bool force)
{
	knot_rrset_t apex_rrsig = node_rrset(zone->apex, KNOT_RRTYPE_RRSIG);
	if (force || apex_rrsig.type != KNOT_RRTYPE_RRSIG) {
		// No RRSIG or forced resign, first batch is one batch interval from now
		return policy->now + policy->sign_lifetime / policy->batch->count;
	}

	/* Just get any expiration, the first can be counted from it. */
	uint32_t expire = knot_rrsig_sig_expiration(&apex_rrsig.rrs, 0);

	/* Expiration may be in the past. */
	while (expire < policy->now) {
		expire += policy->sign_lifetime;
	}

	uint32_t first = policy->now + ((expire - policy->now)
	                      % (policy->sign_lifetime / policy->batch->count));

	/* If first batch is less than refresh interval from now, it means it
	 * will be resigned. Use the next batch after refresh.
	 */
	while (first <= policy->now + policy->refresh) {
		first += policy->sign_lifetime / policy->batch->count;
	}

	return first;
}

static int init_dnssec_structs(const zone_contents_t *zone,
                               const conf_zone_t *config,
                               knot_zone_keys_t *zone_keys,
                               knot_dnssec_policy_t *policy,
                               knot_update_serial_t soa_up, bool force)
{
	assert(zone);
	assert(config);
	assert(zone_keys);
	assert(policy);
	assert(policy->batch);

	// Read zone keys from disk
	bool nsec3_enabled = knot_is_nsec3_enabled(zone);
	int result = knot_load_zone_keys(config->dnssec_keydir,
	                                 zone->apex->owner,
	                                 nsec3_enabled, zone_keys);
	if (result != KNOT_EOK) {
		log_zone_error(zone->apex->owner, "DNSSEC, failed to load keys (%s)",
		               knot_strerror(result));
		knot_free_zone_keys(zone_keys);
		return result;
	}

	// Init sign policy
	knot_dnssec_init_default_policy(policy);
	policy->soa_up = soa_up;
	policy->forced_sign = force;

	// Override signature lifetime, if set in config
	//! \todo Later: also override 'refresh' interval if set in config.
	if (config->sig_lifetime > 0) {
		knot_dnssec_policy_set_sign_lifetime(policy,
		                                     config->sig_lifetime,
		                                     policy->refresh);
	}

	// Get the time of the first batch in the zone
	policy->batch->first = get_first_batch(policy, zone, force);
	assert(policy->batch->first > policy->now);

	return KNOT_EOK;
}

static int zone_sign(zone_contents_t *zone, const conf_zone_t *zone_config,
                     changeset_t *out_ch, bool force,
                     knot_update_serial_t soa_up, uint32_t *refresh_at)
{
	assert(zone);
	assert(out_ch);

	const knot_dname_t *zone_name = zone->apex->owner;

	log_zone_info(zone_name, "DNSSEC, signing started");
	uint32_t new_serial = zone_contents_next_serial(zone, zone_config->serial_policy);

	dbg_dnssec_verb("changeset empty before generating NSEC chain: %d\n",
	                changeset_empty(out_ch));

	// Init needed structs
	knot_zone_keys_t zone_keys;
	knot_init_zone_keys(&zone_keys);
	knot_dnssec_policy_t policy = { 0 };
	knot_dnssec_batch_t batch = { 0 };
	policy.batch = &batch;

	int result = init_dnssec_structs(zone, zone_config, &zone_keys, &policy,
	                                 soa_up, force);
	if (result != KNOT_EOK) {
		return result;
	}

	// Expiration must be an absolute value
	uint32_t min_expire = policy.now + policy.sign_lifetime;

	// generate NSEC records
	result = knot_zone_create_nsec_chain(zone, out_ch, &zone_keys, &policy,
	                                     &min_expire);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to create NSEC(3) chain (%s)",
		               knot_strerror(result));
		knot_free_zone_keys(&zone_keys);
		return result;
	}
	dbg_dnssec_verb("changeset empty after generating NSEC chain: %d\n",
	                changeset_empty(out_ch));

	// add missing signatures
	result = knot_zone_sign(zone, &zone_keys, &policy, out_ch, &min_expire);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to sign the zone (%s)",
		               knot_strerror(result));
		knot_free_zone_keys(&zone_keys);
		return result;
	}
	dbg_dnssec_verb("changeset emtpy after signing: %d\n",
	                changeset_empty(out_ch));

	// Check if only SOA changed
	if (changeset_empty(out_ch) &&
	    !knot_zone_sign_soa_expired(zone, &zone_keys, &policy, &min_expire)) {
		log_zone_info(zone_name, "DNSSEC, no signing performed, zone is valid");
		knot_free_zone_keys(&zone_keys);
		assert(changeset_empty(out_ch));
		*refresh_at = knot_dnssec_policy_refresh_time(&policy, min_expire);
		return KNOT_EOK;
	}

	// update SOA if there were any changes
	knot_rrset_t soa = node_rrset(zone->apex, KNOT_RRTYPE_SOA);
	knot_rrset_t rrsigs = node_rrset(zone->apex, KNOT_RRTYPE_RRSIG);
	assert(!knot_rrset_empty(&soa));
	result = knot_zone_sign_update_soa(&soa, &rrsigs, &zone_keys, &policy,
	                                   new_serial, out_ch, &min_expire);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, not signing, failed to update "
		               "SOA record (%s)", knot_strerror(result));
		knot_free_zone_keys(&zone_keys);
		return result;
	}

	// DNSKEY updates
	uint32_t dnskey_update = knot_get_next_zone_key_event(&zone_keys);
	if (min_expire < dnskey_update) {
		// Signatures expire before keys do
		assert(policy.batch->first != 0);
		assert(min_expire <= policy.batch->first);
		*refresh_at = knot_dnssec_policy_refresh_time(&policy, min_expire);
	} else {
		// Keys expire before signatures
		*refresh_at = dnskey_update;
	}

	knot_free_zone_keys(&zone_keys);
	dbg_dnssec_detail("zone signed: changes=%zu\n", changeset_size(out_ch));

	log_zone_info(zone_name, "DNSSEC, successfully signed");

	return KNOT_EOK;
}

int knot_dnssec_zone_sign(zone_contents_t *zone, const conf_zone_t *zone_config,
                          changeset_t *out_ch,
                          knot_update_serial_t soa_up, uint32_t *refresh_at)
{
	if (zone == NULL || zone_config == NULL || out_ch == NULL) {
		return KNOT_EINVAL;
	}

	return zone_sign(zone, zone_config, out_ch, false, soa_up, refresh_at);
}

int knot_dnssec_zone_sign_force(zone_contents_t *zone, const conf_zone_t *zone_config,
                                changeset_t *out_ch, uint32_t *refresh_at)
{
	if (zone == NULL || zone_config == NULL || out_ch == NULL) {
		return KNOT_EINVAL;
	}

	return zone_sign(zone, zone_config, out_ch, true, KNOT_SOA_SERIAL_UPDATE,
	                 refresh_at);
}

int knot_dnssec_sign_changeset(const zone_contents_t *zone,
                               conf_zone_t *zone_config,
                               const changeset_t *in_ch,
                               changeset_t *out_ch,
                               uint32_t *refresh_at)
{
	if (zone == NULL || in_ch == NULL || out_ch == NULL || refresh_at == NULL) {
		return KNOT_EINVAL;
	}

	const knot_dname_t *zone_name = zone->apex->owner;

	// Keep the original serial
	knot_update_serial_t soa_up = KNOT_SOA_SERIAL_KEEP;
	uint32_t new_serial = zone_contents_serial(zone);

	// Init needed structures
	knot_zone_keys_t zone_keys;
	knot_init_zone_keys(&zone_keys);
	knot_dnssec_policy_t policy = { 0 };
	knot_dnssec_batch_t batch = { 0 };
	policy.batch = &batch;
	int ret = init_dnssec_structs(zone, zone_config, &zone_keys, &policy,
	                              soa_up, false);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Expiration must be an absolute value
	uint32_t min_expire = policy.now + policy.sign_lifetime;

	// Sign added and removed RRSets in changeset
	ret = knot_zone_sign_changeset(zone, in_ch, out_ch,
	                               &zone_keys, &policy, &min_expire);
	if (ret != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to sign changeset (%s)",
		               knot_strerror(ret));
		knot_free_zone_keys(&zone_keys);
		return ret;
	}

	// Create NSEC(3) chain
	ret = knot_zone_create_nsec_chain(zone, out_ch, &zone_keys, &policy,
	                                  &min_expire);
	if (ret != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to create NSEC(3) chain (%s)",
		               knot_strerror(ret));
		knot_free_zone_keys(&zone_keys);
		return ret;
	}

	// Update SOA RRSIGs
	knot_rrset_t soa = node_rrset(zone->apex, KNOT_RRTYPE_SOA);
	knot_rrset_t rrsigs = node_rrset(zone->apex, KNOT_RRTYPE_RRSIG);
	ret = knot_zone_sign_update_soa(&soa, &rrsigs, &zone_keys, &policy,
	                                new_serial, out_ch, &min_expire);
	if (ret != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to sign SOA record (%s)",
		               knot_strerror(ret));
		knot_free_zone_keys(&zone_keys);
		return ret;
	}

	knot_free_zone_keys(&zone_keys);

	/*! \note Maybe we don't need the earliest expiration. First batch time
	 *        should be the earliest, everything before that should have
	 *        been resigned. but is there a way to ensure that? What if the
	 *        parameters' values change?
	 *        This approach, with always getting the current minimum
	 *        expiration time is IMHO safer and it's not a big overhead.
	 * \todo  Remove this note before merging.
	 */
	assert(policy.batch->first != 0);
	assert(policy.batch->first > policy.now);
	*refresh_at = knot_dnssec_policy_refresh_time(&policy, min_expire);

	return KNOT_EOK;
}
