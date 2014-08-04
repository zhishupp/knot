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
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "dnssec/error.h"
#include "dnssec/key.h"
#include "dnssec/sign.h"
#include "libknot/common.h"
#include "libknot/descriptor.h"
#include "libknot/dnssec/key.h"
#include "libknot/dnssec/policy.h"
#include "libknot/dnssec/rrset-sign.h"
#include "libknot/errcode.h"
#include "libknot/rrset.h"
#include "libknot/rrtype/rrsig.h"

#define MAX_RR_WIREFORMAT_SIZE (64 * 1024)
#define RRSIG_RDATA_SIGNER_OFFSET 18

/*- Creating of RRSIGs -------------------------------------------------------*/

/*!
 * \brief Get size of RRSIG RDATA for a given key without signature.
 */
size_t knot_rrsig_rdata_size(const dnssec_key_t *key)
{
	if (!key) {
		return 0;
	}

	size_t size;

	// static part

	size = sizeof(uint16_t)		// type covered
	     + sizeof(uint8_t)		// algorithm
	     + sizeof(uint8_t)		// labels
	     + sizeof(uint32_t)		// original TTL
	     + sizeof(uint32_t)		// signature expiration
	     + sizeof(uint32_t)		// signature inception
	     + sizeof(uint16_t);	// key tag (footprint)

	assert(size == RRSIG_RDATA_SIGNER_OFFSET);

	// variable part

	const uint8_t *signer = dnssec_key_get_dname(key);
	assert(signer);
	size += knot_dname_size(signer);

	return size;
}

/*!
 * \brief Write RRSIG RDATA except signature.
 */
int knot_rrsig_write_rdata(uint8_t *rdata, const dnssec_key_t *key,
                           uint16_t covered_type, uint8_t owner_labels,
                           uint32_t owner_ttl,  uint32_t sig_incepted,
                           uint32_t sig_expires)
{
	if (!rdata || !key || sig_incepted >= sig_expires) {
		return KNOT_EINVAL;
	}

	uint8_t algorithm = dnssec_key_get_algorithm(key);
	uint16_t keytag = dnssec_key_get_keytag(key);
	const uint8_t *signer = dnssec_key_get_dname(key);

	uint8_t *w = rdata;

	knot_wire_write_u16(w, covered_type);	// type covered
	w += sizeof(uint16_t);
	*w = algorithm;				// algorithm
	w += sizeof(uint8_t);
	*w = owner_labels;			// labels
	w += sizeof(uint8_t);
	knot_wire_write_u32(w, owner_ttl);	// original TTL
	w += sizeof(uint32_t);
	knot_wire_write_u32(w, sig_expires);	// signature expiration
	w += sizeof(uint32_t);
	knot_wire_write_u32(w, sig_incepted);	// signature inception
	w += sizeof(uint32_t);
	knot_wire_write_u16(w, keytag);		// key fingerprint
	w += sizeof(uint16_t);

	assert(w == rdata + RRSIG_RDATA_SIGNER_OFFSET);
	memcpy(w, signer, knot_dname_size(signer)); // signer

	return KNOT_EOK;
}

/*- Computation of signatures ------------------------------------------------*/

/*!
 * \brief Add RRSIG RDATA without signature to signing context.
 *
 * Requires signer name in RDATA in canonical form.
 *
 * \param ctx   Signing context.
 * \param rdata Pointer to RRSIG RDATA.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int sign_ctx_add_self(dnssec_sign_ctx_t *ctx, const uint8_t *rdata)
{
	assert(ctx);
	assert(rdata);

	const uint8_t *signer = rdata + RRSIG_RDATA_SIGNER_OFFSET;

	dnssec_binary_t header = { 0 };
	header.data = (uint8_t *)rdata;
	header.size = RRSIG_RDATA_SIGNER_OFFSET + knot_dname_size(signer);

	int result = dnssec_sign_add(ctx, &header);

	return (result == DNSSEC_EOK ? KNOT_EOK : KNOT_DNSSEC_ESIGN);
}

/*!
 * \brief Add covered RRs to signing context.
 *
 * Requires all DNAMEs in canonical form and all RRs ordered canonically.
 *
 * \param ctx      Signing context.
 * \param covered  Covered RRs.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int sign_ctx_add_records(dnssec_sign_ctx_t *ctx, const knot_rrset_t *covered)
{
	// huge block of rrsets can be optionally created
	uint8_t *rrwf = malloc(MAX_RR_WIREFORMAT_SIZE);
	if (!rrwf) {
		return KNOT_ENOMEM;
	}

	int result = KNOT_EOK;

	size_t rr_wire_size = 0;
	uint16_t rr_count = 0;
	result = knot_rrset_to_wire(covered, rrwf, &rr_wire_size,
	                            MAX_RR_WIREFORMAT_SIZE, &rr_count, NULL);
	if (result != KNOT_EOK || rr_count != covered->rrs.rr_count) {
		free(rrwf);
		return result;
	}

	dnssec_binary_t rrset_wire = { 0 };
	rrset_wire.size = rr_wire_size;
	rrset_wire.data = rrwf;
	result = dnssec_sign_add(ctx, &rrset_wire);

	free(rrwf);

	return (result == DNSSEC_EOK ? KNOT_EOK : KNOT_DNSSEC_ESIGN);
}

/*!
 * \brief Add all data covered by signature into signing context.
 *
 * RFC 4034: The signature covers RRSIG RDATA field (excluding the signature)
 * and all matching RR records, which are ordered canonically.
 *
 * Requires all DNAMEs in canonical form and all RRs ordered canonically.
 *
 * \param ctx          Signing context.
 * \param rrsig_rdata  RRSIG RDATA with populated fields except signature.
 * \param covered      Covered RRs.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int sign_ctx_add_data(dnssec_sign_ctx_t *ctx,
                             const uint8_t *rrsig_rdata,
                             const knot_rrset_t *covered)
{
	int result = sign_ctx_add_self(ctx, rrsig_rdata);
	if (result != KNOT_EOK) {
		return result;
	}

	return sign_ctx_add_records(ctx, covered);
}

/*!
 * \brief Create RRSIG RDATA.
 *
 * \param[in]  rrsigs        RR set with RRSIGS.
 * \param[in]  ctx           DNSSEC signing context.
 * \param[in]  covered       RR covered by the signature.
 * \param[in]  key           Key used for signing.
 * \param[in]  sig_incepted  Timestamp of signature inception.
 * \param[in]  sig_expires   Timestamp of signature expiration.
 *
 * \return Error code, KNOT_EOK if succesful.
 */
static int rrsigs_create_rdata(knot_rrset_t *rrsigs, dnssec_sign_ctx_t *ctx,
			       const knot_rrset_t *covered,
			       const dnssec_key_t *key,
			       uint32_t sig_incepted, uint32_t sig_expires)
{
	assert(rrsigs);
	assert(rrsigs->type == KNOT_RRTYPE_RRSIG);
	assert(!knot_rrset_empty(covered));
	assert(key);

	size_t header_size = knot_rrsig_rdata_size(key);
	assert(header_size != 0);

	uint8_t owner_labels = knot_dname_labels(covered->owner, NULL);
	if (knot_dname_is_wildcard(covered->owner)) {
		owner_labels -= 1;
	}

	uint8_t header[header_size];
	const knot_rdata_t *covered_data = knot_rdataset_at(&covered->rrs, 0);
	int res = knot_rrsig_write_rdata(header, key, covered->type, owner_labels,
	                                 knot_rdata_ttl(covered_data),
	                                 sig_incepted, sig_expires);
	assert(res == KNOT_EOK);

	res = dnssec_sign_init(ctx);
	if (res != KNOT_EOK) {
		return res;
	}

	res = sign_ctx_add_data(ctx, header, covered);
	if (res != KNOT_EOK) {
		return res;
	}

	dnssec_binary_t signature = { 0 };
	res = dnssec_sign_write(ctx, &signature);
	if (res != DNSSEC_EOK) {
		return KNOT_DNSSEC_ESIGN;
	}
	assert(signature.size > 0);

	size_t rrsig_size = header_size + signature.size;
	uint8_t rrsig[rrsig_size];
	memcpy(rrsig, header, header_size);
	memcpy(rrsig + header_size, signature.data, signature.size);

	dnssec_binary_free(&signature);

	return knot_rrset_add_rdata(rrsigs, rrsig, rrsig_size,
	                            knot_rdata_ttl(covered_data), NULL);
}

/*!
 * \brief Create RRSIG RR for given RR set.
 */
int knot_sign_rrset(knot_rrset_t *rrsigs, const knot_rrset_t *covered,
                    const dnssec_key_t *key, dnssec_sign_ctx_t *sign_ctx,
                    const knot_dnssec_policy_t *policy)
{
	if (knot_rrset_empty(covered) || !key || !sign_ctx || !policy ||
	    rrsigs->type != KNOT_RRTYPE_RRSIG ||
	    (knot_dname_cmp(rrsigs->owner, covered->owner) != 0)
	) {
		return KNOT_EINVAL;
	}

	uint32_t sig_incept = policy->now;
	uint32_t sig_expire = sig_incept + policy->sign_lifetime;

	return rrsigs_create_rdata(rrsigs, sign_ctx, covered, key, sig_incept,
	                           sig_expire);
}

int knot_synth_rrsig(uint16_t type, const knot_rdataset_t *rrsig_rrs,
                     knot_rdataset_t *out_sig, mm_ctx_t *mm)
{
	if (rrsig_rrs == NULL) {
		return KNOT_ENOENT;
	}

	if (out_sig == NULL || out_sig->rr_count > 0) {
		return KNOT_EINVAL;
	}

	for (int i = 0; i < rrsig_rrs->rr_count; ++i) {
		if (type == knot_rrsig_type_covered(rrsig_rrs, i)) {
			const knot_rdata_t *rr_to_copy = knot_rdataset_at(rrsig_rrs, i);
			int ret = knot_rdataset_add(out_sig, rr_to_copy, mm);
			if (ret != KNOT_EOK) {
				knot_rdataset_clear(out_sig, mm);
				return ret;
			}
		}
	}

	return out_sig->rr_count > 0 ? KNOT_EOK : KNOT_ENOENT;
}

/*- Verification of signatures -----------------------------------------------*/

/*!
 * \brief Check if the signature is expired.
 *
 * \param rrsigs  RR set with RRSIGs.
 * \param pos     Number of RR in the RR set.
 * \param policy  DNSSEC policy.
 *
 * \return Signature is expired or should be replaced soon.
 */
static bool is_expired_signature(const knot_rrset_t *rrsigs, size_t pos,
                                 const knot_dnssec_policy_t *policy)
{
	assert(!knot_rrset_empty(rrsigs));
	assert(rrsigs->type == KNOT_RRTYPE_RRSIG);
	assert(policy);

	uint32_t expiration = knot_rrsig_sig_expiration(&rrsigs->rrs, pos);

	return (expiration <= policy->refresh_before);
}

/*!
 * \brief Check if RRSIG signature is valid.
 */
int knot_is_valid_signature(const knot_rrset_t *covered,
                            const knot_rrset_t *rrsigs, size_t pos,
                            const dnssec_key_t *key, dnssec_sign_ctx_t *ctx,
                            const knot_dnssec_policy_t *policy)
{
	if (knot_rrset_empty(covered) ||
	    knot_rrset_empty(rrsigs) || !key || !ctx || !policy) {
		return KNOT_EINVAL;
	}

	if (is_expired_signature(rrsigs, pos, policy)) {
		return KNOT_DNSSEC_EINVALID_SIGNATURE;
	}

	// identify fields in the signature being validated

	const knot_rdata_t *rr_data = knot_rdataset_at(&rrsigs->rrs, pos);
	uint8_t *rdata = knot_rdata_data(rr_data);
	if (!rdata) {
		return KNOT_EINVAL;
	}

	dnssec_binary_t signature = { 0 };
	knot_rrsig_signature(&rrsigs->rrs, pos, &signature.data, &signature.size);
	if (!signature.data) {
		return KNOT_EINVAL;
	}

	// perform the validation

	int result = dnssec_sign_init(ctx);
	if (result != KNOT_EOK) {
		return result;
	}

	result = sign_ctx_add_data(ctx, rdata, covered);
	if (result != KNOT_EOK) {
		return result;
	}

	result = dnssec_sign_verify(ctx, &signature);
	switch (result) {
	case DNSSEC_EOK:
		return KNOT_EOK;
	case DNSSEC_INVALID_SIGNATURE:
		return KNOT_DNSSEC_EINVALID_SIGNATURE;
	default:
		return KNOT_ERROR;
	}
}
