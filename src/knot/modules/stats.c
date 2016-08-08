/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "contrib/mempattern.h"
#include "libknot/libknot.h"
#include "knot/common/stats.h"
#include "knot/modules/stats.h"
#include "knot/nameserver/axfr.h"
#include "knot/nameserver/process_query.h"

const yp_item_t scheme_mod_stats[] = {
	{ C_ID,      YP_TSTR, YP_VNONE },
	{ C_COMMENT, YP_TSTR, YP_VNONE },
	{ NULL }
};

typedef enum {
	CTR_UDP4,
	CTR_UDP6,
	CTR_TCP4,
	CTR_TCP6,
	CTR_QUERY_BYTES,
	CTR_RESPONSE_BYTES,
	CTR_DDNS_BYTES,
	CTR_XFR_BYTES,
	CTR_OPCODES,
	CTR_RCODES,
	CTR_QUERY_SIZES,
	CTR_RESPONSE_SIZES,
	CTR_QTYPES,
} ctr_idx_t;

typedef struct {
	const char *name;
	uint32_t count;
	mod_idx_to_str_f fcn;
} ctr_desc_t;

#define UNKNOWN		"Unknown"
#define BUCKET_SIZE	16
#define RCODE_NODATA	11 // Unassigned code internally used for NODATA.
#define RCODE_BADSIG	12 // Unassigned code internally used for BADSIG.

static char *opcode_to_str(uint32_t idx, uint32_t count)
{
	switch (idx) {
	case KNOT_OPCODE_QUERY:  return strdup("QUERY");
	case KNOT_OPCODE_IQUERY: return strdup("AXFR"); // Redefined.
	case KNOT_OPCODE_STATUS: return strdup("IXFR"); // Redefined.
	case KNOT_OPCODE_NOTIFY: return strdup("NOTIFY");
	case KNOT_OPCODE_UPDATE: return strdup("UPDATE");
	default:                 return strdup(UNKNOWN);
	}
}

static char *rcode_to_str(uint32_t idx, uint32_t count)
{
	// Check for special NODATA.
	if (idx == RCODE_NODATA) {
		return strdup("NODATA");
	}

	// Check for conflicting BADSIG.
	const knot_lookup_t *rcode = NULL;
	if (idx == RCODE_BADSIG) {
		rcode = knot_lookup_by_id(knot_tsig_rcode_names, KNOT_RCODE_BADSIG);
	} else {
		rcode = knot_lookup_by_id(knot_rcode_names, idx);
	}

	if (rcode != NULL) {
		return strdup(rcode->name);
	} else {
		return strdup(UNKNOWN);
	}
}

static char *qtype_to_str(uint32_t idx, uint32_t count)
{
	char str[32];
	if (idx >= count - 1 || knot_rrtype_to_string(idx, str, sizeof(str)) <= 0) {
		return strdup(UNKNOWN);
	} else {
		return strdup(str);
	}
}

static char *size_to_str(uint32_t idx, uint32_t count)
{
	char str[16];

	int ret;
	if (idx < count - 1) {
		ret = snprintf(str, sizeof(str), "%u-%u", idx * BUCKET_SIZE,
		               (idx + 1) * BUCKET_SIZE - 1);
	} else {
		ret = snprintf(str, sizeof(str), "%u-65535", idx * BUCKET_SIZE);
	}

	if (ret <= 0 || (size_t)ret >= sizeof(str)) {
		return strdup(UNKNOWN);
	} else {
		return strdup(str);
	}
}

static const ctr_desc_t ctr_descs[] = {
	[CTR_UDP4]           = { "udp4", 1 },
	[CTR_UDP6]           = { "udp6", 1 },
	[CTR_TCP4]           = { "tcp4", 1 },
	[CTR_TCP6]           = { "tcp6", 1 },
	[CTR_QUERY_BYTES]    = { "query-bytes", 1 },
	[CTR_RESPONSE_BYTES] = { "response-bytes", 1 },
	[CTR_DDNS_BYTES]     = { "ddns-bytes", 1 },
	[CTR_XFR_BYTES]      = { "xfr-bytes", 1 },
	[CTR_OPCODES]        = { "opcode", KNOT_OPCODE_UPDATE + 2, opcode_to_str },
	[CTR_RCODES]         = { "rcode", KNOT_RCODE_BADCOOKIE + 2, rcode_to_str },
	[CTR_QUERY_SIZES]    = { "query-size", 288 / BUCKET_SIZE + 1, size_to_str },
	[CTR_RESPONSE_SIZES] = { "response-size", 4096 / BUCKET_SIZE + 1, size_to_str },
	[CTR_QTYPES]         = { "qtype", KNOT_RRTYPE_CAA + 2, qtype_to_str },
	{ NULL }
};

static int count(int state, knot_pkt_t *pkt, struct query_data *qdata, void *ctx)
{
	if (pkt == NULL || qdata == NULL || ctx == NULL) {
		return KNOT_STATE_FAIL;
	}

	mod_ctr_t *stats = ctx;

	unsigned xfr_packets = 0;
	uint16_t opcode = KNOT_OPCODE_UPDATE + 1; // Unknown.
	bool count_query = true, count_reply = true;

	switch (qdata->packet_type) {
	case KNOT_QUERY_NORMAL:
		opcode = KNOT_OPCODE_QUERY;
		// Only normal query qtypes are interesting.
		mod_ctrs_incr(stats, CTR_QTYPES, knot_pkt_qtype(qdata->query), 1);
		break;
	case KNOT_QUERY_AXFR:
		opcode = KNOT_OPCODE_IQUERY; // Redefined.
		mod_ctr_incr(stats, CTR_XFR_BYTES, pkt->size);
		if (qdata->ext != NULL) {
			xfr_packets = ((struct xfr_proc *)qdata->ext)->npkts;
		}
		count_reply = false;
		break;
	case KNOT_QUERY_IXFR:
		opcode = KNOT_OPCODE_STATUS; // Redefined.
		mod_ctr_incr(stats, CTR_XFR_BYTES, pkt->size);
		if (qdata->ext != NULL) {
			xfr_packets = ((struct xfr_proc *)qdata->ext)->npkts;
		}
		count_reply = false;
		break;
	case KNOT_QUERY_NOTIFY:
		opcode = KNOT_OPCODE_NOTIFY;
		break;
	case KNOT_QUERY_UPDATE:
		opcode = KNOT_OPCODE_UPDATE;
		mod_ctr_incr(stats, CTR_DDNS_BYTES, qdata->query->size);
		count_query = false;
		break;
	default:
		break;
	}

	// Don't count non-first transfer packets.
	if (xfr_packets > 1) {
		return state;
	}

	mod_ctrs_incr(stats, CTR_OPCODES, opcode, 1);

	// Count IP parameters.
	if (qdata->param->remote->ss_family == AF_INET) {
		if (qdata->param->proc_flags & NS_QUERY_LIMIT_SIZE) {
			mod_ctr_incr(stats, CTR_UDP4, 1);
		} else {
			mod_ctr_incr(stats, CTR_TCP4, 1);
		}
	} else {
		if (qdata->param->proc_flags & NS_QUERY_LIMIT_SIZE) {
			mod_ctr_incr(stats, CTR_UDP6, 1);
		} else {
			mod_ctr_incr(stats, CTR_TCP6, 1);
		}
	}

	// Count message sizes.
	if (count_query) {
		mod_ctr_incr(stats, CTR_QUERY_BYTES, qdata->query->size);
		mod_ctrs_incr(stats, CTR_QUERY_SIZES, qdata->query->size / BUCKET_SIZE, 1);
	}
	if (count_reply) {
		mod_ctr_incr(stats, CTR_RESPONSE_BYTES, pkt->size);
		mod_ctrs_incr(stats, CTR_RESPONSE_SIZES, pkt->size / BUCKET_SIZE, 1);
	}

	// Count RCODE.
	uint16_t rcode = qdata->rcode;
	if (qdata->rcode_tsig != KNOT_RCODE_NOERROR) {
		rcode = qdata->rcode_tsig;
	}
	// Check for NODATA reply (RFC 2308, Section 2.2).
	if (rcode == KNOT_RCODE_NOERROR && opcode == KNOT_OPCODE_QUERY &&
	    knot_wire_get_ancount(pkt->wire) == 0 &&
	    (knot_wire_get_nscount(pkt->wire) == 0 ||
	     knot_pkt_rr(knot_pkt_section(pkt, KNOT_AUTHORITY), 0)->type == KNOT_RRTYPE_SOA)) {
		mod_ctrs_incr(stats, CTR_RCODES, RCODE_NODATA, 1);
	// Check for conflicting code 16.
	} else if (qdata->rcode_tsig == KNOT_RCODE_BADSIG) {
		mod_ctrs_incr(stats, CTR_RCODES, RCODE_BADSIG, 1);
	} else {
		mod_ctrs_incr(stats, CTR_RCODES, rcode, 1);
	}

	return state;
}

int stats_load(struct query_plan *plan, struct query_module *self,
               const knot_dname_t *zone)
{
	if (plan == NULL || self == NULL) {
		return KNOT_EINVAL;
	}

	for (const ctr_desc_t *desc = ctr_descs; desc->name != NULL; desc++) {
		int ret = mod_stats_add(self, desc->name, desc->count, desc->fcn);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	self->ctx = self->stats;

	return query_plan_step(plan, QPLAN_END, count, self->ctx);
}

int stats_unload(struct query_module *self)
{
	if (self == NULL) {
		return KNOT_EINVAL;
	}

	mod_stats_free(self);

	return KNOT_EOK;
}
