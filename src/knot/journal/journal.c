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

#include <assert.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdarg.h>
#include <string.h>

#include "knot/common/log.h"
#include "knot/journal/journal.h"
#include "knot/journal/serialization.h"
#include "knot/zone/serial.h"
#include "libknot/libknot.h"
#include "contrib/endian.h"
#include "contrib/files.h"

/*! \brief journal database name. */
#define DATA_DB_NAME "data"
/*! \brief Minimum journal size. */
#define FSLIMIT_MIN (1 * 1024 * 1024)
/*! \brief Changeset chunk size. */
#define CHUNK_MAX (60 * 1024)
/*! \brief How many deletes per transaction do we perform. */
#define SYNC_BATCH 100
/*! \brief Journal version in BCD code. 10 means "1.0" */
const uint32_t JOURNAL_VERSION = 10;

/*! \brief Parameters managing minimum DB free space
 *
 * DB_KEEP_FREE how much space keep free in normal circumstances
 * DB_KEEP_MERGED ... if the merged changeset is present
 * DB_KEEP_FORMERGE ... if merging is allowed but not yet present
 * DB_DISPOSE_RATIO ... when freeing, delete DB_DISPOSE_RATIO times more than minimum needed (to prevent deleting too often) <-- anyway when freeing the freed amount is a very rough estimate !!
 *
 * TODO: make those be configurable in conf() ?
 */
#define DB_KEEP_FREE 0.5f
#define DB_KEEP_MERGED 0.44f
#define DB_KEEP_FORMERGE 0.72f
#define DB_DISPOSE_RATIO 3
#define DB_MAX_INSERT_TXN 0.05f

enum {
	LAST_FLUSHED_VALID = 1 << 0, /* "last flush is valid" flag. */
	SERIAL_TO_VALID    = 1 << 1, /* "last serial_to is valid" flag. */
	MERGED_SERIAL_VALID= 1 << 2, /* "serial_from" of merged changeset */
	DIRTY_SERIAL_VALID = 1 << 3, /* "dirty_serial" is present in the DB */
};

typedef struct journal_metadata {
	uint32_t first_serial;		// serial_from of the first changeset
	uint32_t last_serial;		// serial_from of the last changeset
	uint32_t last_serial_to;	// serial_to of the last changeset
	uint32_t last_flushed;		// serial_from of the last flushed (or merged) chengeset
	uint32_t merged_serial;		// "serial_from" of merged changeset
	uint32_t dirty_serial;		// serial_from of an incompletely inserted changeset which shall be deleted
	uint32_t flags;			// LAST_FLUSHED_VALID, SERIAL_TO_VALID, MERGED_SERIAL_VALID
} journal_metadata_t;

#define is_last_flushed(metadata, what) (((metadata).flags & LAST_FLUSHED_VALID) && (metadata).last_flushed == (what))
#define is_flushed(metadata) (is_last_flushed((metadata), (metadata).last_serial) || !((metadata).flags & SERIAL_TO_VALID))
#define metadata_flag(j, fl) ((j)->metadata.flags & (fl))

static void copy_metadata(journal_metadata_t *a, journal_metadata_t *b)
{
	memcpy(a, b, sizeof(*a));
}

struct journal {
	knot_db_t *db;                 /*!< DB handler. */
	const knot_db_api_t *db_api;   /*!< DB API backend. */
	char *path;                    /*!< Path to journal file. */
	size_t fslimit;                /*!< File size limit. */
	const knot_dname_t *zone_name; /*!< Associated zone name. */
	journal_metadata_t metadata;   /*!< Metadata. */
};

typedef struct {
	journal_t * j;
	knot_db_txn_t * txn;
	int ret;
	int active; // private
	journal_metadata_t shadow_metadata;
} txn_ctx_t;

// FIXME all public functions ... proper EINVAL for NULL params etc; all static functions ... proper asserts
// FIXME walk through all the functions reusing txn and check the error states .. aborting txn is ok in case of error

/*
 * ***************************** PART 0 *******************************
 *
 *  Journal "business logic"
 *
 * ********************************************************************
 */

static int flush_allowed(journal_t * j) {
	conf_val_t val = conf_zone_get(conf(), C_ZONEFILE_SYNC, j->zone_name);
	if (val.item == NULL || conf_int(&val) >= 0) return 1; // val->item == NULL  --->  default behaviour, ie standard flush, no merge.
	return 0;
}

static int merge_allowed(journal_t * j) {
	return !flush_allowed(j); // TODO think of other behaviour, e.g. setting
}

static float get_used_space(journal_t * j)
{
	float x = knot_db_lmdb_get_usage(j->db);
	return x;
}

static void check_free_space(journal_t * j, size_t * request_free, size_t * request_free_min)
{
	float occupied = get_used_space(j);
	float allowed_occupied = 1.0f - DB_KEEP_FREE;
	if (metadata_flag(j, MERGED_SERIAL_VALID)) {
		allowed_occupied = 1.0f - DB_KEEP_MERGED;
	}
	else if (merge_allowed(j)) allowed_occupied = 1.0f - DB_KEEP_FORMERGE;

	if (occupied > allowed_occupied) {
		*request_free_min = (size_t) ((occupied - allowed_occupied) * j->fslimit);
	}
	else {
		*request_free_min = 0;
	}
	*request_free = DB_DISPOSE_RATIO * (*request_free_min);
}

static int merge_journal(journal_t * j, txn_ctx_t *_txn); // from PART VIII
static int delete_merged_changeset(journal_t * j, txn_ctx_t *t);

/* Please take care what this function does and mind the caller context. The EBUSY code is usually not an error, but correct */
static int try_flush(journal_t * j, txn_ctx_t * txn)
{
	journal_metadata_t * relevant_metadata = &j->metadata;
	if (txn != NULL) relevant_metadata = &txn->shadow_metadata;

	if (is_flushed(*relevant_metadata)) {
		if ((relevant_metadata->flags & MERGED_SERIAL_VALID) && !merge_allowed(j)) {
			// this is the situation that merge was present, we flushed the journal to zonefile via zone, so the merged changeset is actually flushed and not needed anymore
			// this cannot happen if merge_allowed() doesn't change suddenly
			delete_merged_changeset(j, txn);
		}
		return KNOT_EOK;
	}
	if (merge_allowed(j)) return merge_journal(j, txn);

	return KNOT_EBUSY; // returns EBUSY to caller from zone.c - it flushes the journal for us and tries again
}

/*! \brief Just updates the metadata after journal was actually flushed */
int journal_flush(journal_t *j)
{
	if (j == NULL) return KNOT_EINVAL;

	if (metadata_flag(j, SERIAL_TO_VALID)) {
		j->metadata.last_flushed = j->metadata.last_serial;
		j->metadata.flags |= LAST_FLUSHED_VALID;
	}

	return KNOT_EOK;
}

/*
 * ***************************** PART I *******************************
 *
 *  Transaction helper functions
 *
 * ********************************************************************
 */



/*! \brief Creates local-scoped handle for use with following functions
 * Please use just once in a function/block */
#define local_txn_ctx(txn_ctx_name, pjournal) knot_db_txn_t local_txn_ctx_txn; \
					       txn_ctx_t local_txn_ctx_ctx = { .j = (pjournal), .txn = &local_txn_ctx_txn, .ret = KNOT_EOK, .active = 0 }, \
						         * txn_ctx_name = &local_txn_ctx_ctx

/*! \brief Inits a DB transaction with flags */
static void txn_beg(txn_ctx_t * t, int flags)
{
	if (t->active) {
	    t->ret = KNOT_EINVAL;
	    return;
	}
	t->ret = t->j->db_api->txn_begin(t->j->db, t->txn, (unsigned) flags);
	if (t->ret != KNOT_EOK) return;
	t->active = 1;
	copy_metadata(&t->shadow_metadata, &t->j->metadata);
}

static void txn_abort(txn_ctx_t * t) // doesn't touch t->ret
{
	if (t->active) t->j->db_api->txn_abort(t->txn);
	t->active = 0;
}

/*! \brief those check if txn failed in the past and return the caller function in case */
#define txn_check(t, x) if ((t)->ret != KNOT_EOK) return (x)
#define txn_check_void(t) if ((t)->ret != KNOT_EOK) return
#define txn_check_ret(t) if ((t)->ret != KNOT_EOK) txn_check((t), (t)->ret)
#define txn_inactive_inval(t) if (!(t)->active && (t)->ret == KNOT_EOK) (t)->ret = KNOT_ERROR

static int update_metadata(journal_t * j, txn_ctx_t * txn, const char * md_key, uint32_t new_val); // from PART III

#define update_metadata_txn(t, item) if ((t)->shadow_metadata.item != (t)->j->metadata.item) update_metadata((t)->j, (t), #item, (t)->shadow_metadata.item)

/*! \brief Updates both stored (int the DB) metadata and j->metadata according to shadow_metadata and commits the txn */
static void txn_commit(txn_ctx_t * t)
{
	txn_inactive_inval(t);
	txn_check_void(t);

	update_metadata_txn(t, first_serial);
	update_metadata_txn(t, last_serial);
	update_metadata_txn(t, last_serial_to);
	update_metadata_txn(t, last_flushed);
	update_metadata_txn(t, merged_serial);
	update_metadata_txn(t, dirty_serial);
	update_metadata_txn(t, flags);

	t->ret = t->j->db_api->txn_commit(t->txn);
	if (t->ret != KNOT_EOK) {
	    txn_abort(t);
	}
	t->active = 0;
	copy_metadata(&t->j->metadata, &t->shadow_metadata);
}

#undef update_metadata_txn

static size_t txn_db_count(txn_ctx_t * t) // no check for errors
{
	return (size_t) t->j->db_api->count(t->txn);
}

/*! \brief search for key and return in val. If not found, report no error, just return 0 */
static int txn_find(txn_ctx_t * t, knot_db_val_t * key, knot_db_val_t * val, int flags)
{
	txn_inactive_inval(t);
	txn_check(t, 0);
	t->ret = t->j->db_api->find(t->txn, key, val, (unsigned) flags);
	if (t->ret == KNOT_ENOENT) {
	    t->ret = KNOT_EOK;
	    return 0;
	}
	if (t->ret != KNOT_EOK) {
	    txn_abort(t);
	    return 0;
	}
	return 1;
}

/*! \brief Search for key and return in val. If not found, trigger error */
static void txn_find_force(txn_ctx_t * t, knot_db_val_t * key, knot_db_val_t * val, int flags)
{
	txn_inactive_inval(t);
	txn_check_void(t);
	t->ret = t->j->db_api->find(t->txn, key, val, (unsigned) flags);
	if (t->ret != KNOT_EOK) {
	    txn_abort(t);
	}
}

static void txn_insert(txn_ctx_t * t, knot_db_val_t * key, knot_db_val_t * val, int flags)
{
	txn_inactive_inval(t);
	txn_check_void(t);
	t->ret = t->j->db_api->insert(t->txn, key, val, (unsigned) flags);
	if (t->ret != KNOT_EOK) {
	    txn_abort(t);
	}
}

static void txn_del(txn_ctx_t * t, knot_db_val_t * key)
{
	txn_inactive_inval(t);
	txn_check_void(t);
	t->ret = t->j->db_api->del(t->txn, key);
	if (t->ret != KNOT_EOK) {
	    txn_abort(t);
	}
}

/*! \brief If existing_ctx exists, uses it with new name, else creates new-named ctx like usual
 * Please unreuse it always at the end of scope, and consider txn_check_ret afterwards */
#define reuse_txn_ctx(txn_ctx_name, pjournal, existing_ctx, existing_flags) local_txn_ctx(txn_ctx_name, pjournal); do { \
                                                                            if (existing_ctx == NULL) txn_beg(txn_ctx_name, existing_flags); \
                                                                            else txn_ctx_name = existing_ctx; } while (0)

#define unreuse_txn_ctx(txn_ctx_name, existing_ctx) if (existing_ctx == NULL) txn_commit(txn_ctx_name)

/*
 * ***************************** PART II ******************************
 *
 *  DB keys and chunk headers
 *
 * ********************************************************************
 */

/*! \brief represents the keys for the DB */
typedef struct {
	uint32_t serial; // changeset's serial no
	uint32_t chunk;  // chunk index (0 for firs chunk of this changeset)
} journal_key_t;

/*! \brief some "metadata" inserted to the beginning of each chunk */
typedef struct {
	uint32_t serial_to;       // changeset's SOA-to serial
	uint32_t chunk_count;     // # of changeset's chunks
	uint32_t this_chunk_size;
} journal_header_t;

/*! \brief fill *to (aka knot_db_val_t * to) with DB key properties
 * these are macros define local variable make_key_local to save some allocation */
#define make_key(from, to) \
	journal_key_t make_key_local; \
	make_key_local.serial = htobe32((from)->serial); \
	make_key_local.chunk = htobe32((from)->chunk); \
	(to)->data = &make_key_local; \
	(to)->len = sizeof(make_key_local)

#define make_key2(_serial, _chunk, to) \
	journal_key_t make_key_local; \
	make_key_local.serial = htobe32((_serial)); \
	make_key_local.chunk = htobe32((_chunk)); \
	(to)->data = &make_key_local; \
	(to)->len = sizeof(make_key_local)

/*! \brief decode the key's properties */
static void unmake_key(const knot_db_val_t * from, journal_key_t * to)
{
	assert(from->len == sizeof(journal_key_t));
	to->serial = be32toh(((journal_key_t *) from->data)->serial);
	to->chunk = be32toh(((journal_key_t *) from->data)->chunk);
}

static int keys_equal(const knot_db_val_t * key1, const knot_db_val_t * key2)
{
	if (key1->len != key2->len) return 0;
	if (key1->len != sizeof(journal_key_t)) return (memcmp(key1->data, key2->data, key1->len) == 0);

	journal_key_t a, b;
	unmake_key(key1, &a);
	unmake_key(key2, &b);
	return ((a.serial == b.serial) && (a.chunk == b.chunk));
}

static void make_header(knot_db_val_t * to, uint32_t serial_to, size_t chunk_size, int chunk_count)
{
	assert(to->len >= sizeof(journal_header_t));
	assert(chunk_count > 0);
	assert(chunk_size <= UINT32_MAX);

	journal_header_t h;
	h.serial_to = htobe32(serial_to);
	h.chunk_count = htobe32((uint32_t) chunk_count);
	h.this_chunk_size = htobe32((uint32_t) chunk_size);
	memcpy(to->data, &h, sizeof(h));
}

/*! \brief read properties from chunk header "from". All the output params are optional */
static void unmake_header(const knot_db_val_t * from, uint32_t * serial_to, size_t * chunk_size, int * chunk_count, size_t * header_size)
{
	assert(from->len >= sizeof(journal_header_t));
	journal_header_t * h = (journal_header_t *) from->data;

	if (serial_to != NULL) *serial_to = be32toh(h->serial_to);
	if (chunk_size != NULL) *chunk_size = be32toh(h->this_chunk_size);
	assert(be32toh(h->chunk_count) <= INT_MAX);
	if (chunk_count != NULL) *chunk_count = (int) be32toh(h->chunk_count);
	if (header_size != NULL) *header_size = sizeof(*h);
}

/*
 * ***************************** PART III *****************************
 *
 *  Metadata preserving in DB
 *
 * ********************************************************************
 */

static uint32_t first_digit(uint32_t of)
{
	while (of > 9) of /= 10;
	return of;
}

/*! \brief insert single metadata tey/val into DB */
static int update_metadata(journal_t * j, txn_ctx_t * txn, const char * md_key, uint32_t new_val)
{
	reuse_txn_ctx(t, j, txn, 0);
	uint32_t new_val_be = htobe32(new_val);
	knot_db_val_t key = { .len = strlen(md_key)+1, .data = (void *) md_key },
	              val = { .len = sizeof(uint32_t), .data = &new_val_be };
	txn_insert(t, &key, &val, 0);
	unreuse_txn_ctx(t, txn);
	txn_check_ret(t);
	return KNOT_EOK;
}

// TODO this function was originally intended as the opponent of load_metadata() to be called when closing DB
// now it's called only at the beginning and is useful just for storing version and zone_name
// consider removing this function ...
static int store_metadata(journal_t * j, txn_ctx_t * txn)
{
	reuse_txn_ctx(t, j, txn, 0);

	knot_db_val_t key, val;

	uint32_t version = JOURNAL_VERSION;

	update_metadata(j, t, "version",       version);
	update_metadata(j, t, "first_serial",  j->metadata.first_serial);
	update_metadata(j, t, "last_serial",   j->metadata.last_serial);
	update_metadata(j, t, "last_serial_to",j->metadata.last_serial_to);
	update_metadata(j, t, "last_flushed",  j->metadata.last_flushed);
	update_metadata(j, t, "merged_serial", j->metadata.merged_serial);
	update_metadata(j, t, "dirty_serial",  j->metadata.merged_serial);
	update_metadata(j, t, "flags",         j->metadata.flags);

	key.len = strlen("zone_name") + 1;
	key.data = (void *) "zone_name";
	val.len = strlen((const char *) j->zone_name) + 1;
	val.data = (void *) j->zone_name;
	txn_insert(t, &key, &val, 0);

	unreuse_txn_ctx(t, txn);
	txn_check_ret(t);
	return KNOT_EOK;
}

/*! \brief Load from meta_db incl version check and endian converison. */
static int load_metadata(journal_t * j)
{
	local_txn_ctx(txn, j);
	txn_beg(txn, 0);

	knot_db_val_t key, val;

	#define load_metadata_one(keystr, storeto) { \
		key.len = strlen(keystr) + 1; \
		key.data = (void * ) (keystr); \
		txn_find_force(txn, &key, &val, 0); \
		txn_check_ret(txn); \
		if (val.len != sizeof(storeto)) { \
			txn_abort(txn); \
			return KNOT_EMALF; \
		} \
		if (sizeof(storeto) == sizeof(uint32_t)) { \
			storeto = be32toh(*(uint32_t *) val.data); \
		} \
		else { \
			memcpy(&storeto, val.data, sizeof(storeto)); \
		} \
	}

	uint32_t version = 0;

	if (txn_db_count(txn) == 0) {
		// completely clean new journal, write version and zone_name
		assert(j->metadata.flags == 0);
		store_metadata(j, txn);
		txn_commit(txn);
		txn_check_ret(txn);
		return KNOT_EOK;
	}

	// version is stored in BCD code: 10 means "1.0"
	key.len = strlen("version") + 1;
	key.data = (void *) "version";
	if (!txn_find(txn, &key, &val, 0)) {
		txn_abort(txn);
		return txn->ret; // KNOT_EOK if not found instead of KNOT_ENOENT !
	}
	if (val.len == sizeof(version)) version = be32toh(*(uint32_t *) val.data); // else first-digit check also fails

	if (first_digit(version) != first_digit(JOURNAL_VERSION)) {
		txn_abort(txn);
		return KNOT_ENOTSUP; // TODO another option how to proceed is overwriting journal with older version and start with clear one, like below:
		/*
		log_zone_error(j->zone_name, "different journal version detected, overwriting");
		version = htobe32(JOURNAL_VERSION);
		key.len = strlen("version");
		key.data = "version";
		val.len = sizeof(version);
		val.data = &version;
		txn_beg_jdb(txn, meta_db, 0);
		txn_insert(txn, &key, &val, 0);
		txn_commit(txn);
		txn_check_ret(txn);
		txn_beg_jdb(txn, meta_db, KNOT_DB_RDONLY);
		// no return here (or better yes ?)
		*/
	}

	if (version != JOURNAL_VERSION) {
		// FIXME warning
	}

	load_metadata_one("first_serial",   j->metadata.first_serial);
	load_metadata_one("last_serial",    j->metadata.last_serial);
	load_metadata_one("last_serial_to", j->metadata.last_serial_to);
	load_metadata_one("last_flushed",   j->metadata.last_flushed);
	load_metadata_one("merged_serial",  j->metadata.merged_serial);
	load_metadata_one("dirty_serial",  j->metadata.dirty_serial);
	load_metadata_one("flags",          j->metadata.flags);

	txn_commit(txn);

	#undef load_metadata_one

	return KNOT_EOK;
}

int journal_load_zone_name(journal_t * j, const knot_dname_t ** zname)
{
        if (j == NULL || zname == NULL || j->db == NULL) return KNOT_EINVAL;

        local_txn_ctx(txn, j);
        txn_beg(txn, KNOT_DB_RDONLY);

        knot_db_val_t key, val;
        key.len = strlen("zone_name") + 1;
        key.data = (void *) "zone_name";
        txn_find_force(txn, &key, &val, 0);
        txn_check_ret(txn);

        if (knot_dname_cmp(val.data, j->zone_name) == 0) {
                txn_abort(txn);
                *zname = j->zone_name;
                return KNOT_EOK;
        }

        *zname = knot_dname_copy(val.data, NULL); // val.data was stored with ending '\0'
        txn_abort(txn);
        if (*zname == NULL) return KNOT_ENOMEM;

        j->zone_name = *zname;
        return KNOT_ESEMCHECK;
}

void journal_metadata_info(journal_t * j, int * is_empty, uint32_t * serial_from, uint32_t * serial_to)
{
        // NOTE: there is NEVER the situation that only merged changeset would be present and no common changeset in db.

        if (j == NULL || j->db == NULL || !metadata_flag(j, SERIAL_TO_VALID)) {
                *is_empty = 1;
                return;
        }

        *is_empty = 0;
        *serial_from = j->metadata.first_serial;
        *serial_to = j->metadata.last_serial_to;

        if (metadata_flag(j, MERGED_SERIAL_VALID)) {
                *serial_from = j->metadata.merged_serial;
        }
}

/*
 * ***************************** PART IV ******************************
 *
 *  DB record iteration
 *
 * ********************************************************************
 */

enum {
	JOURNAL_ITERATION_CHUNKS,     // call the iteration callback for each chunk read, with just the chunk in ctx->val
	JOURNAL_ITERATION_CHANGESETS  // call the iteration callback after the last chunk of a changeset read, with all its chunks in ctx->val
};

typedef struct {
	txn_ctx_t * txn;	// DB txn not to be touched by callback, just contains journal pointer
	uint32_t serial;	// serial-from of current changeset
	uint32_t serial_to;	// serial-to of current changeset
	const int method;	// JOURNAL_ITERATION_CHUNKS or JOURNAL_ITERATION_CHANGESETS, to be set by the caller of iterate()
	int chunk_index;	// index of current chunk
	int chunk_count;	// # of chunks of current changeset
	knot_db_val_t *val;	// one val if JOURNAL_ITERATION_CHUNKS; chunk_count vals if JOURNAL_ITERATION_CHANGESETS
	knot_db_iter_t *iter;	// DB iteration context, not to be touched by callback
	void * iter_context;	// anything to send to the callback by the caller of iterate(), untouched by iterate()
} iteration_ctx_t;

/*!
 * \brief Move iter to next changeset chunk.
 *
 * Try optimisticly fast move to next DB item. But the changeset can be out of order,
 * so if we don't succeed (different serial or end of DB), we lookup next serial slowly.
 */
static int get_iter_next(journal_t *j, knot_db_iter_t *iter, knot_db_val_t *key)
{
	int ret = KNOT_EOK;
	knot_db_val_t other_key;

	/* Move to the next item */
	iter = j->db_api->iter_next(iter);
	if (iter == NULL) {
		/* Maybe we hit the end, try finding the next one normally */
		iter = j->db_api->iter_seek(iter, key, 0);
		if (iter == NULL) {
			return KNOT_ENOENT;
		}
		return KNOT_EOK;
	}

	/* Get the next item's key */
	ret = j->db_api->iter_key(iter, &other_key);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* If the next item's key is not what we're looking for... */
	if (!keys_equal(key, &other_key)) {
		/* ... look it up normally */
		iter = j->db_api->iter_seek(iter, key, 0);
		if (iter == NULL) {
			return KNOT_ENOENT;
		}
	}

	return KNOT_EOK;
}

typedef int (*iteration_cb_t)(iteration_ctx_t *ctx);

/*! \brief error-checking macro for iterate() function
 * the context here is fixed: journal_t * j, int ret, iteration_ctx_t * ctx, txn_ctx_t * txn, knot_db_val_t * vals */
#define check_ret_iter(err) \
	if (ret != KNOT_EOK || ctx->iter == NULL) { \
		if (ret == KNOT_EOK) ret = (err); \
		if (ctx->iter != NULL) j->db_api->iter_finish(ctx->iter); \
		if (vals != NULL) free(vals); \
		txn_abort(txn); \
		return ret; \
	}

/*!
 * \brief Iterates over all chunks of all changesets from interval [first, last] including
 *
 * The point is to do something with each changeset (ctx->method == JOURNAL_ITERATION_CHANGESETS)
 * or with each chunk (ctx->method == JOURNAL_ITERATION_CHUNKS) instide the callback.
 *
 * \param j Journal
 * \param _txn Optional: open txn to a DB
 * \param cb Callback to be called when a chunk/changeset is read
 * \param ctx Initial values for iteration context, please set up .method and .iter_context
 * \param first, last Interval of changesets to be iterated over
 *
 * \retval KNOT_E*
 */
static int iterate(journal_t * j, txn_ctx_t * _txn, iteration_cb_t cb, iteration_ctx_t *ctx, uint32_t first, uint32_t last)
{
	reuse_txn_ctx(txn, j, _txn, 0);

	ctx->txn = txn; // just for convenience

	int ret = KNOT_EOK;

	knot_db_val_t val, * vals = NULL;

	// Begin iterator
	ctx->iter = j->db_api->iter_begin(txn->txn, KNOT_DB_NOOP);
	check_ret_iter(KNOT_ERROR);

	knot_db_val_t key;
	ctx->serial = first;
	ctx->chunk_index = 0;
	make_key2(ctx->serial, ctx->chunk_index, &key);

	// Move iterator to starting position
	ctx->iter = j->db_api->iter_seek(ctx->iter, &key, 0);
	check_ret_iter(KNOT_ENOENT);

	ctx->val = &val;
	// Iterate through the DB
	while (true) {
		ret = j->db_api->iter_val(ctx->iter, &val);
		check_ret_iter(KNOT_ERROR);

		unmake_header(&val, &ctx->serial_to, NULL, &ctx->chunk_count, NULL);

		if (ctx->method == JOURNAL_ITERATION_CHANGESETS) {
			if (ctx->chunk_index == 0) {
				if (vals != NULL) free(vals);
				vals = malloc(ctx->chunk_count * sizeof(knot_db_val_t));
				if (vals == NULL) ret = KNOT_ENOMEM;
				check_ret_iter(KNOT_ERROR);
				ctx->val = vals;
			}
			memcpy(vals + ctx->chunk_index, &val, sizeof(val));
		}

		if (ctx->method == JOURNAL_ITERATION_CHUNKS) {
			ret = cb(ctx);
			check_ret_iter(KNOT_ERROR);
		}

		if (ctx->chunk_index == ctx->chunk_count - 1) { // hit last chunk of current changeset
			if (ctx->method == JOURNAL_ITERATION_CHANGESETS) {
				ret = cb(ctx);
				check_ret_iter(KNOT_ERROR);
			}

			if (ctx->serial == last) break; // standard loop exit here

			ctx->serial = ctx->serial_to;
			ctx->chunk_index = 0;
		}
		else {
			ctx->chunk_index++;
		}

		make_key2(ctx->serial, ctx->chunk_index, &key);
		ret = get_iter_next(j, ctx->iter, &key);
		check_ret_iter(KNOT_ERROR);
	}

	if (vals != NULL) free(vals);
	j->db_api->iter_finish(ctx->iter);

	unreuse_txn_ctx(txn, _txn);
	txn_check_ret(txn);

	return KNOT_EOK;
}

/*
 * ***************************** PART V *******************************
 *
 *  Loading a Changeset from DB
 *
 * ********************************************************************
 */

/*! \brief Deserialize changeset from chunks (in vals) */
static int vals_to_changeset(knot_db_val_t *vals, int nvals, const knot_dname_t *zone_name, changeset_t **ch)
{
	uint8_t * valps[nvals];
	size_t vallens[nvals]; // C99 can this :)
	for (int i = 0; i < nvals; i++) {
		valps[i] = vals[i].data + sizeof(journal_header_t);
		vallens[i] = vals[i].len - sizeof(journal_header_t);
	}

	changeset_t *t_ch = changeset_new(zone_name);
	if (t_ch == NULL) return KNOT_ENOMEM;

	int ret = changeset_deserialize_chunks(t_ch, valps, vallens, nvals);

	if (ret != KNOT_EOK) {
		changeset_free(t_ch);
		return ret;
	}
	*ch = t_ch;
	return KNOT_EOK;
}

static int load_one_itercb(iteration_ctx_t * ctx)
{
	changeset_t * ch = NULL;
	if (ctx->iter_context != NULL) return KNOT_EINVAL;

	int ret = vals_to_changeset(ctx->val, ctx->chunk_count, ctx->txn->j->zone_name, &ch);
	if (ret != KNOT_EOK) return ret;

	ctx->iter_context = ch;
	return KNOT_EOK;
}

static int load_list_itercb(iteration_ctx_t * ctx)
{
	changeset_t * ch = NULL;

	int ret = vals_to_changeset(ctx->val, ctx->chunk_count, ctx->txn->j->zone_name, &ch);
	if (ret != KNOT_EOK) return ret;

	list_t * chlist = (list_t *) ctx->iter_context;
	add_tail(chlist, &ch->n);

	return KNOT_EOK;
}

/*! \brief Load one changeset (with serial) from DB */
static int load_one(journal_t * j, txn_ctx_t * _txn, uint32_t serial, changeset_t ** ch)
{
	reuse_txn_ctx(txn, j, _txn, KNOT_DB_RDONLY);
	iteration_ctx_t ctx = { .method = JOURNAL_ITERATION_CHANGESETS, .iter_context = NULL };
	int ret = iterate(j, txn, load_one_itercb, &ctx, serial, serial);
	unreuse_txn_ctx(txn, _txn);
	if (ret == KNOT_EOK) ret = txn->ret;
	if (ret != KNOT_EOK) return ret;
	if (ctx.iter_context == NULL) return KNOT_ERROR;
	*ch = ctx.iter_context;
	return KNOT_EOK;
}

static int load_merged_changeset(journal_t * j, txn_ctx_t * txn, changeset_t ** mch)
{
	journal_metadata_t * relevant_metadata = &j->metadata;
	if (txn != NULL) relevant_metadata = &txn->shadow_metadata;

	if (!(relevant_metadata->flags & MERGED_SERIAL_VALID)) return KNOT_ENOENT;
	return load_one(j, txn, relevant_metadata->merged_serial, mch);
}

/*! \brief API: load all changesets since "from" serial into dst. */
int journal_load_changesets(journal_t *j, list_t *dst, uint32_t from)
{
	if (j == NULL || dst == NULL) return KNOT_EINVAL;
	int ret;
	local_txn_ctx(txn, j);
	txn_beg(txn, KNOT_DB_RDONLY);

	if (metadata_flag(j, MERGED_SERIAL_VALID) && serial_compare(from, j->metadata.merged_serial) == 0) {
		changeset_t * mch = NULL;
		ret = load_merged_changeset(j, txn, &mch);
		if (ret != KNOT_EOK) goto jlch_ret;
		add_tail(dst, &mch->n);
		from = knot_soa_serial(&mch->soa_to->rrs);
	}

	iteration_ctx_t ctx = { .method = JOURNAL_ITERATION_CHANGESETS, .iter_context = (void *) dst };
	ret = iterate(j, txn, load_list_itercb, &ctx, from, j->metadata.last_serial);
	jlch_ret:
	txn_commit(txn);
	if (ret == KNOT_EOK) ret = txn->ret;

	return ret;
}

/*
 * ***************************** PART VI ******************************
 *
 *  Changeset DELETION functions
 *  We use them just to save space (and drop_journal())
 *
 * ********************************************************************
 */

typedef struct {
	size_t freed_approx;
	size_t to_be_freed;
} deletefirst_iter_ctx_t;

static int del_upto_itercb(iteration_ctx_t * ctx)
{
	knot_db_val_t key;
	make_key2(ctx->serial, ctx->chunk_index, &key);
	txn_del(ctx->txn, &key);
	txn_check_ret(ctx->txn);

	// one whole changeset has been deleted => update metadata. We are sure that the deleted changeset is first at this time. If it's not merged changeset, point first_serial to next one
	if (ctx->chunk_index == ctx->chunk_count - 1) {
		if (!(ctx->txn->shadow_metadata.flags & MERGED_SERIAL_VALID) ||
		    serial_compare(ctx->txn->shadow_metadata.merged_serial,ctx->serial) != 0)
			ctx->txn->shadow_metadata.first_serial = ctx->serial_to;
		if (serial_compare(ctx->txn->shadow_metadata.last_flushed, ctx->serial) == 0) ctx->txn->shadow_metadata.flags &= ~LAST_FLUSHED_VALID;
		if (serial_compare(ctx->txn->shadow_metadata.last_serial,  ctx->serial) == 0) ctx->txn->shadow_metadata.flags &= ~SERIAL_TO_VALID;
		if (serial_compare(ctx->txn->shadow_metadata.merged_serial,ctx->serial) == 0) ctx->txn->shadow_metadata.flags &= ~MERGED_SERIAL_VALID;
	}
	return KNOT_EOK;
}

/*! \brief Delete from beginning of DB up to "last" changeset including.
 * Please ensure (dbfirst == j->metadata.first_serial) */
static int delete_upto(journal_t * j, txn_ctx_t * txn, uint32_t dbfirst, uint32_t last)
{
	iteration_ctx_t ctx = { .method = JOURNAL_ITERATION_CHUNKS };
	int ret = iterate(j, txn, del_upto_itercb, &ctx, dbfirst, last);
	if (ret != KNOT_EOK) return ret;
	return KNOT_EOK;
}

static int delete_merged_changeset(journal_t * j, txn_ctx_t * t)
{
	journal_metadata_t * relevant_metadata = &j->metadata;
	if (t != NULL) relevant_metadata = &t->shadow_metadata;

	if (!(relevant_metadata->flags & MERGED_SERIAL_VALID)) return KNOT_ENOENT;
	int ret = delete_upto(j, t, relevant_metadata->merged_serial, relevant_metadata->merged_serial);
	if (ret == KNOT_EOK) relevant_metadata->flags &= ~MERGED_SERIAL_VALID;
	return ret;
}

static int drop_journal(journal_t * j, txn_ctx_t * _txn)
{
	int ret = KNOT_EOK;
	reuse_txn_ctx(txn, j, _txn, 0);
	if ((txn->shadow_metadata.flags & MERGED_SERIAL_VALID)) ret = delete_merged_changeset(j, txn);
	if (ret == KNOT_EOK && (txn->shadow_metadata.flags & SERIAL_TO_VALID)) ret = delete_upto(j, txn, txn->shadow_metadata.first_serial, txn->shadow_metadata.last_serial);
	unreuse_txn_ctx(txn, _txn);
	txn_check_ret(txn);
	return ret;
}

static int del_tofree_itercb(iteration_ctx_t * ctx)
{
	deletefirst_iter_ctx_t * dfctx = ctx->iter_context;

	if (dfctx->to_be_freed == 0) return KNOT_EOK; // all done, just running through the rest of records w/o change

	dfctx->freed_approx += 4096 + ctx->val->len;

	// reuse iteration txn and delete one chunk
	knot_db_val_t key;
	make_key2(ctx->serial, ctx->chunk_index, &key);
	txn_del(ctx->txn, &key);
	txn_check_ret(ctx->txn);

	// when whole changeset deleted, check target and update metadata
	if (ctx->chunk_index == ctx->chunk_count - 1) {
		ctx->txn->shadow_metadata.first_serial = ctx->serial_to;
		if (serial_compare(ctx->txn->shadow_metadata.last_flushed, ctx->serial) == 0) {
			ctx->txn->shadow_metadata.flags &= ~LAST_FLUSHED_VALID;
			dfctx->to_be_freed = 0;
		}
		if (serial_compare(ctx->txn->shadow_metadata.last_serial,  ctx->serial) == 0) ctx->txn->shadow_metadata.flags &= ~SERIAL_TO_VALID;
		if (dfctx->freed_approx >= dfctx->to_be_freed) dfctx->to_be_freed = 0;
	}

	return KNOT_EOK;
}

/*!
 * \brief Deletes from j->db oldest changesets to free up space
 *
 * It tries deleting olny flushed changesets, preserves all unflushed ones.
 *
 * \retval KNOT_EOK if no error, even if too little or nothing deleted (check really_freed for result); KNOT_E* if error
 */
static int delete_tofree(journal_t * j, txn_ctx_t * txn, size_t to_be_freed, size_t * really_freed)
{
	journal_metadata_t * relevant_metadata = &j->metadata;
	if (txn != NULL) relevant_metadata = &txn->shadow_metadata;

	if (!(relevant_metadata->flags & LAST_FLUSHED_VALID)) {
		*really_freed = 0;
		return KNOT_EOK;
	}
	deletefirst_iter_ctx_t dfctx = { .freed_approx = 0, .to_be_freed = to_be_freed };
	iteration_ctx_t ctx = { .method = JOURNAL_ITERATION_CHUNKS, .iter_context = &dfctx };
	int ret = iterate(j, txn, del_tofree_itercb, &ctx, relevant_metadata->first_serial, relevant_metadata->last_serial);
	*really_freed = dfctx.freed_approx;
	if (ret != KNOT_EOK) return ret;
	return KNOT_EOK;
}

static int delete_dirty_serial(journal_t * j, txn_ctx_t * _txn)
{
        //if (!metadata_flag(DIRTY_SERIAL_VALID)) return;

        int chunk = 0;
        knot_db_val_t key, unused;

        reuse_txn_ctx(txn, j, _txn, 0);

        make_key2(txn->shadow_metadata.dirty_serial, 0, &key);


        while (txn_find(txn, &key, &unused, 0)) {
                txn_del(txn, &key);
                make_key2(txn->shadow_metadata.dirty_serial, ++chunk, &key);
        }

        if (chunk > 0) log_zone_info(j->zone_name, "deleted dirty journal record (serial %u)\n", txn->shadow_metadata.dirty_serial);

        if (txn->ret == KNOT_EOK) txn->shadow_metadata.flags &= ~DIRTY_SERIAL_VALID;

        unreuse_txn_ctx(txn, _txn);
        txn_check_ret(txn);
        return KNOT_EOK;
}

/*
 * **************************** PART VII ******************************
 *
 *  Adding a Changeset into DB
 *
 * ********************************************************************
 */

// returns EBUSY if asking zone to flush
/*!
 * \brief Inserts a changeset into DB, chunking it
 *
 * \param j Journal
 * \param _txn Optional: an open (read-write) txn to the DB
 * \param ch Changeset to be inserted
 * \param is_merged Flag to delcare if this is merged changeset. In that case, try_flush() is never attempted and metadata updated appropriately
 *
 * \return KNOT_EBUSY to tell the caller (from zone.c) to flush the journal, KNOT_E* otherwise
 */
static int insert_one_changeset(journal_t * j, txn_ctx_t * _txn, const changeset_t * ch, int is_merged)
{
	int ret = KNOT_EOK;
	size_t chsize = changeset_serialized_size(ch);
	uint32_t serial = knot_soa_serial(&ch->soa_from->rrs);
	uint32_t serial_to = knot_soa_serial(&ch->soa_to->rrs);
	size_t inserted_size = 0;
	int restart_txn = 0;
	int insert_txn_count = 1;

	uint8_t * allchunks = NULL;
	uint8_t ** chunkptrs = NULL;
	size_t * chunksizes = NULL;
	knot_db_val_t key, val;
	knot_db_val_t * vals = NULL;

	reuse_txn_ctx(txn, j, _txn, 0);
#define i_o_ch_txn_check if (txn->ret != KNOT_EOK) { txn_abort(txn); ret = txn->ret; goto i_o_ch_free; }

	// PART 1: continuity check
	if (!is_merged && (txn->shadow_metadata.flags & SERIAL_TO_VALID) && serial_compare(txn->shadow_metadata.last_serial_to, serial) != 0) {
		log_zone_warning(j->zone_name, "discontinuity in chages history (%u -> %u), dropping older changesets", txn->shadow_metadata.last_serial_to, serial);
		ret = try_flush(j, txn);
		if (ret != KNOT_EOK) goto i_o_ch_free;
		ret = drop_journal(j, txn);
		restart_txn = 1;
		if (ret != KNOT_EOK) goto i_o_ch_free;
	}

	// PART 2: removing possibly existing duplicite serial
	if (!is_merged) {
		make_key2(serial_to, 0, &key);
		if (txn_find(txn, &key, &val, 0)) {
			log_zone_warning(j->zone_name, "duplicite changeset serial (%u), dropping older changesets", serial_to);
			ret = try_flush(j, txn);
			if (ret != KNOT_EOK) goto i_o_ch_free;
			ret = delete_upto(j, txn, txn->shadow_metadata.first_serial, serial_to);
			restart_txn = 1;
			if (ret != KNOT_EOK) goto i_o_ch_free;
		}
	}

	// restart txn to properly recalculate free space based on what has been deleted
	if (restart_txn) {
		txn_commit(txn);
		i_o_ch_txn_check
		txn_beg(txn, 0);
	}

	// PART 3: making free space
	size_t free_req_min, free_req, freed = 0;
	check_free_space(j, &free_req, &free_req_min);
	if (freed < free_req_min) {
		ret = delete_tofree(j, txn, free_req, &freed); // delete_tofree is not accurate, but it's enough to keep the the usage levels timid
		if (ret != KNOT_EOK) goto i_o_ch_free;
	}
	if (freed < free_req_min && !is_merged) {
		ret = try_flush(j, txn);
		if (ret != KNOT_EOK) goto i_o_ch_free; // handles well also EBUSY (=asking zone to flush)
		free_req_min -= freed;
		free_req -= freed;
		ret = delete_tofree(j, txn, free_req, &freed);
		if (ret != KNOT_EOK) goto i_o_ch_free;
	}
	if (freed < free_req_min) {
		if (!is_merged) { // if storing merged changeset, there is more danger of losing history, so attempt inserting even when the space was not prepared well
			ret = KNOT_ESPACE;
			goto i_o_ch_free;
		}
	}

	// PART 4: serializing into chunks
	int maxchunks = chsize * 2 / CHUNK_MAX + 1, chunks; // twice chsize seems like enough room to store all chunks together
	allchunks = malloc(maxchunks * CHUNK_MAX);
	chunkptrs = malloc(maxchunks * sizeof(uint8_t *));
	chunksizes = malloc(maxchunks * sizeof(size_t));
	vals = malloc(maxchunks * sizeof(knot_db_val_t));
	if (allchunks == NULL || chunkptrs == NULL || chunksizes == NULL) {
		ret = KNOT_ENOMEM;
		goto i_o_ch_free;
	}
	for (int i = 0; i < maxchunks; i++) {
		chunkptrs[i] = allchunks + i*CHUNK_MAX + sizeof(journal_header_t);
	}
	assert(CHUNK_MAX >= sizeof(journal_header_t));
	ret = changeset_serialize_chunks(ch, chunkptrs, CHUNK_MAX - sizeof(journal_header_t), maxchunks, chunksizes, &chunks);
	if (ret != KNOT_EOK) goto i_o_ch_free;

	// PART 5: updating headers and creating vals
	for (int i = 0; i < chunks; i++) {
		vals[i].data = allchunks + i*CHUNK_MAX;
		vals[i].len = sizeof(journal_header_t) + chunksizes[i];
		make_header(vals + i, serial_to, chunksizes[i], chunks);
	}

	// PART 6: inserting vals into db
	for (int i = 0; i < chunks; i++) {
		make_key2(serial, i, &key);
		txn_insert(txn, &key, vals+i, 0);
		i_o_ch_txn_check
		inserted_size += (vals+i)->len;
		if ((float) inserted_size > DB_MAX_INSERT_TXN * (float) j->fslimit) { // insert txn too large
			inserted_size = 0;
			txn->shadow_metadata.dirty_serial = serial;
			txn->shadow_metadata.flags |= DIRTY_SERIAL_VALID;
			txn_commit(txn);
			i_o_ch_txn_check
			insert_txn_count++;
			txn_beg(txn, 0);
			i_o_ch_txn_check
			txn->shadow_metadata.flags &= ~DIRTY_SERIAL_VALID;
		}
	}

	// PART 7: metadata update
	if (!is_merged) {
		if (!(txn->shadow_metadata.flags & SERIAL_TO_VALID)) txn->shadow_metadata.first_serial = serial;
		txn->shadow_metadata.flags |= SERIAL_TO_VALID;
		txn->shadow_metadata.last_serial = serial;
		txn->shadow_metadata.last_serial_to = serial_to;
	}
	else {
		txn->shadow_metadata.flags |= MERGED_SERIAL_VALID;
		txn->shadow_metadata.merged_serial = serial;
	}

	// PART 8: cleanup
	i_o_ch_free:

	if (!txn->active && metadata_flag(j, DIRTY_SERIAL_VALID)) {
		delete_dirty_serial(j, NULL);
	}

	if (allchunks != NULL) free(allchunks);
	if (chunkptrs != NULL) free(chunkptrs);
	if (chunksizes != NULL) free(chunksizes);
	if (vals != NULL) free(vals);

	unreuse_txn_ctx(txn, _txn);
#undef i_o_ch_txn_check

	if (ret != KNOT_EOK) {
		log_zone_warning(j->zone_name, "failed to insert a changeset into journal in %d transactions (%s)", insert_txn_count, knot_strerror(ret)); // TODO consider removing
		journal_check(j, KNOT_JOURNAL_CHECK_INFO); // debug
	}

	return ret;
}

static int insert_merged_changeset(journal_t * j, txn_ctx_t * txn, const changeset_t * mch)
{
	return insert_one_changeset(j, txn, mch, 1);
}

int journal_store_changeset(journal_t *journal, changeset_t *ch)
{
	return insert_one_changeset(journal, NULL, ch, 0);
}

int journal_store_changesets(journal_t *journal, list_t *src)
{
	int ret = KNOT_EOK;
	changeset_t *chs = NULL;
	local_txn_ctx(txn, journal);
	txn_beg(txn, 0);
	txn_check_ret(txn);
	WALK_LIST(chs, *src) {
		ret = insert_one_changeset(journal, txn, chs, 0);
		txn_check_ret(txn);
		if (ret != KNOT_EOK) break;
	}
	txn_commit(txn);
	txn_check_ret(txn);
	return ret;
}

/*
 * *************************** PART VIII ******************************
 *
 *  Merge journal
 *
 * ********************************************************************
 */

static int find_first_unflushed(journal_t * j, txn_ctx_t * _txn, uint32_t * first)
{
	reuse_txn_ctx(txn, j, _txn, KNOT_DB_RDONLY);

	if (!(txn->shadow_metadata.flags & LAST_FLUSHED_VALID)) {
		*first = txn->shadow_metadata.first_serial;
		unreuse_txn_ctx(txn, _txn);
		return KNOT_EOK;
	}

	knot_db_val_t key, val;
	uint32_t lf = txn->shadow_metadata.last_flushed;
	make_key2(lf, 0, &key);


	txn_find_force(txn, &key, &val, 0);

	if (txn->ret == KNOT_EOK) {
		unmake_header(&val, first, NULL, NULL, NULL);

		if ((txn->shadow_metadata.flags & SERIAL_TO_VALID) && serial_compare(*first, txn->shadow_metadata.last_serial_to) == 0) txn->ret = KNOT_ENOENT;
	}

	unreuse_txn_ctx(txn, _txn);

	return txn->ret;
}

static int merge_itercb(iteration_ctx_t * ctx)
{
	changeset_t * ch = NULL, * mch = (changeset_t *) ctx->iter_context;

	int ret = vals_to_changeset(ctx->val, ctx->chunk_count, ctx->txn->j->zone_name, &ch);
	if (ret != KNOT_EOK) return ret;

	ret = changeset_merge(mch, ch);
	changeset_free(ch);
	return ret;
}

/*!
 * \brief Alternative to flushing into zonefile: merges the changesets
 *
 * If (merge_allowed()), when the journal becomes full, instead of asking tohe zone to flush into zonefile, the journal merges the old changesets into one
 * and saves in a special DB designated for this single (big) changeset (chunked, anyway). The idea is that multiple changesets usually modify the same
 * zone entries, so the size of merged changeset can be way less than sum of sizes of the changesets. The first time this method invoked, it merges all
 * the changesets from j->db together and stores the merged changeset aside, marking them "flushed". The next time, it merges all the unmerged new changesets
 * to the existing merged changeset, marking the new ones "flushed" again. Usually, many of these (oldest) changesets will get deleted soon.
 */
static int merge_journal(journal_t * j, txn_ctx_t * _txn)
{
	changeset_t * mch = NULL;
	int ret;

	reuse_txn_ctx(txn, j, _txn, 0);

	uint32_t from;
	ret = find_first_unflushed(j, txn, &from);
	if (ret == KNOT_ENOENT) return KNOT_EOK; // journal empty or completely flushed, nothing to do
	if (ret != KNOT_EOK) return ret;

	if ((txn->shadow_metadata.flags & MERGED_SERIAL_VALID)) {
		ret = load_merged_changeset(j, txn, &mch);
		if (ret == KNOT_EOK && serial_compare(from, knot_soa_serial(&mch->soa_to->rrs)) != 0) {
			ret = KNOT_ERROR;
		}
	}
	else { // this is the very first merge. we take the first unmerged changeset as a base and merge the rest to it.
		txn->shadow_metadata.merged_serial = from;
		txn->shadow_metadata.flags &= ~MERGED_SERIAL_VALID;

		ret = load_one(j, txn, from, &mch);
		if (ret == KNOT_EOK) {
			delete_upto(j, txn, txn->shadow_metadata.first_serial, from);
			from = knot_soa_serial(&mch->soa_to->rrs);
		}
	}
	if (ret != KNOT_EOK) {
		if (mch != NULL) changeset_free(mch);
		unreuse_txn_ctx(txn, _txn);
		return ret;
	}
	// mch now contains the initial changeset we will merge the other ones to

	delete_merged_changeset(j, txn);
	txn->shadow_metadata.flags &= ~MERGED_SERIAL_VALID;

	if (serial_compare(from, txn->shadow_metadata.last_serial) != 0) {
		iteration_ctx_t ctx = { .method = JOURNAL_ITERATION_CHANGESETS, .iter_context = (void *) mch };
		ret = iterate(j, txn, merge_itercb, &ctx, from, txn->shadow_metadata.last_serial);
	}

	if (ret == KNOT_EOK) ret = insert_merged_changeset(j, txn, mch);
	if (ret == KNOT_EOK) {
		if ((txn->shadow_metadata.flags & SERIAL_TO_VALID)) {
			txn->shadow_metadata.last_flushed = txn->shadow_metadata.last_serial;
			txn->shadow_metadata.flags |= LAST_FLUSHED_VALID;
		}
	}
	changeset_free(mch); // in all cases
	unreuse_txn_ctx(txn, _txn);

	log_zone_info(j->zone_name, "journal history merged (%s)", knot_strerror(ret)); // TODO remove

	return ret;
}

/*
 * ***************************** PART IX ******************************
 *
 *  Journal initialization and global manipulation
 *
 * ********************************************************************
 */

/*! \brief DB init, include DB files open/create. Requires path and fslimit. */
static int init_db(journal_t *j)
{
	j->db_api = knot_db_lmdb_api();
	struct knot_db_lmdb_opts opts = KNOT_DB_LMDB_OPTS_INITIALIZER;
	opts.path = j->path;
	opts.mapsize = j->fslimit;
	opts.maxdbs = 3; // One DB for data, one for metadata and one for merged changeset.

	opts.dbname = DATA_DB_NAME;
	int ret = j->db_api->init(&j->db, NULL, &opts);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = load_metadata(j);
	if (ret != KNOT_EOK) {
		j->db_api->deinit(j->db);
		return ret;
	}

	return KNOT_EOK;
}

journal_t *journal_new()
{
	journal_t *j = malloc(sizeof(*j));
	if (j != NULL) memset(j, 0, sizeof(*j));
	return j;
}

void journal_free(journal_t **j)
{
	if (j == NULL || *j == NULL) return;
	free(*j);
	*j = NULL;
}

/*! \brief Open/create the journal based on the filesystem path to LMDB directory */
int journal_open(journal_t *j, const char *path, size_t fslimit, const knot_dname_t *zone_name)
{
	if (j == NULL || path == NULL || zone_name == NULL) return KNOT_EINVAL;
	if (j->path != NULL) return KNOT_EBUSY;

	j->fslimit = (fslimit > FSLIMIT_MIN) ? fslimit : FSLIMIT_MIN;

	j->path = strdup(path);
	if (j->path == NULL) {
		return KNOT_ENOMEM;
	}

#define NOK_FREE if (ret != KNOT_EOK) { free(j->path); return ret; }

	j->zone_name = zone_name;

	int ret = init_db(j);
	NOK_FREE

	// Check if we by any chance opened the DB with smaller mapsize than before.
	// If so, we need to return error, flush and retry.
	if (knot_db_lmdb_get_mapsize(j->db) > j->fslimit) {
		log_zone_warning(j->zone_name, "reopening journal DB with smaller mapsize %zu versus %zu\n", knot_db_lmdb_get_mapsize(j->db), j->fslimit);
		if (!is_flushed(j->metadata)) {
			return KNOT_EAGAIN;
		} else {
			j->db_api->deinit(j->db);
			j->db = NULL;
			memset(&j->metadata, 0, sizeof(j->metadata));
			if (!remove_path(j->path)) {
				ret = KNOT_ERROR;
				NOK_FREE
			}
			ret = init_db(j);
			NOK_FREE
		}
	}
#undef NOK_FREE

	if (metadata_flag(j, DIRTY_SERIAL_VALID)) {
		delete_dirty_serial(j, NULL);
	}

	// return journal_check(j, KNOT_JOURNAL_CHECK_SILENT); // would be nice, but too slow
	return KNOT_EOK;
}

void journal_close(journal_t *j)
{
	if (j == NULL || j->path == NULL) return;

	//int ret = store_metadata(j); // not needed anymore - metadata are updated continuously
	//if (ret != KNOT_EOK) {
	//	log_zone_error(j->zone_name, "unable to store journal metadata");
	//}

	j->db_api->deinit(j->db);

	free(j->path);
	j->db = NULL;
	j->path = NULL;
}

bool journal_exists(const char *path)
{
	if (path == NULL) return false;
	struct stat st;
	return (stat(path, &st) == 0);
}

/*
 * **************************** PART X ********************************
 *
 *  Journal Check
 *
 * ********************************************************************
 */

static void _jch_print(const knot_dname_t * zname, int warn_level, const char * format, ...)
{
        static char buf[512];
        strcpy(buf, "journal check: ");

        va_list args;
        va_start(args, format);
        vsprintf(buf + strlen(buf), format, args);
        va_end(args);

        switch (warn_level) {
        case KNOT_JOURNAL_CHECK_INFO:
                log_zone_info(zname, "%s", buf);
                break;
        case KNOT_JOURNAL_CHECK_WARN:
                log_zone_error(zname, "%s", buf);
                break;
        }
}

int journal_check(journal_t *j, int warn_level)
{
	int ret = KNOT_EOK, ret2 = KNOT_EOK, i = 1;
	uint32_t soa_to, nexts, last_flushed_soa_to = UINT32_MAX, soa_from;
	changeset_t * ch;
	size_t total_chsize = 0;

#define jch_print(wl, fmt_args...) if (wl <= warn_level) _jch_print(j->zone_name, wl, fmt_args)
#define jch_info KNOT_JOURNAL_CHECK_INFO
#define jch_warn KNOT_JOURNAL_CHECK_WARN

	if (j == NULL) {
		jch_print(jch_warn, "journal is null");
		return KNOT_ERROR;
	}

	if (j->db == NULL) {
		jch_print(jch_warn, "journal DB is not open");
		return KNOT_ESEMCHECK;
	}

	jch_print(jch_info, "metadata: fs %u ls %u lst %u lf %u ms %u flgs %d",
		  j->metadata.first_serial, j->metadata.last_serial, j->metadata.last_serial_to,
		  j->metadata.last_flushed, j->metadata.merged_serial, j->metadata.flags);

	local_txn_ctx(txn, j);
	txn_beg(txn, KNOT_DB_RDONLY);
	if (txn->ret != KNOT_EOK) {
		jch_print(jch_warn, "db cannot be accessed");
		return txn->ret;
	}

	size_t dbsize = txn_db_count(txn);
	txn_abort(txn);
	jch_print(jch_info, "db size is %zu", dbsize);

	jch_print(jch_info, "db usage: %.2f%%", get_used_space(j) * 100.0f);

	if (dbsize == 0) {
		if (metadata_flag(j, SERIAL_TO_VALID)) {
			jch_print(jch_warn, "SERIAL_TO_VALID is set");
			ret2 = KNOT_ENOENT;
		}
		if (metadata_flag(j, LAST_FLUSHED_VALID)) {
			jch_print(jch_warn, "LAST_FLUSHED_VALID is set");
			ret2 = KNOT_ENOENT;
		}
		txn_abort(txn);
		goto check_merged;
	}

	if (!metadata_flag(j, SERIAL_TO_VALID)) {
		jch_print(jch_warn, "SERIAL_TO_VALID is not set");
		ret2 = KNOT_ENOENT;
	}
	ret = load_one(j, NULL, j->metadata.first_serial, &ch);
	if (ret != KNOT_EOK) {
		jch_print(jch_warn, "first changeset no %u cannot be accessed (%d)", j->metadata.first_serial, ret);
		return ret;
	}
	total_chsize += changeset_serialized_size(ch);
	soa_from = knot_soa_serial(&ch->soa_from->rrs);
	soa_to = knot_soa_serial(&ch->soa_to->rrs);
	if (serial_compare(soa_from, j->metadata.first_serial) != 0) {
		jch_print(jch_warn, "first changeset serial from is %u, not %u as expected", soa_from, j->metadata.first_serial);
		changeset_free(ch);
		txn_abort(txn);
		return KNOT_EMALF;
	}
	changeset_free(ch);

	while (soa_to != j->metadata.last_serial_to) {
		++i;
		nexts  = soa_to;
		ret = load_one(j, NULL, nexts, &ch);
		if (ret != KNOT_EOK) {
			jch_print(jch_warn, "can't read %d%s changeset no %u", i, (i == 2 ? "nd" : (i == 3 ? "rd" : "th")), nexts);
			txn_abort(txn);
			return ret;
		}
		total_chsize += changeset_serialized_size(ch);
		soa_from = knot_soa_serial(&ch->soa_from->rrs);
		soa_to = knot_soa_serial(&ch->soa_to->rrs);
		if (is_last_flushed(j->metadata, nexts)) {
			last_flushed_soa_to = soa_to;
			jch_print(jch_info, "%d%s changeset no %u is last flushed", i, (i == 2 ? "nd" : (i == 3 ? "rd" : "th")), nexts);
		}
		if (serial_compare(soa_from, nexts) != 0) {
			jch_print(jch_warn, "%d%s changeset serial from is %u, not %u as expected", i, (i == 2 ? "nd" : (i == 3 ? "rd" : "th")), soa_from, nexts);
			changeset_free(ch);
			txn_abort(txn);
			return KNOT_EMALF;
		}
		changeset_free(ch);
	}

	jch_print(jch_info, "total changeset size: %zu", total_chsize);

	check_merged:

	ret = load_merged_changeset(j, NULL, &ch);
	if (ret == KNOT_EOK && !metadata_flag(j, MERGED_SERIAL_VALID)) {
		jch_print(jch_warn, "merged changeset found but should not be according to metadata");
	}
	if (ret != KNOT_EOK && metadata_flag(j, MERGED_SERIAL_VALID)) {
		jch_print(jch_warn, "merged changeset not loadable (%d) but shloud be", ret);
		return ret;
	}
	if (ret == KNOT_EOK) { //no problem otherwise
		soa_from = knot_soa_serial(&ch->soa_from->rrs);
		soa_to = knot_soa_serial(&ch->soa_to->rrs);
		jch_print(jch_info, "note: merged changeset %u -> %u, size %zu", j->metadata.merged_serial, soa_to, changeset_serialized_size(ch));
		if (metadata_flag(j, LAST_FLUSHED_VALID) && serial_compare(soa_to, last_flushed_soa_to) != 0) {
			jch_print(jch_warn, "last_flushed soa_to is %u but merged soa_to is %u", last_flushed_soa_to, soa_to);
			changeset_free(ch);
			return KNOT_ENOENT;
		}
		if (serial_compare(soa_from, j->metadata.merged_serial) != 0) {
			jch_print(jch_warn, "merged changeset serial from is %u, not %u as expected", soa_from, j->metadata.merged_serial);
			changeset_free(ch);
			return KNOT_EMALF;
		}
		changeset_free(ch);
	}

	if (ret2 == KNOT_EOK) jch_print(jch_info, "passed without errors");

#undef jch_print
#undef jch_info
#undef jch_warn

	return ret2;
}
