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

#include "knot/common/log.h"
#include "knot/journal/journal.h"
#include "knot/journal/serialization.h"
#include "knot/zone/serial.h"
#include "libknot/libknot.h"
#include "contrib/endian.h"
#include "contrib/files.h"

/*! \brief Primary journal database name for main data storage. */
#define DATA_DB_NAME "data"
/*! \brief Secondary journal database name for metadata storage. */
#define META_DB_NAME "meta"
/*! \brief Third journal database to store just the merged changeset (exsting only in case of disabled flush). */
#define MERGED_DB_NAME "merged"
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
#define DB_KEEP_MERGED 0.33f
#define DB_KEEP_FORMERGE 0.67f
#define DB_DISPOSE_RATIO 3
#define DB_MAX_INSERT_TXN 0.05f

enum {
	LAST_FLUSHED_VALID = 1 << 0, /* "last flush is valid" flag. */
	SERIAL_TO_VALID    = 1 << 1, /* "last serial_to is valid" flag. */
	MERGED_SERIAL_VALID= 1 << 2, /* "serial_from" of merged changeset */
};

typedef struct journal_metadata {
	uint32_t first_serial;		// serial_from of the first changeset
	uint32_t last_serial;		// serial_from of the last changeset
	uint32_t last_serial_to;	// serial_to of the last changeset
	uint32_t last_flushed;		// serial_from of the last flushed (or merged) chengeset
	uint32_t merged_serial;		// "serial_from" of merged changeset
	uint32_t flags;			// LAST_FLUSHED_VALID, SERIAL_TO_VALID, MERGED_SERIAL_VALID
} journal_metadata_t;

#define is_last_flushed(metadata, what) (((metadata).flags & LAST_FLUSHED_VALID) && (metadata).last_flushed == (what))
#define is_flushed(metadata) (is_last_flushed((metadata), (metadata).last_serial))

static void copy_metadata(journal_metadata_t *a, journal_metadata_t *b)
{
	memcpy(a, b, sizeof(*a));
}

struct journal {
	knot_db_t *db;                 /*!< DB handler. */
	knot_db_t *meta_db;            /*!< Metadata DB handler. */
	knot_db_t *merged_db;          /*!< Merged changeset DB handler. */
	const knot_db_api_t *db_api;   /*!< DB API backend. */
	char *path;                    /*!< Path to journal file. */
	size_t fslimit;                /*!< File size limit. */
	const knot_dname_t *zone_name; /*!< Associated zone name. */
	journal_metadata_t metadata;   /*!< Metadata. */
};

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

float get_used_space(journal_t * j)
{
	float x = knot_db_lmdb_get_usage(j->db);
	if ((j->metadata.flags & MERGED_SERIAL_VALID)) {
		x += knot_db_lmdb_get_usage(j->merged_db);
	}
	return x;
}

void check_free_space(journal_t * j, size_t * request_free, size_t * request_free_min)
{
	float occupied = get_used_space(j);
	float allowed_occupied = 1.0f - DB_KEEP_FREE;
	if ((j->metadata.flags & MERGED_SERIAL_VALID)) {
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

static int merge_journal(journal_t * j); // from PART VIII
static int delete_merged_changeset(journal_t * j);

/* Please take care what this function does and mind the caller context. The EBUSY code is usually not an error, but correct */
static int try_flush(journal_t * j)
{
	if (is_flushed(j->metadata)) {
		if ((j->metadata.flags & MERGED_SERIAL_VALID) && !merge_allowed(j)) {
			// this is the situation that merge was present, we flushed the journal to zonefile via zone, so the merged changeset is actually flushed and not needed anymore
			// this cannot happen if merge_allowed() doesn't change suddenly
			delete_merged_changeset(j);
		}
		return KNOT_EOK;
	}
	if (merge_allowed(j)) return merge_journal(j);

	return KNOT_EBUSY; // returns EBUSY to caller from zone.c - it flushes the journal for us and tries again
}

/*! \brief Just updates the metadata after journal was actually flushed */
int journal_flush(journal_t *j)
{
	if ((j->metadata.flags & SERIAL_TO_VALID)) {
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

typedef struct {
	journal_t * j;
	knot_db_txn_t * txn;
	int ret;
	int active; // private
} txn_ctx_t;

/*! \brief Creates local-scoped handle for use with following functions
 * Please use just once in a function/block */
#define local_txn_ctx(txn_ctx_name, pjournal) knot_db_txn_t local_txn_ctx_txn; \
					       txn_ctx_t local_txn_ctx_ctx = { .j = (pjournal), .txn = &local_txn_ctx_txn, .ret = KNOT_EOK, .active = 0 }, \
						         * txn_ctx_name = &local_txn_ctx_ctx;

/*! \brief Inits a DB transaction with flags
 * db shall be one of j->db, j->meta_db and j->merged_db */
void txn_beg_db(txn_ctx_t * t, knot_db_t * db, int flags)
{
	if (t->active) {
	    t->ret = KNOT_EINVAL;
	    return;
	}
	t->ret = t->j->db_api->txn_begin(db, t->txn, flags);
	if (t->ret == KNOT_EOK) t->active = 1;
}
#define txn_beg_jdb(_t, _db, _flags) txn_beg_db((_t), (_t)->j->_db, (_flags))
#define txn_beg(t, flags) txn_beg_jdb((t), db, (flags))

void txn_abort(txn_ctx_t * t) // doesn't touch t->ret
{
	if (t->active) t->j->db_api->txn_abort(t->txn);
	t->active = 0;
}

/*! \brief those check if txn failed in the past and return the caller function in case */
#define txn_check(t, x) if ((t)->ret != KNOT_EOK) { return (x); }
#define txn_check_void(t) if ((t)->ret != KNOT_EOK) { return; }
#define txn_check_ret(t) txn_check((t), (t)->ret)
#define txn_inactive_inval(t) if (!(t)->active) { if ((t)->ret == KNOT_EOK) (t)->ret = KNOT_EINVAL; }

void txn_commit(txn_ctx_t * t)
{
	txn_inactive_inval(t);
	txn_check_void(t);
	t->ret = t->j->db_api->txn_commit(t->txn);
	if (t->ret != KNOT_EOK) {
	    txn_abort(t);
	}
	t->active = 0;
}

size_t txn_db_count(txn_ctx_t * t) // no check for errors
{
	return t->j->db_api->count(t->txn);
}

/*! \brief search for key and return in val. If not found, report no error, just return 0 */
int txn_find(txn_ctx_t * t, knot_db_val_t * key, knot_db_val_t * val, int flags)
{
	txn_inactive_inval(t);
	txn_check(t, 0);
	t->ret = t->j->db_api->find(t->txn, key, val, flags);
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

/*! \brief Searc for key and return in val. If not found, trigger error */
void txn_find_force(txn_ctx_t * t, knot_db_val_t * key, knot_db_val_t * val, int flags)
{
	txn_inactive_inval(t);
	txn_check_void(t);
	t->ret = t->j->db_api->find(t->txn, key, val, flags);
	if (t->ret != KNOT_EOK) {
	    txn_abort(t);
	}
}

void txn_insert(txn_ctx_t * t, knot_db_val_t * key, knot_db_val_t * val, int flags)
{
	txn_inactive_inval(t);
	txn_check_void(t);
	t->ret = t->j->db_api->insert(t->txn, key, val, flags);
	if (t->ret != KNOT_EOK) {
	    txn_abort(t);
	}
}

void txn_del(txn_ctx_t * t, knot_db_val_t * key)
{
	txn_inactive_inval(t);
	txn_check_void(t);
	t->ret = t->j->db_api->del(t->txn, key);
	if (t->ret != KNOT_EOK) {
	    txn_abort(t);
	}
}

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
	(to)->len = sizeof(make_key_local);

#define make_key2(_serial, _chunk, to) \
	journal_key_t make_key_local; \
	make_key_local.serial = htobe32((_serial)); \
	make_key_local.chunk = htobe32((_chunk)); \
	(to)->data = &make_key_local; \
	(to)->len = sizeof(make_key_local);

/*! \brief decode the key's properties */
static void unmake_key(const knot_db_val_t * from, journal_key_t * to)
{
	assert(from->len == sizeof(journal_key_t));
	to->serial = be32toh(((journal_key_t *) from->data)->serial);
	to->chunk = be32toh(((journal_key_t *) from->data)->chunk);
}

static int keys_equal(const knot_db_val_t * key1, const knot_db_val_t * key2)
{
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
	if (chunk_count != NULL) *chunk_count = be32toh(h->chunk_count);
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

/*! \brief Load from meta_db incl version check and endian converison. */
static int load_metadata(journal_t * j)
{
	assert(j);

	local_txn_ctx(txn, j);
	txn_beg_jdb(txn, meta_db, KNOT_DB_RDONLY);

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

	load_metadata_one("first_serial",   j->metadata.first_serial);
	load_metadata_one("last_serial",    j->metadata.last_serial);
	load_metadata_one("last_serial_to", j->metadata.last_serial_to);
	load_metadata_one("last_flushed",   j->metadata.last_flushed);
	load_metadata_one("merged_serial",  j->metadata.merged_serial);
	load_metadata_one("flags",          j->metadata.flags);

	txn_abort(txn); // we can just abort read-only transactions

	#undef load_metadata_one

	return KNOT_EOK;
}

static int store_metadata(journal_t *j)
{
	assert(j);

	local_txn_ctx(t, j);
	txn_beg_jdb(t, meta_db, 0);

	knot_db_val_t key, val;

	#define store_metadata_one(keystr, value) { \
		uint32_t valuendian; \
		key.len = strlen(keystr) + 1; \
		key.data = (void *) (keystr); \
		val.len = sizeof(value); \
		if (sizeof(value) == sizeof(uint32_t)) { \
			valuendian = htobe32(value); \
			val.data = (void *) &valuendian; \
		} \
		else { \
			val.data = (void *) &value; \
		} \
		txn_insert(t, &key, &val, 0); \
	}

	uint32_t version = JOURNAL_VERSION;

	store_metadata_one("version",       version);
	store_metadata_one("first_serial",  j->metadata.first_serial);
	store_metadata_one("last_serial",   j->metadata.last_serial);
	store_metadata_one("last_serial_to",j->metadata.last_serial_to);
	store_metadata_one("last_flushed",  j->metadata.last_flushed);
	store_metadata_one("merged_serial", j->metadata.merged_serial);
	store_metadata_one("flags",         j->metadata.flags);

	key.len = strlen("zone_name") + 1;
	key.data = (void *) "zone_name";
	val.len = strlen((const char *) j->zone_name) + 1;
	val.data = (void *) j->zone_name;
	txn_insert(t, &key, &val, 0);

	txn_commit(t);
	txn_check_ret(t);

	#undef store_metadata_one

	return KNOT_EOK;
}

int journal_load_zone_name(journal_t * j, const knot_dname_t ** zname)
{
        if (j == NULL) return KNOT_EINVAL;

        local_txn_ctx(txn, j);
        txn_beg_jdb(txn, meta_db, KNOT_DB_RDONLY);

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

        if (j == NULL || !(j->metadata.flags & SERIAL_TO_VALID)) {
                *is_empty = 1;
                return;
        }

        *is_empty = 0;
        *serial_from = j->metadata.first_serial;
        *serial_to = j->metadata.last_serial_to;

        if ((j->metadata.flags & MERGED_SERIAL_VALID)) {
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

typedef struct {
	knot_db_t * db; // DB to iterate over (usually j->db)
	int flags;      // txn flags (0 or KNOT_DB_RDONLY)
} iteration_db_spec;

/*! \brief Call with full txn to restart it while keeping iterator. */
static int refresh_txn_iter(txn_ctx_t * t, iteration_ctx_t * ictx, const iteration_db_spec * spec, uint32_t * last_refreshed)
{
	assert(t->j == ictx->txn->j);

	t->j->db_api->iter_finish(ictx->iter);
	txn_commit(t);
	txn_check_ret(t);

	if (ictx->method == JOURNAL_ITERATION_CHANGESETS) {
		if (*last_refreshed == ictx->serial) return KNOT_ELIMIT; // trying to refresh cyclically the same changeset which cannot be read at once
		*last_refreshed = ictx->serial;
		ictx->chunk_index = 0; // restart at the beginning of current changeset
	}

	txn_beg_db(t, spec->db, spec->flags); // really NOOP? or 0 now ?, not spec->flags
	txn_check_ret(t);

	knot_db_iter_t *it = t->j->db_api->iter_begin(t->txn, KNOT_DB_NOOP);
	if (it == NULL) {
		return KNOT_ERROR;
	}

	knot_db_val_t key;
	make_key2(ictx->serial, ictx->chunk_index, &key);
	it = t->j->db_api->iter_seek(it, &key, 0);
	if (it == NULL) {
		return KNOT_ENOENT;
	}

	ictx->iter = it;
	return KNOT_EOK;
}

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
 * \param txn Open txn to a DB, can possibly be restarted
 * \param cb Callback to be called when a chunk/changeset is read
 * \param ctx Initial values for iteration context, please set up .method and .iter_context
 * \param first, last Interval of changesets to be iterated over
 * \param spec DB pointer and flags of txn, for the sake of restarting it
 *
 * \retval KNOT_E*
 */
static int iterate_txn(txn_ctx_t * txn, iteration_cb_t cb, iteration_ctx_t *ctx, uint32_t first, uint32_t last, const iteration_db_spec * spec)
{
	journal_t * j = txn->j;
	ctx->txn = txn; // just for convenience

	int ret = KNOT_EOK;
	uint32_t last_refreshed = ~first; // TODO this mechanizm is not elegant. think of other ways how to stop cyclic refreshing

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
			if (ret == KNOT_ELIMIT) {
				ret = refresh_txn_iter(txn, ctx, spec, NULL);
				check_ret_iter(KNOT_ERROR);
				ret = cb(ctx);
			}
			check_ret_iter(KNOT_ERROR);
		}

		if (ctx->chunk_index == ctx->chunk_count - 1) { // hit last chunk of current changeset
			if (ctx->method == JOURNAL_ITERATION_CHANGESETS) {
				ret = cb(ctx);
				if (ret == KNOT_ELIMIT) {
					ret = refresh_txn_iter(txn, ctx, spec, &last_refreshed);
					check_ret_iter(KNOT_ERROR);
					continue;
				}
				check_ret_iter(KNOT_ERROR);
			}

			if (ctx->serial == last) break; // standard loop exit here

			ctx->serial = ctx->serial_to;
			ctx->chunk_index = 0;
			last_refreshed = ~ctx->serial;
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

	return KNOT_EOK;
}

/*! \brief Apply cb() successively on interval [first, last] (including).
 * See the function above for details */
static int iterate(journal_t *j, knot_db_t * db, iteration_cb_t cb, iteration_ctx_t *ctx, uint32_t first, uint32_t last, int txnflags)
{
	local_txn_ctx(txn, j);
	txn_beg_db(txn, db, txnflags);
	txn_check_ret(txn);
	iteration_db_spec spec = { .db = db, .flags = txnflags };
	int ret = iterate_txn(txn, cb, ctx, first, last, &spec);
	if (ret == KNOT_EOK) txn_commit(txn);
	return ret;
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

/*! \brief Load one changeset (with serial) from DB (specified db and j) */
static int load_one(journal_t * j, knot_db_t * db, uint32_t serial, changeset_t ** ch)
{
	iteration_ctx_t ctx = { .method = JOURNAL_ITERATION_CHANGESETS, .iter_context = NULL };
	int ret = iterate(j, db, load_one_itercb, &ctx, serial, serial, KNOT_DB_RDONLY);
	if (ret != KNOT_EOK) return ret;
	if (ctx.iter_context == NULL) return KNOT_ERROR;
	*ch = ctx.iter_context;
	return KNOT_EOK;
}

static int load_merged_changeset(journal_t * j, changeset_t ** mch)
{
	if (!(j->metadata.flags & MERGED_SERIAL_VALID)) return KNOT_ENOENT;
	return load_one(j, j->merged_db, j->metadata.merged_serial, mch);
}

/*! \brief API: load all changesets since "from" serial into dst. */
int journal_load_changesets(journal_t *j, list_t *dst, uint32_t from)
{
	if (j == NULL || dst == NULL) return KNOT_EINVAL;
	int ret;

	if ((j->metadata.flags & MERGED_SERIAL_VALID) && serial_compare(from, j->metadata.merged_serial) == 0) {
		changeset_t * mch = NULL;
		ret = load_merged_changeset(j, &mch);
		if (ret != KNOT_EOK) return ret;
		add_tail(dst, &mch->n);
		from = knot_soa_serial(&mch->soa_to->rrs);
	}

	iteration_ctx_t ctx = { .method = JOURNAL_ITERATION_CHANGESETS, .iter_context = (void *) dst };
	ret = iterate(j, j->db, load_list_itercb, &ctx, from, j->metadata.last_serial, KNOT_DB_RDONLY);

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

/*! \brief After deleting the first(!) changeset, updates metadata */
static void deleted_update_metadata(journal_metadata_t * shadow_metadata, uint32_t deleted, uint32_t serial_to /*, size_t deleted_size*/)
{
	if (serial_compare(shadow_metadata->last_flushed, deleted) == 0) shadow_metadata->flags &= ~LAST_FLUSHED_VALID;
	if (serial_compare(shadow_metadata->last_serial, deleted) == 0) {
		shadow_metadata->flags &= ~SERIAL_TO_VALID;
		return;
	}
	shadow_metadata->first_serial = serial_to;
}

typedef struct {
	journal_metadata_t shadow; // the point of shadow metadata is to apply them just after successful commit
	size_t freed_approx;       // ^--- and not to apply them in case of error aborting the txn
	size_t to_be_freed;
} deletefirst_iter_ctx_t;

static int del_upto_itercb(iteration_ctx_t * ctx)
{
	deletefirst_iter_ctx_t * dfctx = ctx->iter_context;

	dfctx->freed_approx += 4096 + ctx->val->len;

	// reuse iteration txn and delete one chunk
	knot_db_val_t key;
	make_key2(ctx->serial, ctx->chunk_index, &key);
	txn_del(ctx->txn, &key);
	txn_check_ret(ctx->txn);

	// when whole changeset deleted, check target and update metadata
	if (ctx->chunk_index == ctx->chunk_count - 1) {
		deleted_update_metadata(&dfctx->shadow, ctx->serial, ctx->serial_to /*, dfctx->freed_approx*/);
		dfctx->freed_approx = 0;
	}
	return KNOT_EOK;
}

/*! \brief Delete from beginning of DB up to "last" changeset including.
 * Please ensure (dbfirst == j->metadata.first_serial) */
static int delete_upto(journal_t * j, knot_db_t * db, uint32_t dbfirst, uint32_t last)
{
	deletefirst_iter_ctx_t dfctx = { .freed_approx = 0 };
	copy_metadata(&dfctx.shadow, &j->metadata);
	iteration_ctx_t ctx = { .method = JOURNAL_ITERATION_CHUNKS, .iter_context = &dfctx };
	int ret = iterate(j, db, del_upto_itercb, &ctx, dbfirst, last, 0);
	if (ret != KNOT_EOK) return ret;
	if (db == j->db) copy_metadata(&j->metadata, &dfctx.shadow);
	return KNOT_EOK;
}

static int delete_merged_changeset(journal_t * j)
{
	if (!(j->metadata.flags & MERGED_SERIAL_VALID)) return KNOT_ENOENT;
	int ret = delete_upto(j, j->merged_db, j->metadata.merged_serial, j->metadata.merged_serial);
	if (ret == KNOT_EOK) j->metadata.flags &= ~MERGED_SERIAL_VALID;
	return ret;
}

static int drop_journal(journal_t * j)
{
	int ret = KNOT_EOK;
	if ((j->metadata.flags & MERGED_SERIAL_VALID)) ret = delete_merged_changeset(j);
	if (ret == KNOT_EOK && (j->metadata.flags & SERIAL_TO_VALID)) ret = delete_upto(j, j->db, j->metadata.first_serial, j->metadata.last_serial);
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
		deleted_update_metadata(&dfctx->shadow, ctx->serial, ctx->serial_to /*, dfctx->freed_approx */);
		if (dfctx->freed_approx >= dfctx->to_be_freed) dfctx->to_be_freed = 0;
		if (serial_compare(ctx->serial, ctx->txn->j->metadata.last_flushed) == 0) dfctx->to_be_freed = 0;
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
static int delete_tofree(journal_t * j, size_t to_be_freed, size_t * really_freed)
{
	if (!(j->metadata.flags & LAST_FLUSHED_VALID)) {
		*really_freed = 0;
		return KNOT_EOK;
	}
	deletefirst_iter_ctx_t dfctx = { .freed_approx = 0, .to_be_freed = to_be_freed };
	copy_metadata(&dfctx.shadow, &j->metadata);
	iteration_ctx_t ctx = { .method = JOURNAL_ITERATION_CHUNKS, .iter_context = &dfctx };
	int ret = iterate(j, j->db, del_tofree_itercb, &ctx, j->metadata.first_serial, j->metadata.last_serial, 0);
	*really_freed = dfctx.freed_approx;
	if (ret != KNOT_EOK) return ret;
	copy_metadata(&j->metadata, &dfctx.shadow);
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
 * \param j Journal
 * \param db Either j->db or j->merged_db
 * \param ch Changeset to be inserted
 * \param try_flush_allowed Flag to delcare if the call of try_flush() is allowed by this function
 * \return KNOT_EBUSY to tell the caller (from zone.c) to flush the journal, KNOT_E* otherwise
 */
static int insert_one_changeset(journal_t * j, knot_db_t * db, const changeset_t * ch, int try_flush_allowed)
{
	if (j == NULL || (db != j->db && db != j->merged_db) || ch == NULL) return KNOT_EINVAL;
	int ret = KNOT_EOK;
	size_t chsize = changeset_serialized_size(ch);
	uint32_t serial = knot_soa_serial(&ch->soa_from->rrs);
	uint32_t serial_to = knot_soa_serial(&ch->soa_to->rrs);
	size_t inserted_size = 0;

	int restarted = -1;
	uint8_t * allchunks = NULL;
	uint8_t ** chunkptrs = NULL;
	size_t * chunksizes = NULL;
	knot_db_val_t key, val;
	knot_db_val_t * vals = NULL;

	// PART 1: continuity check
	if (db == j->db && (j->metadata.flags & SERIAL_TO_VALID) && serial_compare(j->metadata.last_serial_to, serial) != 0) {
		log_zone_warning(j->zone_name, "discontinuity in chages history (%u -> %u), dropping older changesets", j->metadata.last_serial_to, serial);
		if (try_flush_allowed) {
			ret = try_flush(j);
			if (ret != KNOT_EOK) goto i_o_ch_free;
		}
		ret = drop_journal(j);
		if (ret != KNOT_EOK) goto i_o_ch_free;
	}

	// PART 2: removing possibly existing duplicite serial
	local_txn_ctx(txn, j);
	if (db == j->db) {
		txn_beg(txn, KNOT_DB_RDONLY);
		make_key2(serial_to, 0, &key);
		if (txn_find(txn, &key, &val, 0)) {
			txn_abort(txn);
			log_zone_warning(j->zone_name, "duplicite changeset serial (%u), dropping older changesets", serial_to);
			if (try_flush_allowed) {
				ret = try_flush(j);
				if (ret != KNOT_EOK) goto i_o_ch_free;
			}
			ret = delete_upto(j, j->db, j->metadata.first_serial, serial_to);
			if (ret != KNOT_EOK) goto i_o_ch_free;

		}
		txn_abort(txn);
	}

	// PART 3: making free space
		size_t free_req_min, free_req, freed = 0;
		check_free_space(j, &free_req, &free_req_min);
		if (freed < free_req_min) {
			ret = delete_tofree(j, free_req, &freed); // delete_tofree is not accurate, but it's enough to keep the the usage levels timid
			if (ret != KNOT_EOK) return ret;
		}
		if (freed < free_req_min && try_flush_allowed) {
			ret = try_flush(j);
			if (ret != KNOT_EOK) return ret; // handles well also EBUSY (=asking zone to flush)
			free_req_min -= freed;
			free_req -= freed;
			ret = delete_tofree(j, free_req, &freed);
			if (ret != KNOT_EOK) return ret;
		}
		if (freed < free_req_min) {
			if (try_flush_allowed) return KNOT_ESPACE;
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
#define i_o_ch_txn_check if (txn->ret != KNOT_EOK) { txn_abort(txn); ret = txn->ret; goto i_o_ch_free; }

	txn_beg_db(txn, db, 0);
	i_o_ch_txn_check
	for (int i = 0; i < chunks; i++) {
		make_key2(serial, i, &key);
		txn_insert(txn, &key, vals+i, 0);
		inserted_size += (vals+i)->len;
		if (txn->ret == KNOT_ELIMIT || // txn full, commit and start over
		    (float) inserted_size > DB_MAX_INSERT_TXN * (float) j->fslimit) { // insert txn too large
			inserted_size = 0;
			restarted = i;
			txn->ret = KNOT_EOK;
			txn_commit(txn);
			i_o_ch_txn_check
			txn_beg_db(txn, db, 0);
			i_o_ch_txn_check
			txn_insert(txn, &key, vals+i, 0);
		}
		i_o_ch_txn_check
	}
	txn_commit(txn);
	i_o_ch_txn_check

	// PART 7: metadata update
	if (db == j->db) {
		if (!(j->metadata.flags & SERIAL_TO_VALID)) j->metadata.first_serial = serial;
		j->metadata.flags |= SERIAL_TO_VALID;
		j->metadata.last_serial = serial;
		j->metadata.last_serial_to = serial_to;
	}
	if (db == j->merged_db) {
		j->metadata.flags |= MERGED_SERIAL_VALID;
		j->metadata.merged_serial = serial;
	}

	// PART 8: cleanup
	i_o_ch_free:

	if (restarted > -1 && ret != KNOT_EOK) { // we failed in the middle of inserting => need to delete the commited part of changeset
		txn_beg_db(txn, db, 0);
		i_o_ch_txn_check
		for (int i = 0; i < restarted; i++) {
			make_key2(serial, i, &key);
			txn_del(txn, &key);
			i_o_ch_txn_check
		}
		txn_commit(txn);
		// TODO: if the server crashes between PART 6 and PART 8, there may remain rubbish in the DB. Please think of a way to clean it occasionally.
		i_o_ch_txn_check
	}

	if (allchunks != NULL) free(allchunks);
	if (chunkptrs != NULL) free(chunkptrs);
	if (chunksizes != NULL) free(chunksizes);
	if (vals != NULL) free(vals);

	return ret;
}

static int insert_merged_changeset(journal_t * j, const changeset_t * mch)
{
	return insert_one_changeset(j, j->merged_db, mch, 0);
}

int journal_store_changeset(journal_t *journal, changeset_t *ch)
{
	return insert_one_changeset(journal, journal->db, ch, 1);
}

int journal_store_changesets(journal_t *journal, list_t *src)
{
	int ret = KNOT_EOK;

	changeset_t *chs = NULL;
	WALK_LIST(chs, *src) {
		ret = journal_store_changeset(journal, chs);
		if (ret != KNOT_EOK) break;
	}
	return ret;
}

/*
 * *************************** PART VIII ******************************
 *
 *  Merge journal
 *
 * ********************************************************************
 */

static int find_first_unflushed(journal_t * j, uint32_t * first)
{
	if (!(j->metadata.flags & LAST_FLUSHED_VALID)) {
		*first = j->metadata.first_serial;
		return KNOT_EOK;
	}

	knot_db_val_t key, val;
	uint32_t lf = j->metadata.last_flushed;
	make_key2(lf, 0, &key);

	local_txn_ctx(txn, j);
	txn_beg(txn, KNOT_DB_RDONLY);
	txn_find_force(txn, &key, &val, 0);
	txn_check_ret(txn);
	unmake_header(&val, first, NULL, NULL, NULL);
	txn_abort(txn);

	if ((j->metadata.flags & SERIAL_TO_VALID) && serial_compare(*first, j->metadata.last_serial_to) == 0) return KNOT_ENOENT;

	return KNOT_EOK;
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
static int merge_journal(journal_t * j)
{
	changeset_t * mch = NULL;
	int ret;

	uint32_t from;
	ret = find_first_unflushed(j, &from);
	if (ret == KNOT_ENOENT) return KNOT_EOK; // journal empty or completely flushed, nothing to do
	if (ret != KNOT_EOK) return ret;

	if ((j->metadata.flags & MERGED_SERIAL_VALID)) {
		ret = load_merged_changeset(j, &mch);
	}
	else { // this is the very first merge. we take the first unmerged changeset as a base and merge the rest to it.
		j->metadata.merged_serial = from;
		j->metadata.flags &= ~MERGED_SERIAL_VALID;

		ret = load_one(j, j->db, from, &mch);
		if (ret == KNOT_EOK) from = knot_soa_serial(&mch->soa_to->rrs);
	}
	if (ret != KNOT_EOK) {
		if (mch != NULL) changeset_free(mch);
		return ret;
	}
	// mch now contains the initial changeset we will merge the other ones to

	delete_merged_changeset(j);
	j->metadata.flags &= ~MERGED_SERIAL_VALID;

	if (serial_compare(from, j->metadata.last_serial) != 0) {
		iteration_ctx_t ctx = { .method = JOURNAL_ITERATION_CHANGESETS, .iter_context = (void *) mch };
		ret = iterate(j, j->db, merge_itercb, &ctx, from, j->metadata.last_serial, KNOT_DB_RDONLY);
	}

	if (ret == KNOT_EOK) ret = insert_merged_changeset(j, mch);
	if (ret == KNOT_EOK) ret = journal_flush(j);
	changeset_free(mch); // in all cases
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

	j->meta_db = j->db;   // those are necessary in order to create the SHARED environment:
	j->merged_db = j->db; // j->db->env == j->meta_db->env, but j->db->dbi != j->meta_db->dbi

	opts.dbname = META_DB_NAME;
	ret = j->db_api->init(&j->meta_db, NULL, &opts);
	if (ret != KNOT_EOK) {
		j->db_api->deinit(j->db);
		return ret;
	}

	opts.dbname = MERGED_DB_NAME;
	ret = j->db_api->init(&j->merged_db, NULL, &opts);
	if (ret != KNOT_EOK) {
		j->db_api->deinit(j->meta_db);
		j->db_api->deinit(j->db);
		return ret;
	}

	ret = load_metadata(j);
	if (ret != KNOT_EOK) {
		j->db_api->deinit(j->meta_db);
		j->db_api->deinit(j->merged_db);
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
			j->db_api->deinit(j->meta_db);
			j->db_api->deinit(j->merged_db);
			j->db_api->deinit(j->db);
			j->db = NULL;
			j->meta_db = NULL;
			j->merged_db = NULL;
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

	return KNOT_EOK;
}

void journal_close(journal_t *j)
{
	if (j == NULL || j->path == NULL) return;

	int ret = store_metadata(j);
	if (ret != KNOT_EOK) {
		log_zone_error(j->zone_name, "unable to store journal metadata");
	}

	j->db_api->deinit(j->meta_db);
	j->db_api->deinit(j->merged_db);
	j->db_api->deinit(j->db);

	free(j->path);
	j->db = NULL;
	j->meta_db = NULL;
	j->merged_db = NULL;
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
		if ((j->metadata.flags & SERIAL_TO_VALID)) {
			jch_print(jch_warn, "SERIAL_TO_VALID is set");
			ret2 = KNOT_ENOENT;
		}
		if ((j->metadata.flags & LAST_FLUSHED_VALID)) {
			jch_print(jch_warn, "LAST_FLUSHED_VALID is set");
			ret2 = KNOT_ENOENT;
		}
		txn_abort(txn);
		goto check_merged;
	}

	if (!(j->metadata.flags & SERIAL_TO_VALID)) {
		jch_print(jch_warn, "SERIAL_TO_VALID is not set");
		ret2 = KNOT_ENOENT;
	}
	ret = load_one(j, j->db, j->metadata.first_serial, &ch);
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
		ret = load_one(j, j->db, nexts, &ch);
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

	txn_beg_jdb(txn, merged_db, KNOT_DB_RDONLY);
	if (txn->ret != KNOT_EOK) {
		jch_print(jch_warn, "merged db cannot be accessed");
		return txn->ret;
	}
	txn_abort(txn);

	ret = load_merged_changeset(j, &ch);
	if (ret == KNOT_EOK && !(j->metadata.flags & MERGED_SERIAL_VALID)) {
		jch_print(jch_warn, "merged changeset found but should not be according to metadata");
	}
	if (ret != KNOT_EOK && (j->metadata.flags & MERGED_SERIAL_VALID)) {
		jch_print(jch_warn, "merged changeset not loadable (%d) but shloud be", ret);
		return ret;
	}
	if (ret == KNOT_EOK) { //no problem otherwise
		soa_from = knot_soa_serial(&ch->soa_from->rrs);
		soa_to = knot_soa_serial(&ch->soa_to->rrs);
		jch_print(jch_info, "note: merged changeset %u -> %u, size %zu", j->metadata.merged_serial, soa_to, changeset_serialized_size(ch));
		if ((j->metadata.flags & LAST_FLUSHED_VALID) && serial_compare(soa_to, last_flushed_soa_to) != 0) {
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
