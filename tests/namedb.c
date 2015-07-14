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

#include <dirent.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>
#include <tap/basic.h>

#include "libknot/internal/mempool.h"
#include "libknot/internal/mem.h"
#include "libknot/internal/namedb/namedb_lmdb.h"
#include "libknot/internal/namedb/namedb_trie.h"
#include "libknot/internal/strlcpy.h"
#include "libknot/libknot.h"

/* Constants. */
#define KEY_MAXLEN 64
#define KEY_SET(key, str) key.data = (str); key.len = strlen(str) + 1

/*! \brief Generate random key. */
static const char *alphabet = "abcdefghijklmn0123456789";
static char *str_key_rand(size_t len, mm_ctx_t *pool)
{
	char *s = mm_alloc(pool, len);
	memset(s, 0, len);
	for (unsigned i = 0; i < len - 1; ++i) {
		s[i] = alphabet[rand() % strlen(alphabet)];
	}
	return s;
}

/* UCW array sorting defines. */
#define ASORT_PREFIX(X) str_key_##X
#define ASORT_KEY_TYPE char*
#define ASORT_LT(x, y) (strcmp((x), (y)) < 0)
#include "libknot/internal/array-sort.h"

static void namedb_test_set(unsigned nkeys, char **keys, namedb_ctx_t *db)
{
//	if (api == NULL) {
//		skip("API not compiled in");
//		return;
//	}



	/* Start WR transaction. */
	namedb_txn_t txn;
	int ret = namedb_begin_txn(db, &txn, 0);
	ok(ret == KNOT_EOK, "%s: txn_begin(WR)", db->api->name);

	/* Insert keys */
	namedb_val_t key, val;
	bool passed = true;
	for (unsigned i = 0; i < nkeys; ++i) {
		KEY_SET(key, keys[i]);
		val.len = sizeof(void*);
		val.data = &key.data;

		ret = namedb_insert(db, &txn, &key, &val, 0);
		if (ret != KNOT_EOK && ret != KNOT_EEXIST) {
			passed = false;
			break;
		}
	}
	ok(passed, "%s: insert", db->api->name);

	/* Commit WR transaction. */
	ret = namedb_commit_txn(db, &txn);
	ok(ret == KNOT_EOK, "%s: txn_commit(WR)", db->api->name);

	/* Start RD transaction. */
	ret = namedb_begin_txn(db, &txn, NAMEDB_RDONLY);
	ok(ret == KNOT_EOK, "%s: txn_begin(RD)", db->api->name);

	/* Lookup all keys */
	passed = true;
	for (unsigned i = 0; i < nkeys; ++i) {
		KEY_SET(key, keys[i]);

		ret = namedb_find(db, &txn, &key, &val, 0);
		if (ret != KNOT_EOK) {
			passed = false;
			break;
		}

		const char **stored_key = val.data;
		if (strcmp(*stored_key, keys[i]) != 0) {
			diag("%s: mismatch on element '%u'", db->api->name, i);
			passed = false;
			break;
		}
	}
	ok(passed, "%s: lookup all keys", db->api->name);

	/* Fetch dataset size. */
	int db_size = namedb_count(db, &txn);
	ok(db_size > 0 && db_size <= nkeys, "%s: count %d", db->api->name, db_size);

	/* Unsorted iteration */
	int iterated = 0;
	namedb_iter_t *it = namedb_begin_iter(db, &txn, 0);
	while (it != NULL) {
		++iterated;
		it = namedb_next_iter(db, it);
	}
	namedb_finish_iter(db, it);
	is_int(db_size, iterated, "%s: unsorted iteration", db->api->name);

	/* Sorted iteration. */
	char first_key[KEY_MAXLEN] = { '\0' };
	char second_key[KEY_MAXLEN] = { '\0' };
	char last_key[KEY_MAXLEN] = { '\0' };
	char key_buf[KEY_MAXLEN] = {'\0'};
	iterated = 0;
	memset(&key, 0, sizeof(key));
	it = namedb_begin_iter(db, &txn, NAMEDB_SORTED);
	while (it != NULL) {
		namedb_key_iter(db, it, &key);
		if (iterated > 0) { /* Only if previous exists. */
			if (strcmp(key_buf, key.data) > 0) {
				diag("%s: iter_sort '%s' <= '%s' FAIL\n",
				     db->api->name, key_buf, (const char *)key.data);
				break;
			}
			if (iterated == 1) {
				memcpy(second_key, key.data, key.len);
			}
		} else {
			memcpy(first_key, key.data, key.len);
		}
		++iterated;
		memcpy(key_buf, key.data, key.len);
		it = namedb_next_iter(db, it);
	}
	strlcpy(last_key, key_buf, sizeof(last_key));
	is_int(db_size, iterated, "%s: sorted iteration", db->api->name);
	namedb_finish_iter(db, it);

	/* Interactive iteration. */
	it = namedb_begin_iter(db, &txn, NAMEDB_NOOP);
	if (it != NULL) { /* If supported. */
		ret = 0;
		/* Check if first and last keys are reachable */
		it = namedb_seek_iter(db, it, NULL, NAMEDB_FIRST);
		ret += namedb_key_iter(db, it, &key);
		is_string(first_key, key.data, "%s: iter_set(FIRST)", db->api->name);
		/* Check left/right iteration. */
		it = namedb_seek_iter(db, it, &key, NAMEDB_NEXT);
		ret += namedb_key_iter(db, it, &key);
		is_string(second_key, key.data, "%s: iter_set(NEXT)", db->api->name);
		it = namedb_seek_iter(db, it, &key, NAMEDB_PREV);
		ret += namedb_key_iter(db, it, &key);
		is_string(first_key, key.data, "%s: iter_set(PREV)", db->api->name);
		it = namedb_seek_iter(db, it, &key, NAMEDB_LAST);
		ret += namedb_key_iter(db, it, &key);
		is_string(last_key, key.data, "%s: iter_set(LAST)", db->api->name);
		/* Check if prev(last_key + 1) is the last_key */
		strlcpy(key_buf, last_key, sizeof(key_buf));
		key_buf[0] += 1;
		KEY_SET(key, key_buf);
		it = namedb_seek_iter(db, it, &key, NAMEDB_LEQ);
		ret += namedb_key_iter(db, it, &key);
		is_string(last_key, key.data, "%s: iter_set(LEQ)", db->api->name);
		/* Check if next(first_key - 1) is the first_key */
		strlcpy(key_buf, first_key, sizeof(key_buf));
		key_buf[0] -= 1;
		KEY_SET(key, key_buf);
		it = namedb_seek_iter(db, it, &key, NAMEDB_GEQ);
		ret += namedb_key_iter(db, it, &key);
		is_string(first_key, key.data, "%s: iter_set(GEQ)", db->api->name);
		namedb_finish_iter(db, it);
		is_int(ret, 0, "%s: iter_* error codes", db->api->name);
	}
	namedb_abort_txn(db, &txn);

	/* Clear database and recheck. */
	ret =  namedb_begin_txn(db, &txn, 0);
	ret += namedb_clear(db, &txn);
	ret += namedb_commit_txn(db, &txn);
	is_int(0, ret, "%s: clear()", db->api->name);

	/* Check if the database is empty. */
	namedb_begin_txn(db, &txn, NAMEDB_RDONLY);
	db_size = namedb_count(db, &txn);
	is_int(0, db_size, "%s: count after clear = %d", db->api->name, db_size);
	namedb_abort_txn(db, &txn);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	mm_ctx_t pool;
	mm_ctx_mempool(&pool, MM_DEFAULT_BLKSIZE);

	/* Temporary DB identifier. */
	char dbid_buf[] = "/tmp/namedb.XXXXXX";
	char *dbid = mkdtemp(dbid_buf);

	/* Random keys. */
	unsigned nkeys = 10000;
	char **keys = mm_alloc(&pool, sizeof(char*) * nkeys);
	for (unsigned i = 0; i < nkeys; ++i) {
		keys[i] = str_key_rand(KEY_MAXLEN, &pool);
	}

	/* Sort random keys. */
	str_key_sort(keys, nkeys);

	/* Execute test set for all backends. */
	struct namedb_lmdb_opts lmdb_opts = NAMEDB_LMDB_OPTS_INITIALIZER;
	lmdb_opts.path = dbid;
	struct namedb_trie_opts trie_opts = NAMEDB_TRIE_OPTS_INITIALIZER;

	/* Create database LMDB*/
	namedb_ctx_t db;
	int ret = namedb_init_lmdb(&db, &pool, &lmdb_opts);
	ok(ret == KNOT_EOK && db.api != NULL, "%s: create", db.api->name);
	namedb_test_set(nkeys, keys, &db);
	namedb_deinit(&db);
	/* Create database TRIE*/
	ret = namedb_init_trie(&db, &pool, &trie_opts);
	ok(ret == KNOT_EOK && db.api != NULL, "%s: create", db.api->name);
	namedb_test_set(nkeys, keys, &db);
	namedb_deinit(&db);

	/* Cleanup. */
	mp_delete(pool.ctx);

	/* Cleanup temporary DB. */
	DIR *dir = opendir(dbid);
	struct dirent *dp;
	while ((dp = readdir(dir)) != NULL) {
		if (dp->d_name[0] == '.') {
			continue;
		}
		char *file = sprintf_alloc("%s/%s", dbid, dp->d_name);
		remove(file);
		free(file);
	}
	closedir(dir);
	remove(dbid);

	return 0;
}
