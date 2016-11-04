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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <tap/basic.h>
#include <tap/files.h>

#include "libknot/libknot.h"
#define JOURNAL_TEST_ENV
#include "knot/journal/journal.c"
#include "knot/zone/zone.h"
#include "knot/zone/zone-diff.h"
#include "libknot/rrtype/soa.h"
#include "test_conf.h"

#define RAND_RR_LABEL 16
#define RAND_RR_PAYLOAD 64
#define MIN_SOA_SIZE 22

/*! \brief Generate random string with given length. */
static int randstr(char* dst, size_t len)
{
	for (int i = 0; i < len - 1; ++i) {
		dst[i] = '0' + (int) (('Z'-'0') * (rand() / (RAND_MAX + 1.0)));
	}
	dst[len - 1] = '\0';

	return 0;
}

/*! \brief Init RRSet with type SOA and given serial. */
static void init_soa(knot_rrset_t *rr, const uint32_t serial, const knot_dname_t *apex)
{
	knot_rrset_init(rr, knot_dname_copy(apex, NULL), KNOT_RRTYPE_SOA, KNOT_CLASS_IN);

	//assert(serial < 256);
	uint8_t soa_data[MIN_SOA_SIZE] = { 0 };
	int ret = knot_rrset_add_rdata(rr, soa_data, sizeof(soa_data), 3600, NULL);
	knot_soa_serial_set(&rr->rrs, serial);
	(void)ret;
	assert(ret == KNOT_EOK);
}

/*! \brief Init RRSet with type TXT, random owner and random payload. */
static void init_random_rr(knot_rrset_t *rr , const knot_dname_t *apex)
{
	/* Create random label. */
	char owner[RAND_RR_LABEL + knot_dname_size(apex)];
	owner[0] = RAND_RR_LABEL - 1;
	randstr(owner + 1, RAND_RR_LABEL);

	/* Append zone apex. */
	memcpy(owner + RAND_RR_LABEL, apex, knot_dname_size(apex));
	knot_rrset_init(rr, knot_dname_copy((knot_dname_t *)owner, NULL),
			KNOT_RRTYPE_TXT, KNOT_CLASS_IN);

	/* Create random RDATA. */
	uint8_t txt[RAND_RR_PAYLOAD + 1];
	txt[0] = RAND_RR_PAYLOAD - 1;
	randstr((char *)(txt + 1), RAND_RR_PAYLOAD);

	int ret = knot_rrset_add_rdata(rr, txt, RAND_RR_PAYLOAD, 3600, NULL);
	(void)ret;
	assert(ret == KNOT_EOK);
}

/*! \brief Init changeset with random changes. */
static void init_random_changeset(changeset_t *ch, const uint32_t from, const uint32_t to, const size_t size, const knot_dname_t *apex)
{
	int ret = changeset_init(ch, apex);
	(void)ret;
	assert(ret == KNOT_EOK);

	// Add SOAs
	knot_rrset_t soa;
	init_soa(&soa, from, apex);

	ch->soa_from = knot_rrset_copy(&soa, NULL);
	assert(ch->soa_from);
	knot_rrset_clear(&soa, NULL);

	init_soa(&soa, to, apex);
	ch->soa_to = knot_rrset_copy(&soa, NULL);
	assert(ch->soa_to);
	knot_rrset_clear(&soa, NULL);

	// Add RRs to add section
	for (size_t i = 0; i < size / 2; ++i) {
		knot_rrset_t rr;
		init_random_rr(&rr, apex);
		int ret = changeset_add_addition(ch, &rr, 0);
		(void)ret;
		assert(ret == KNOT_EOK);
		knot_rrset_clear(&rr, NULL);
	}

	// Add RRs to remove section
	for (size_t i = 0; i < size / 2; ++i) {
		knot_rrset_t rr;
		init_random_rr(&rr, apex);
		int ret = changeset_add_removal(ch, &rr, 0);
		(void)ret;
		assert(ret == KNOT_EOK);
		knot_rrset_clear(&rr, NULL);
	}
}

static void changeset_set_soa_serials(changeset_t *ch, uint32_t from, uint32_t to,
				      const knot_dname_t *apex)
{
	knot_rrset_t soa;

	init_soa(&soa, from, apex);
	knot_rrset_free(&ch->soa_from, NULL);
	ch->soa_from = knot_rrset_copy(&soa, NULL);
	assert(ch->soa_from);
	knot_rrset_clear(&soa, NULL);

	init_soa(&soa, to, apex);
	knot_rrset_free(&ch->soa_to, NULL);
	ch->soa_to = knot_rrset_copy(&soa, NULL);
	assert(ch->soa_to);
	knot_rrset_clear(&soa, NULL);
}

/*! \brief Compare two changesets for equality. */
static bool changesets_eq(const changeset_t *ch1, changeset_t *ch2)
{
	if (changeset_size(ch1) != changeset_size(ch2)) {
		return false;
	}

	changeset_iter_t it1;
	changeset_iter_all(&it1, ch1);
	changeset_iter_t it2;
	changeset_iter_all(&it2, ch2);

	knot_rrset_t rr1 = changeset_iter_next(&it1);
	knot_rrset_t rr2 = changeset_iter_next(&it2);
	bool ret = true;
	while (!knot_rrset_empty(&rr1)) {
		if (!knot_rrset_equal(&rr1, &rr2, KNOT_RRSET_COMPARE_WHOLE)) {
			ret = false;
			break;
		}
		rr1 = changeset_iter_next(&it1);
		rr2 = changeset_iter_next(&it2);
	}

	changeset_iter_clear(&it1);
	changeset_iter_clear(&it2);

	return ret;
}

static bool changesets_list_eq(list_t *l1, list_t *l2)
{
	node_t *n = NULL;
	node_t *k = HEAD(*l2);
	WALK_LIST(n, *l1) {
		if (k == NULL) {
			return false;
		}

		changeset_t *ch1 = (changeset_t *) n;
		changeset_t *ch2 = (changeset_t *) k;
		if (!changesets_eq(ch1, ch2)) {
			return false;
		}

		k = k->next;
	}

	if (k->next != NULL) {
		return false;
	}

	return true;
}

/*! \brief Test a list of changesets for continuity. */
static bool test_continuity(list_t *l)
{
	node_t *n = NULL;
	uint32_t key1, key2;
	WALK_LIST(n, *l) {
		if (n == TAIL(*l)) {
			break;
		}
		changeset_t *ch1 = (changeset_t *) n;
		changeset_t *ch2 = (changeset_t *) n->next;
		key1 = knot_soa_serial(&ch1->soa_to->rrs);
		key2 = knot_soa_serial(&ch2->soa_from->rrs);
		if (key1 != key2) {
			return KNOT_EINVAL;
		}
	}

	return KNOT_EOK;
}

/*! \brief Test behavior with real changesets. */
static void test_store_load(journal_t *j, char *jfilename)
{
	/*\todo: set this to something >1MiB, as we need to test setting smaller mapsizes. */
	const size_t filesize = 2 * 1024 * 1024;
	uint8_t *apex = (uint8_t *)"\4test";
	int ret = journal_open(j, jfilename, filesize, apex);

	/* Save and load changeset. */
	changeset_t *m_ch = changeset_new(apex);
	init_random_changeset(m_ch, 0, 1, 128, apex);
	ret = journal_store_changeset(j, m_ch);
	ok(ret == KNOT_EOK, "journal: store changeset");
	ret = journal_check(j, KNOT_JOURNAL_CHECK_SILENT);
	ok(ret == KNOT_EOK, "journal check");
	list_t l, k;
	init_list(&l);
	init_list(&k);
	ret = journal_load_changesets(j, &l, 0);
	add_tail(&k, &m_ch->n);
	ok(ret == KNOT_EOK && changesets_list_eq(&l, &k), "journal: load changeset");
	ret = journal_check(j, KNOT_JOURNAL_CHECK_SILENT);
	ok(ret == KNOT_EOK, "journal check");

	changesets_free(&l);
	changeset_free(m_ch);
	/* Flush the journal. */
	ret = journal_flush(j);
	ok(ret == KNOT_EOK, "journal: first and simple flush");
	ret = journal_check(j, KNOT_JOURNAL_CHECK_SILENT);
	ok(ret == KNOT_EOK, "journal check");
	init_list(&l);
	init_list(&k);

	/* Fill the journal. */
	ret = KNOT_EOK;
	uint32_t serial = 1;
	for (; ret == KNOT_EOK; ++serial) {
		m_ch = changeset_new(apex);
		init_random_changeset(m_ch, serial, serial + 1, 128, apex);
		ret = journal_store_changeset(j, m_ch);
		if (ret != KNOT_EOK) {
			changeset_free(m_ch);
			break;
		}
		add_tail(&k, &m_ch->n);
	}
	ok(ret == KNOT_EBUSY, "journal: overfill with changesets (%d inserted)", serial);
	ret = journal_check(j, KNOT_JOURNAL_CHECK_SILENT);
	ok(ret == KNOT_EOK, "journal check");

	/* Load all changesets stored until now. */
	ret = journal_load_changesets(j, &l, 1);
	ok(ret == KNOT_EOK, "journal: load changesets EOK");
	ok(changesets_list_eq(&l, &k), "journal: load changesets eq");

	changesets_free(&l);
	init_list(&l);
	ret = journal_load_changesets(j, &l, 1);
	ok(ret == KNOT_EOK && changesets_list_eq(&l, &k), "journal: re-load changesets");

	changesets_free(&l);
	init_list(&l);

	/* Flush the journal. */
	ret = journal_flush(j);
	ok(ret == KNOT_EOK, "journal: second flush");
	ret = journal_check(j, KNOT_JOURNAL_CHECK_SILENT);
	ok(ret == KNOT_EOK, "journal check");

	/* Test whether the journal kept changesets after flush. */
	ret = journal_load_changesets(j, &l, 1);
	ok(ret == KNOT_EOK && changesets_list_eq(&l, &k), "journal: load right after flush");

	changesets_free(&k);
	changesets_free(&l);
	init_list(&k);
	init_list(&l);

	/* Store next changeset. */
	changeset_t ch;
	changeset_init(&ch, apex);
	init_random_changeset(&ch, serial, serial + 1, 128, apex);
	ret = journal_store_changeset(j, &ch);
		changeset_clear(&ch);
	ok(ret == KNOT_EOK, "journal: store after flush");
	ret = journal_check(j, KNOT_JOURNAL_CHECK_SILENT);
	ok(ret == KNOT_EOK, "journal check");

	/* Load last changesets. */
	init_list(&l);
	ret = journal_load_changesets(j, &l, serial);
	changesets_free(&l);
	ok(ret == KNOT_EOK, "journal: load changesets after flush");

	/* Flush the journal again. */
	ret = journal_flush(j);
	ok(ret == KNOT_EOK, "journal: flush again");
	ret = journal_check(j, KNOT_JOURNAL_CHECK_SILENT);
	ok(ret == KNOT_EOK, "journal check");

	/* Fill the journal using a list. */
	uint32_t m_serial = 1;
	for (; m_serial < serial / 2; ++m_serial) {
		m_ch = changeset_new(apex);
		init_random_changeset(m_ch, m_serial, m_serial + 1, 128, apex);
		add_tail(&l, &m_ch->n);
	}
	ret = journal_store_changesets(j, &l);
	ok(ret == KNOT_EOK, "journal: fill with changesets using a list (%d inserted)", m_serial);
	ret = journal_check(j, KNOT_JOURNAL_CHECK_SILENT);
	ok(ret == KNOT_EOK, "journal check");

	/* Cleanup. */
	changesets_free(&l);
	init_list(&l);

	/* Load all previous changesets. */
	ret = journal_load_changesets(j, &l, 1);
	ok(ret == KNOT_EOK && knot_soa_serial(&((changeset_t *)TAIL(l))->soa_to->rrs) == m_serial,
	   "journal: load all changesets");

	/* Check for changeset ordering. */
	ok(test_continuity(&l) == KNOT_EOK, "journal: changesets are in order");

	/* Cleanup. */
	changesets_free(&l);
	init_list(&l);
	assert(journal_flush(j) == KNOT_EOK);
	assert(drop_journal(j) == KNOT_EOK); /* Clear the journal for the collision test */

	/* Test for serial number collision handling. We insert changesets
	 * with valid serial sequence that overflows and then collides with itself.
	 * The sequence is 0 -> 1 -> 2 -> 2147483647 -> 4294967294 -> 1 which should
	 * remove changesets 0->1 and 1->2. */
	m_ch = changeset_new(apex);
	init_random_changeset(m_ch, 0, 1, 128, apex);
	assert(journal_store_changeset(j, m_ch) == KNOT_EOK);
	changeset_set_soa_serials(m_ch, 1, 2, apex);
	assert(journal_store_changeset(j, m_ch) == KNOT_EOK);
	changeset_set_soa_serials(m_ch, 2, 2147483647, apex);
	add_tail(&k, &m_ch->n);
	assert(journal_store_changeset(j, m_ch) == KNOT_EOK);
	m_ch = changeset_new(apex);
	init_random_changeset(m_ch, 2147483647, 4294967294, 128, apex);
	add_tail(&k, &m_ch->n);
	assert(journal_store_changeset(j, m_ch) == KNOT_EOK);
	m_ch = changeset_new(apex);
	init_random_changeset(m_ch, 4294967294, 1, 128, apex);
	add_tail(&k, &m_ch->n);
	assert(journal_store_changeset(j, m_ch) == KNOT_EBUSY);
	assert(journal_flush(j) == KNOT_EOK);
	assert(journal_store_changeset(j, m_ch) == KNOT_EOK);
	assert(journal_flush(j) == KNOT_EOK);
	ret = journal_load_changesets(j, &l, 0);
	int ret2 = journal_load_changesets(j, &l, 1);
	int ret3 = journal_load_changesets(j, &l, 2);
	ok(ret == KNOT_ENOENT && ret2 == KNOT_ENOENT && ret3 == KNOT_EOK &&
	   changesets_list_eq(&l, &k), "journal: serial collision");
	ret = journal_check(j, KNOT_JOURNAL_CHECK_SILENT);
	ok(ret == KNOT_EOK, "journal check");

	/* Cleanup. */
	changesets_free(&l);
	changesets_free(&k);
	init_list(&l);
	init_list(&k);

	journal_close(j);
}

const uint8_t * rdA = (const uint8_t *) "\x01\x02\x03\x04", * rdB = (const uint8_t *) "\x01\x02\x03\x05", * rdC = (const uint8_t *) "\x01\x02\x03\x06";

static knot_rrset_t * tm_rrset(const knot_dname_t * owner, const uint8_t * rdata)
{
	knot_rrset_t * rrs = knot_rrset_new(owner, KNOT_RRTYPE_A, KNOT_CLASS_IN, NULL);
	knot_rrset_add_rdata(rrs, rdata, 4, 3600, NULL);
	return rrs;
}

static knot_dname_t * tm_owner(const char * prefix, const knot_dname_t *apex)
{
	knot_dname_t * ret = malloc(strlen(prefix) + knot_dname_size(apex) + 2);
	ret[0] = strlen(prefix);
	strcpy((char *) (ret + 1), prefix);
	memcpy(ret + ret[0] + 1, apex, knot_dname_size(apex));
	return ret;
}

static knot_rrset_t * tm_rrs(const knot_dname_t * apex, int x)
{
	static knot_rrset_t * rrsA = NULL;
	static knot_rrset_t * rrsB = NULL;
	static knot_rrset_t * rrsC = NULL;
	if (rrsA == NULL) rrsA = tm_rrset(tm_owner("aaaaaaaaaaaaaaaaa", apex), rdA);
	if (rrsB == NULL) rrsB = tm_rrset(tm_owner("bbbbbbbbbbbbbbbbb", apex), rdB);
	if (rrsC == NULL) rrsC = tm_rrset(tm_owner("ccccccccccccccccc", apex), rdC);
	switch ((x % 3 + 3) % 3) {
	case 0: return rrsA;
	case 1: return rrsB;
	case 2: return rrsC;
	}
	assert(0); return NULL;
}

int tm_rrcnt(const changeset_t * ch, int flg)
{
	changeset_iter_t it;
	int i = 0;
	if (flg >= 0) changeset_iter_add(&it, ch);
	else changeset_iter_rem(&it, ch);

	knot_rrset_t rri;
	while (rri = changeset_iter_next(&it), !knot_rrset_empty(&rri)) i++;
	return i;
}

static changeset_t * tm_chs(const knot_dname_t * apex, int x)
{
	static changeset_t * chsI = NULL, * chsX = NULL, * chsY = NULL;
	static uint32_t serial = 0;
	//int err;
//#define tm_chs_check(what) if ((err = (what)) != KNOT_EOK) printf("error: %s returned %d\n", #what, err)
#define tm_chs_check(what) (what)

	if (chsI == NULL) {
		chsI = changeset_new(apex);
		assert(chsI != NULL);
		tm_chs_check(changeset_add_addition(chsI, tm_rrs(apex, 0), 0));
		tm_chs_check(changeset_add_addition(chsI, tm_rrs(apex, 1), 0));
	}
	if (chsX == NULL) {
		chsX = changeset_new(apex);
		assert(chsX != NULL);
		tm_chs_check(changeset_add_removal(chsX, tm_rrs(apex, 1), 0));
		tm_chs_check(changeset_add_addition(chsX, tm_rrs(apex, 2), 0));
	}
	if (chsY == NULL) {
		chsY = changeset_new(apex);
		assert(chsY != NULL);
		tm_chs_check(changeset_add_removal(chsY, tm_rrs(apex, 2), 0));
		tm_chs_check(changeset_add_addition(chsY, tm_rrs(apex, 1), 0));
	}
	assert(x >= 0);
	changeset_t * ret;
	if (x == 0) ret = chsI;
	else if (x % 2 == 1) ret = chsX;
	else ret = chsY;

	changeset_set_soa_serials(ret, serial, serial + 1, apex);
	serial++;

	return ret;
}

static void test_merge(journal_t * j, const char * fname)
{
	const size_t filesize = 4 * 1024 * 1024;
	uint8_t *apex = (uint8_t *)"\4test";
	int ret = journal_open(j, fname, filesize, apex);
	assert(ret == KNOT_EOK);
	int i;
	list_t l;

	// allow merge
	const char *conf_str =
		"zone:\n"
		"  - domain: test\n"
		"    zonefile-sync: -1\n";
	ret = test_conf(conf_str, NULL);
	assert(ret == KNOT_EOK);
	ok(merge_allowed(j), "journal: merge allowed");

	ret = drop_journal(j);
	assert(ret == KNOT_EOK);

	// insert stuff and check the merge
	for (i = 0; !(j->metadata.flags & MERGED_SERIAL_VALID); i++) {
		ret = journal_store_changeset(j, tm_chs(apex, i));
	}
	init_list(&l);
	ret = journal_load_changesets(j, &l, 0);
	ok(list_size(&l) == 2, "journal: read the merged and one following");
	changeset_t * mch = (changeset_t *)HEAD(l);
	ok(list_size(&l) >= 1 && tm_rrcnt(mch, 1) == 2, "journal: merged additions # = 2");
	ok(list_size(&l) >= 1 && tm_rrcnt(mch, -1) == 1, "journal: merged removals # = 1");
	changesets_free(&l);

	// insert one more and check the #s of results
	journal_store_changeset(j, tm_chs(apex, i));
	init_list(&l);
	ret = journal_load_changesets(j, &l, 0);
	ok(list_size(&l) == 3, "journal: read merged together with new changeset");
	changesets_free(&l);
	init_list(&l);
	ret = journal_load_changesets(j, &l, (uint32_t) (i - 3));
	ok(list_size(&l) == 4, "journal: read short history of merged/unmerged changesets");

	ret = drop_journal(j);
	assert(ret == KNOT_EOK);

	// disallow merge
	const char *conf_str2 =
		"zone:\n"
		"  - domain: test\n"
		"    zonefile-sync: 10\n";
	ret = test_conf(conf_str2, NULL);
	assert(ret == KNOT_EOK);
	ok(!merge_allowed(j), "journal: merge disallowed");

	journal_close(j);
}

static void test_stress_base(journal_t *j, char *jfilename, size_t update_size, size_t file_size)
{
	int ret;
	const uint8_t *apex = (uint8_t *)"\4test";
	uint32_t serial = 0;

	changeset_t ch;
	changeset_init(&ch, apex);
	init_random_changeset(&ch, serial, serial + 1, update_size, apex);

	for (int i = 1; i <= 6; ++i) {
		serial = 0;
		ret = journal_open(j, jfilename, file_size, apex);
		assert(ret == KNOT_EOK);
		while (true) {
			changeset_set_soa_serials(&ch, serial, serial + 1, apex);
			ret = journal_store_changeset(j, &ch);

			if (ret != KNOT_EOK) fprintf(stderr, "store failed %d serial=%d (espace=%d ebusy=%d)\n", ret, serial, KNOT_ESPACE, KNOT_EBUSY);


			if (ret == KNOT_EOK) {
				serial++;
			} else {
				break;
			}
		}

		int ret = journal_flush(j);
		journal_close(j);
		ok(serial > 0 && ret == KNOT_EOK, "journal: pass #%d fillup run (%d inserts)", i, serial);
	}

	changeset_clear(&ch);
}


/*! \brief Test behavior when writing to jurnal and flushing it. */
static void test_stress(journal_t *j, char *jfilename)
{
	printf("stress test: small data\n");
	test_stress_base(j, jfilename, 40, 1024 * 1024 / 2);

	printf("stress test: medium data\n");
	test_stress_base(j, jfilename, 400, 2 * 1024 * 1024);

	printf("stress test: large data\n");
	test_stress_base(j, jfilename, 4000, 10 * 1024 * 1024);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	const uint8_t *apex = (uint8_t *)"\4test";

	/* Create tmpdir */
	char *jfilename = test_mkdtemp();
	ok(jfilename != NULL, "make temporary directory");

	journal_t *j = journal_new();
	assert(j);

	/* Try to open journal with too small fsize. */
	int ret = journal_open(j, jfilename, 1024, apex);
	ok(ret == KNOT_EOK, "journal: open too small");
	journal_close(j);

	/* Open/create new journal. */
	ret = journal_open(j, jfilename, 10 * 1024 * 1024, apex);
	ok(ret == KNOT_EOK, "journal: open journal '%s'", jfilename);
	if (j == NULL) {
		goto skip_all;
	}

	/* Close journal. */
	journal_close(j);

	test_store_load(j, jfilename);

	test_merge(j, jfilename);

	test_stress(j, jfilename);

	journal_free(&j);

	/* Delete journal. */
	test_rm_rf(jfilename);
	free(jfilename);

skip_all:
	return 0;
}
