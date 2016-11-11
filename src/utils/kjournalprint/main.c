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

#include <stdlib.h>
#include <getopt.h>

#include "libknot/libknot.h"
#include "knot/journal/journal.h"
#include "knot/zone/zone-dump.h"
#include "utils/common/exec.h"
#include "contrib/strtonum.h"

#define PROGRAM_NAME	"kjournalprint"
#define SPACE		"                  "

#define FSLIMIT_INF (1 * 1024 * 1024 * 1024)

#define RED	"\x1B[31m"
#define GRN	"\x1B[32m"
#define RESET	"\x1B[0m"

static void print_help(void)
{
	printf("Usage: %s [parameter] <journal> [limit]\n"
	       "\n"
	       "Parameter:\n"
	       " -n, --no-color"SPACE"Get output without terminal coloring.\n"
	       "Limit:\n"
	       " Read only x newest changes.\n",
	       PROGRAM_NAME);
}

/*!
 * \brief get_rrset Function for better handling rrset buffer
 */
static inline char *get_rrset(knot_rrset_t *rrset, char *buff, int len)
{
	int ret = knot_rrset_txt_dump(rrset, buff, len, &KNOT_DUMP_STYLE_DEFAULT);
	return (ret)? buff : "Corrupted or missing!\n";
}

int print_journal(char *path, int limit, bool color)
{
	list_t db;
	init_list(&db);
	/* Open journal for reading. */
	journal_t *j = journal_new();
	int ret = journal_open(j, path, FSLIMIT_INF, (const knot_dname_t *) "\x0e""fake_zone_name");
	if (ret != KNOT_EOK) return ret;
#define PJ_ERR if (ret != KNOT_EOK) goto pj_finally;

	const knot_dname_t * real_zone_name;
	ret = journal_load_zone_name(j, &real_zone_name);
	if (ret == KNOT_EOK) ret = KNOT_ERROR;
	if (ret == KNOT_ESEMCHECK) ret = KNOT_EOK;
	PJ_ERR

	uint32_t serial_from, serial_to;
	journal_metadata_info(j, &ret, &serial_from, &serial_to);
	ret *= KNOT_ENOENT;
	PJ_ERR

	ret = journal_load_changesets(j, &db, serial_from);
	PJ_ERR

	changeset_t *chs = NULL;
	char buff[8192];
	int i = 0;

	WALK_LIST(chs, db) {
		if (++i >= limit) {
			printf("i=%d limit=%d\n", i, limit);
			break;
		}
		printf(";; %d -> %d\n", knot_soa_serial(&chs->soa_from->rrs), knot_soa_serial(&chs->soa_to->rrs));
		// remove
		printf(color ? RED : "");
		printf("%s", get_rrset(chs->soa_from, buff, 8192));
		zone_dump_text(chs->remove, stdout, false);
		printf(color ? RESET : "");
		// add
		printf(color ? GRN : "");
		printf("%s", get_rrset(chs->soa_to, buff, 8192));
		zone_dump_text(chs->add, stdout, false);
		printf(color ? RESET : "");
	}

	changesets_free(&db);

	pj_finally:
	journal_close(j);
	journal_free(&j);
	free((knot_dname_t *) real_zone_name);
	return ret;
}

int main(int argc, char *argv[])
{
	struct option opts[] = {
		{ "no-color", no_argument, NULL, 'n' },
		{ "help",     no_argument, NULL, 'h' },
		{ "version",  no_argument, NULL, 'V' },
		{ NULL }
	};

	bool color = true;
	int opt = 0;
	while ((opt = getopt_long(argc, argv, "+nhV", opts, NULL)) != -1) {
		switch (opt) {
		case 'n':
			color = false;
			break;
		case 'h':
			print_help();
			return EXIT_SUCCESS;
		case 'V':
			print_version(PROGRAM_NAME);
			return EXIT_SUCCESS;
		default:
			print_help();
			return EXIT_FAILURE;
		}
	}
	char *db;
	int param = INT_MAX;
	switch (argc - optind) {
	case 2:
		if (str_to_int(argv[optind + 1], &param) != KNOT_EOK) {
			print_help();
			return EXIT_FAILURE;
		}
	case 1:
		db = argv[optind];
		break;
	default:
		print_help();
		return EXIT_FAILURE;
	}

	int ret = print_journal(db, param, color);
	if (ret == KNOT_ENOENT) {
		printf("0 records in journal\n");
	} else if (ret != KNOT_EOK) {
		fprintf(stderr, "Failed to load changesets (%s)\n", knot_strerror(ret));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
