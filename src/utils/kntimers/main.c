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

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/stat.h>

#include "libknot/libknot.h"
#include "knot/zone/timers.h"
#include "knot/server/server.h"
#include "knot/conf/base.h"
#include "knot/conf/conf.h"
#include "utils/common/params.h"


#define PROGRAM_NAME		"kntimers"

static void help()
{
    printf("Usage: %s [parameter] <journal> [limit]\n"
 	       "\n"
 	       "Parameter:\n"
	       " -c, --config <file>     Use a textual configuration file.\n"
	       "                           (default %s)\n"
	       " -C, --confdb <dir>      Use a binary configuration database directory.\n"
	       "                           (default %s)\n"
	       " -z, --zone <name>       Name of zone to print timers for."
	       " -a, --all               Print timers for all zones"
 	       " -h, --help              Print the program help.\n"
	       " -V, --version           Print the program version"
	   ,PROGRAM_NAME, CONF_DEFAULT_FILE, CONF_DEFAULT_DBDIR);
}

 /*!
  * \brief Make server configuration
  *
  * \param[in] confdb Configuration database or NULL
  * \param[in] config Configuration file or NULL
  * \param[out] conf Server configuration
  *
  * \return KNOT_E
  */
static int make_conf(char *confdb, char *config, conf_t **conf)
{
        if (config != NULL && confdb != NULL) {
        	printf("No configuration source");
		return KNOT_EINVAL;
	}

	/* Choose the optimal config source. */
	struct stat st;
	bool import = false;
	if (confdb != NULL) {
		import = false;
	} else if (config != NULL){
		import = true;
	} else if (stat(CONF_DEFAULT_DBDIR, &st) == 0) {
		import = false;
		confdb = CONF_DEFAULT_DBDIR;
	} else {
		import = true;
		config = CONF_DEFAULT_FILE;
	}

	/* Open confdb. */
	int ret = conf_new(conf, conf_scheme, confdb, CONF_FNONE);
	if (ret != KNOT_EOK) {
		printf("Failed to open configuration database");
		return ret;
	}

	/* Import the config file. */
	if (import) {
		ret = conf_import(*conf, config, true);
		if (ret != KNOT_EOK) {
		        printf("Failed to load configuration file)");
			conf_free(*conf);
			return ret;
		}
	}

	return KNOT_EOK;
}

 /*!
  * \brief Get path to timers database
  *
  * \param conf Configuration
  *
  * \return path to timers database
  */
static char* get_timers_db_path(conf_t *conf)
 {
        char *path;
        conf_val_t val = conf_default_get(conf, C_STORAGE);
	char *storage = conf_abs_path(&val, NULL);
	val = conf_default_get(conf, C_TIMER_DB);
	path = conf_abs_path(&val, storage);

	free(storage);
	return path;
 }

 /*!
  * \brief Print zone timers from timers database
  *
  * \param path Path to timers database
  * \param zone Zone name
  *
  * \return KNOT_E
  */
 static int print_zone_timers(char *path, knot_dname_t *zone)
 {
        knot_db_t *timer_db;
        int ret = open_timers_db(path, &timer_db);

	if (ret == KNOT_EOK) {
	time_t *timers;
	timers = (time_t*) malloc(ZONE_EVENT_COUNT);
	ret = read_zone_timers(timer_db, zone, timers);
		if (ret == KNOT_EOK)
		{
			printf("%s: [\n", knot_dname_to_str(NULL, zone, 0));
			for(int i=0; i<ZONE_EVENT_COUNT-1; ++i) {
				printf("\t%lld,\n", (long long) timers[i]);
			}
			printf("\t%lld\n]\n", (long long) timers[ZONE_EVENT_COUNT-1]);
		}
		else {
			printf("Failed to read timers for zone %s\n", knot_dname_to_str(NULL, zone, 0));
		}
		free(timers);
	}
	else {
		printf("Failed to open timer database\n");
		return ret;
	}

	close_timers_db(timer_db);
	return ret;
 }

 /*!
  * \brief Print timers for all zones
  *
  * \param path Path to timers database
  * \param zone Zone name
  *
  * \return KNOT_E
  */
 static int print_all_timers(char *path, conf_t *conf)
 {
        knot_db_t *timer_db;
        int ret = open_timers_db(path, &timer_db);
	int ret2 = ret;

	if (ret == KNOT_EOK) {
		time_t *timers;
		timers = (time_t*) malloc(ZONE_EVENT_COUNT);
		for (conf_iter_t iter = conf_iter(conf, C_ZONE); iter.code == KNOT_EOK; conf_iter_next(conf, &iter)) {
			conf_val_t id = conf_iter_id(conf, &iter);
			const knot_dname_t *zone = conf_dname(&id);
			ret = read_zone_timers(timer_db, zone, timers);
			if (ret == KNOT_EOK) {
				printf("%s: [\n", knot_dname_to_str(NULL, zone, 0));
				for(int i=0; i<ZONE_EVENT_COUNT-1; ++i) {
				printf("\t%lld,\n", (long long) timers[i]);
				}
			printf("\t%lld\n]\n", (long long) timers[ZONE_EVENT_COUNT-1]);
			}
			else {
				printf("Failed to read timers for zone %s", knot_dname_to_str(NULL, zone, 0));
				ret2 = ret;
  			}
		}
		free(timers);
	}
	else {
		printf("Failed to open timer database\n");
		return ret;
	}

	close_timers_db(timer_db);
	return ret2;
 }

int main(int argc, char **argv)
{
        /* Long options. */
        struct option opts[] = {
		{ "config",    required_argument, NULL, 'c' },
		{ "confdb",    required_argument, NULL, 'C' },
		{ "zone",      required_argument, NULL, 'z' },
 		{ "all",       no_argument, NULL, 'a' },
 		{ "help",      no_argument, NULL, 'h' },
		{ "version",   no_argument, NULL, 'V'},
 		{ NULL }
        };

	char *config = NULL;
	char *confdb = NULL;
	knot_dname_t *zone = NULL;
	bool all = false;

	/* Parse command line arguments. */
	int opt = 0;
 	while ((opt = getopt_long(argc, argv, "c:C:z:ah", opts, NULL)) != -1)
	  {
 		switch (opt) {
		case 'c':
			config = optarg;
			break;
		case 'C':
			confdb = optarg;
			break;
		case 'z':
		        zone = knot_dname_from_str(NULL, optarg, 0);
		        break;
		case 'a':
		        all = true;
		        break;
 		case 'h':
 			help();
 			return EXIT_SUCCESS;
		case 'V':
		  print_version(PROGRAM_NAME);
 		default:
 			help();
 			return EXIT_FAILURE;
		}
	  }
	/* Check for non-option parameters. */
	if (argc - optind > 0) {
		help();
		return EXIT_FAILURE;
	}

	/* Set up the configuration */
	conf_t *conf;
	int ret = make_conf(confdb, config, &conf);
	if (ret != KNOT_EOK) {
		return EXIT_FAILURE;
	}

	/* Get path to timers database*/
 	char *path = get_timers_db_path(conf);
 	if (!path) {
 		fprintf(stderr, "Failed to find timers database\n");
 		return EXIT_FAILURE;
 	}

	/*print timers*/
	if (all) {
		int ret = print_all_timers(path, conf);
		if (ret != KNOT_EOK) {
			free(zone);
			return EXIT_FAILURE;
		}
	}
	else if (zone) {
 		int ret = print_zone_timers(path, zone);
 		if (ret != KNOT_EOK) {
	        	free(zone);
 			return EXIT_FAILURE;
 			}
 		}
 	else {
		printf("No zone specified");
		return EXIT_FAILURE;
	}

 	free(zone);

 	return EXIT_SUCCESS;
}
