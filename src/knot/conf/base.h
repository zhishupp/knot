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
/*!
 * \file
 *
 * Server configuration core.
 *
 * \addtogroup config
 *
 * @{
 */

#pragma once

#include "libknot/libknot.h"
#include "libknot/yparser/ypscheme.h"
#include "contrib/hat-trie/hat-trie.h"
#include "contrib/ucw/lists.h"

/*! Default template identifier. */
#define CONF_DEFAULT_ID		((uint8_t *)"\x08""default\0")
/*! Default configuration file. */
#define CONF_DEFAULT_FILE	(CONFIG_DIR "/knot.conf")
/*! Default configuration database. */
#define CONF_DEFAULT_DBDIR	(STORAGE_DIR "/confdb")
/*! Maximum depth of nested transactions. */
#define CONF_MAX_TXN_DEPTH	5

/*! Configuration specific logging. */
#define CONF_LOG(severity, msg, ...) do { \
	log_msg(severity, "config, " msg, ##__VA_ARGS__); \
	} while (0)

#define CONF_LOG_ZONE(severity, zone, msg, ...) do { \
	log_msg_zone(severity, zone, "config, " msg, ##__VA_ARGS__); \
	} while (0)

/*! Configuration getter output. */
typedef struct {
	/*! Item description. */
	const yp_item_t *item;
	/*! Whole data (can be array). */
	const uint8_t *blob;
	/*! Whole data length. */
	size_t blob_len;
	// Public items.
	/*! Current single data. */
	const uint8_t *data;
	/*! Current single data length. */
	size_t len;
	/*! Value getter return code. */
	int code;
} conf_val_t;

/*! Configuration context. */
typedef struct {
	/*! Cloned configuration indicator. */
	bool is_clone;
	/*! Currently used namedb api. */
	const struct knot_db_api *api;
	/*! Configuration scheme. */
	yp_item_t *scheme;
	/*! Memory context. */
	knot_mm_t *mm;
	/*! Configuration database. */
	knot_db_t *db;

	/*! Read-only transaction for config access. */
	knot_db_txn_t read_txn;

	struct {
		/*! The current writing transaction. */
		knot_db_txn_t *txn;
		/*! Stack of nested writing transactions. */
		knot_db_txn_t txn_stack[CONF_MAX_TXN_DEPTH];
		/*! Master transaction flags. */
		yp_flag_t flags;
		/*! Changed zones. */
		hattrie_t *zones;
	} io;

	/*! Current config file (for reload if started with config file). */
	char *filename;

	/*! Prearranged hostname string (for automatic NSID or CH ident value). */
	char *hostname;

	/*! Cached critical confdb items. */
	struct {
		int16_t srv_max_ipv4_udp_payload;
		int16_t srv_max_ipv6_udp_payload;
		int32_t srv_tcp_hshake_timeout;
		int32_t srv_tcp_idle_timeout;
		int32_t srv_tcp_reply_timeout;
		int32_t srv_max_tcp_clients;
		int32_t srv_rate_limit_slip;
		int32_t ctl_timeout;
		conf_val_t srv_nsid;
		conf_val_t srv_rate_limit_whitelist;
	} cache;

	/*! List of active query modules. */
	list_t query_modules;
	/*! Default query modules plan. */
	struct query_plan *query_plan;
} conf_t;

/*!
 * Configuration access flags.
 */
typedef enum {
	CONF_FNONE        = 0,      /*!< Empty flag. */
	CONF_FREADONLY    = 1 << 0, /*!< Read only access. */
	CONF_FNOCHECK     = 1 << 1, /*!< Disabled confdb check. */
	CONF_FNOHOSTNAME  = 1 << 2, /*!< Don't set the hostname. */
} conf_flag_t;

/*!
 * Configuration update flags.
 */
typedef enum {
	CONF_UPD_FNONE    = 0,      /*!< Empty flag. */
	CONF_UPD_FMODULES = 1 << 0, /*!< Reuse previous global modules. */
	CONF_UPD_FCONFIO  = 1 << 1, /*!< Reuse previous cofio reload context. */
} conf_update_flag_t;

/*!
 * Returns the active configuration.
 */
conf_t* conf(void);

/*!
 * Refreshes common read-only transaction.
 *
 * \param[in] conf  Configuration.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_refresh_txn(
	conf_t *conf
);

/*!
 * Refreshes cached hostname.
 *
 * \param[in] conf  Configuration.
 */
void conf_refresh_hostname(
	conf_t *conf
);

/*!
 * Creates new or opens old configuration database.
 *
 * \param[out] conf   Configuration.
 * \param[in] scheme  Configuration scheme.
 * \param[in] db_dir  Database path or NULL.
 * \param[in] flags   Access flags.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_new(
	conf_t **conf,
	const yp_item_t *scheme,
	const char *db_dir,
	conf_flag_t flags
);

/*!
 * Creates a partial copy of the active configuration.
 *
 * Shared objects: api, mm, db, filename.
 *
 * \param[out] conf  Configuration.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_clone(
	conf_t **conf
);

/*!
 * Replaces the active configuration with the specified one.
 *
 * \param[in] conf   New configuration.
 * \param[in] flags  Update flags.
 */
void conf_update(
	conf_t *conf,
	conf_update_flag_t flags
);

/*!
 * Removes the specified configuration.
 *
 * \param[in] conf  Configuration.
 */
void conf_free(
	conf_t *conf
);

/*!
 * Activates configured query modules for the specified zone or for all zones.
 *
 * \param[in] conf           Configuration.
 * \param[in] zone_name      Zone name, NULL for all zones.
 * \param[in] query_modules  Destination query modules list.
 * \param[in] query_plan     Destination query plan.
 */
void conf_activate_modules(
	conf_t *conf,
	const knot_dname_t *zone_name,
	list_t *query_modules,
	struct query_plan **query_plan
);

/*!
 * Deactivates query modules list.
 *
 * \param[in] query_modules  Destination query modules list.
 * \param[in] query_plan     Destination query plan.
 */
void conf_deactivate_modules(
	list_t *query_modules,
	struct query_plan **query_plan
);

/*!
 * Parses textual configuration from the string or from the file.
 *
 * This function is not for direct using, just for includes processing!
 *
 * \param[in] conf     Configuration.
 * \param[in] txn      Transaction.
 * \param[in] input    Configuration string or filename.
 * \param[in] is_file  Specifies if the input is string or input filename.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_parse(
	conf_t *conf,
	knot_db_txn_t *txn,
	const char *input,
	bool is_file
);

/*!
 * Imports textual configuration.
 *
 * \param[in] conf     Configuration.
 * \param[in] input    Configuration string or input filename.
 * \param[in] is_file  Specifies if the input is string or filename.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_import(
	conf_t *conf,
	const char *input,
	bool is_file
);

/*!
 * Exports configuration to textual file.
 *
 * \param[in] conf   Configuration.
 * \param[in] input  Output filename.
 * \param[in] style  Formatting style.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_export(
	conf_t *conf,
	const char *file_name,
	yp_style_t style
);

/*! @} */
