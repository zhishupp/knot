/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
/*
#include <assert.h>

#include "error.h"
#include "kasp/dir/json.h"
#include "kasp/dir/keystore.h"
#include "kasp/internal.h"
#include "shared.h"
#include <string.h>

static int import_keyusage(dnssec_keyusage_t *keyusage, const json_t *json)
{
	json_t *jrecord = NULL;
	int a, b;
	if (!json_is_array(json)) {
		if (json_is_null(json)) {
			return DNSSEC_EOK;
		} else {
			return DNSSEC_CONFIG_MALFORMED;
		}
	}
	json_array_foreach(json, a, jrecord) {
		json_t *jkeytag = NULL;
		jkeytag = json_object_get(jrecord, "keytag");



		kasp_keyusage_t *record = malloc(sizeof(*record));
		if (record == NULL) {
			return DNSSEC_ENOMEM;
		}

		int r = decode_string(jkeytag, &record->keytag);
		if (r != DNSSEC_EOK) {
			return r;
		}

		json_t *jzones = NULL, *jzone = NULL;
		jzones = json_object_get(jrecord, "zones");
		record->zones = dnssec_list_new();

		json_array_foreach(jzones, b, jzone) {
			char *zone;
			int r = decode_string(jzone, &zone);
			if (r != DNSSEC_EOK) {
				return r;
			}
			dnssec_list_append(record->zones, zone);
			free(zone);
		}
		dnssec_list_append(keyusage, record);
	}

	return DNSSEC_EOK;
}

static int export_keyusage(dnssec_keyusage_t *keyusage, json_t **json)
{
	assert(keyusage);
	assert(json);
	kasp_keyusage_t *record;
	int r;

	if (dnssec_list_is_empty(keyusage)) {
		return DNSSEC_EOK;
	}

	json_t *jrecords = json_array();
	if (!jrecords) {
		return DNSSEC_ENOMEM;
	}

	json_t *jkeytag = NULL;
	json_t *jzone = NULL;
	json_t *jzones = NULL;

	dnssec_list_foreach(item, keyusage) {
		record = dnssec_item_get(item);

		json_t *jzones = json_array();
		if (!jzones) {
			json_array_clear(jrecords);
			return DNSSEC_ENOMEM;
		}

		r = encode_string(&record->keytag, &jkeytag);
		if (r != DNSSEC_EOK) {
			json_decref(jkeytag);
			goto error;
		}

		dnssec_list_foreach(item, record->zones) {
			const char *zone = dnssec_item_get(item);
			r = encode_string(&zone, &jzone);
			if (r != DNSSEC_EOK) {
				json_decref(jzone);
				goto error;
			}
			if (json_array_append_new(jzones, jzone)) {
				r = DNSSEC_ENOMEM;
				goto error;
			}
		}
		json_t *jrecord = json_object();
		if (!jrecord) {
			r = DNSSEC_ENOMEM;
			goto error;
		}

		if (json_object_set(jrecord, "keytag",jkeytag)) {
			json_object_clear(jrecord);
			r = DNSSEC_ENOMEM;
			goto error;
		}
		json_decref(jkeytag);

		if (json_object_set(jrecord, "zones",jzones)) {
			json_object_clear(jrecord);
			r = DNSSEC_ENOMEM;
			goto error;
		}
		json_decref(jzones);

		if (json_array_append_new(jrecords, jrecord)) {
			json_object_clear(jrecord);
			r = DNSSEC_ENOMEM;
			goto error;
		}
	}
	*json = jrecords;

	return DNSSEC_EOK;
error:
	json_array_clear(jzones);
	json_array_clear(jrecords);
	return r;

}

int dnssec_keyusage_load(dnssec_keyusage_t *keyusage, const char *filename)
{
	assert(keyusage);
	assert(filename);

	dnssec_list_clear(keyusage);

	_cleanup_fclose_ FILE *file = fopen(filename, "r");
	if (!file) {
		return DNSSEC_NOT_FOUND;
	}

	json_error_t error = { 0 };
	_json_cleanup_ json_t *json = json_loadf(file, JSON_LOAD_OPTIONS, &error);
	if (!json) {
		if (error.position != 1) {
			return DNSSEC_CONFIG_MALFORMED;
		} else {
			return DNSSEC_EOK;
		}
	}

	return import_keyusage(keyusage, json);
}

int dnssec_keyusage_save(dnssec_keyusage_t *keyusage, const char *filename)
{
	assert(keyusage);
	assert(filename);

	_json_cleanup_ json_t *json = NULL;
	int r = export_keyusage(keyusage, &json);
	if (r != DNSSEC_EOK) {
	    fprintf(stdout, "export :(");
		return r;
	}

	_cleanup_fclose_ FILE *file = fopen(filename, "w");
	if (!file) {
	    fprintf(stdout, "create file :(");
		return DNSSEC_NOT_FOUND;
	}

	if (json)
	{
		r = json_dumpf(json, file, JSON_DUMP_OPTIONS);
		if (r != DNSSEC_EOK) {
		    fprintf(stdout, "dump :(");
			return r;
		}
	}

	fputc('\n', file);
	return DNSSEC_EOK;
}
*/
