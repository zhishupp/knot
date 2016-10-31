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

#include <assert.h>

#include "error.h"
#include "kasp/dir/json.h"
#include "kasp/dir/keystore.h"
#include "kasp/internal.h"
#include "shared.h"

static const encode_attr_t KEYTAG_ATTRIBUTES[] = {
	#define off(member) offsetof(kasp_keyusage_t, member)
	{ "keytag", off(keytag), encode_string, decode_string },
	{ NULL }
};

static int import_keyusage(dnssec_kasp_keyusage_t *keyusage, const json_t *json)
{
	dnssec_kasp_keyusage_t *result = dnssec_kasp_keyusage_new();
	json_t *jrecord = NULL;
	int a, b;
	kasp_keyusage_t *record = NULL;

	json_array_foreach(json, a, jrecord) {
		json_t *jkeytag = NULL;
		jkeytag = json_object_get(jrecord, "keytag");
		int r = decode_object(KEYTAG_ATTRIBUTES, jkeytag, &record->keytag);
		if (r != DNSSEC_EOK) {
			return r;
		}
		json_t *jzones = NULL, *jzone = NULL;
		jzones = json_object_get(jrecord, "zones");
		char *zone;
		record->zones = dnssec_list_new();
		json_array_foreach(jzones, b, jzone) {
			int r = decode_string(jzone, &zone);
			if (r != DNSSEC_EOK) {
				return r;
			}
			dnssec_list_append(record->zones, zone);
		}
		dnssec_list_append(result->keyrecords, record);
	}

	dnssec_kasp_keyusage_free(keyusage);
	keyusage = result;

	return DNSSEC_EOK;
}

static int export_keyusage(const dnssec_kasp_keyusage_t *keyusage, json_t **json)
{
	assert(keyusage);
	assert(json);

	json_t *jrecords = json_array();
	if (!jrecords) {
		return DNSSEC_ENOMEM;
	}

	dnssec_list_foreach(item, keyusage->keyrecords) {
		kasp_keyusage_t *record = dnssec_item_get(item);

		json_t *jzones = json_array();
		if (!jzones) {
			return DNSSEC_ENOMEM;
		}
		json_t *jkeytag = NULL;
		json_t *jzone = NULL;

		int r = encode_object(KEYTAG_ATTRIBUTES, &record->keytag, &jkeytag);
		if (r != DNSSEC_EOK) {
			json_decref(jkeytag);
			return r;
		}

		dnssec_list_foreach(item, record->zones) {
			const char *zone = dnssec_item_get(item);
			r = encode_string(&zone, &jzone);
			if (r != DNSSEC_EOK) {
				json_decref(jzone);
				return r;
			}
			if (json_array_append_new(jzones, jzone)) {
				json_decref(jzone);
				json_decref(jzones);
				return DNSSEC_ENOMEM;
			}
		}
		json_t *jrecord = json_object();
		if (!jrecord) {
			return DNSSEC_ENOMEM;
		}

		if (json_object_update(jrecord, jkeytag)) {
			json_decref(jrecord);
			json_decref(jkeytag);
			return DNSSEC_ENOMEM;
		}

		if (json_object_update(jrecord, jzones)) {
			json_decref(jrecord);
			json_decref(jzones);
			return DNSSEC_ENOMEM;
		}

		if (json_array_append_new(jrecords, jrecord)) {
			json_decref(jrecords);
			json_decref(jrecord);
			return DNSSEC_ENOMEM;
		}
	}

	*json = jrecords;

	return DNSSEC_EOK;
}

int load_keyusage(dnssec_kasp_keyusage_t *keyusage, const char *filename)
{
	assert(keyusage);
	assert(filename);

	_cleanup_fclose_ FILE *file = fopen(filename, "r");
	if (!file) {
		return DNSSEC_NOT_FOUND;
	}

	json_error_t error = { 0 };
	_json_cleanup_ json_t *json = json_loadf(file, JSON_LOAD_OPTIONS, &error);
	if (!json) {
		return DNSSEC_CONFIG_MALFORMED;
	}

	return import_keyusage(keyusage, json);
}

int save_keyusage(const dnssec_kasp_keyusage_t *keyusage, const char *filename)
{
	assert(keyusage);
	assert(filename);

	_json_cleanup_ json_t *json = NULL;
	int r = export_keyusage(keyusage, &json);
	if (r != DNSSEC_EOK) {
		return r;
	}

	_cleanup_fclose_ FILE *file = fopen(filename, "w");
	if (!file) {
		return DNSSEC_NOT_FOUND;
	}

	r = json_dumpf(json, file, JSON_DUMP_OPTIONS);
	if (r != DNSSEC_EOK) {
		return r;
	}

	fputc('\n', file);
	return DNSSEC_EOK;
}
