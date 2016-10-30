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

#include "dnssec/keyusage.h"
#include "error.h"
#include "string.h"
#include "dnssec.h"

int dnssec_keyusage_add(dnssec_kasp_keyusage_t *keyusage, const char *keytag, char *zone) {
	dnssec_list_foreach(item, keyusage->keyrecords) {
		kasp_keyusage_t *record = dnssec_item_get(item);
		if (strcmp(record->keytag, keytag) == 0) {
			dnssec_list_append(record->zones, zone);
			return DNSSEC_EOK;
		}
	}
	kasp_keyusage_t *record = malloc(sizeof(record));
	record->keytag = strdup(keytag);
	record->zones = dnssec_list_new();
	dnssec_list_append(record->zones, zone);
	dnssec_list_append(keyusage->keyrecords, record);
	return DNSSEC_EOK;
}

int dnssec_keyusage_remove(dnssec_kasp_keyusage_t *keyusage, const char *keytag, char *zone) {
	dnssec_list_foreach(item, keyusage->keyrecords) {
		kasp_keyusage_t *record = dnssec_item_get(item);
		if (strcmp(record->keytag, keytag) == 0) {
			dnssec_item_t *to_delete = dnssec_list_search(record->zones, zone);
			if (to_delete == NULL) {
				return DNSSEC_ENOENT;
			}
			dnssec_list_remove(to_delete);
			if (dnssec_list_is_empty(record->zones)) {
				dnssec_list_remove(item);
			}
			return DNSSEC_EOK;
		}
	}
	return DNSSEC_ENOENT;
}
