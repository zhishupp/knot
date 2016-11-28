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

#include <stdlib.h>

#include "kasp.h"
#include "kasp/internal.h"
#include "shared.h"

/* -- internal API --------------------------------------------------------- */
/*
//todo
void dnssec_keyusage_cleanup(dnssec_keyusage_t *keyusage)
{
	if (keyusage == NULL) {
		return;
	}

	if (!dnssec_list_is_empty(keyusage)) {
		dnssec_list_foreach(item, keyusage) {
			kasp_keyusage_t *record = dnssec_item_get(item);

			free(record->keytag);
			dnssec_list_free(record->zones);
			free(record);
		}
	}
	dnssec_list_free(keyusage);
}
*/
/* -- public API ----------------------------------------------------------- */
/*
_public_
dnssec_keyusage_t *dnssec_keyusage_new()
{
	dnssec_keyusage_t *keyusage = dnssec_list_new();
	return keyusage;
}

_public_
void dnssec_keyusage_free(dnssec_keyusage_t *keyusage)
{
	if (keyusage == NULL) {
		return;
	}

	keyusage_cleanup(keyusage);
	keyusage = NULL;
}
*/
