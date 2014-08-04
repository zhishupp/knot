/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <string.h>

#include "dname.h"
#include "kasp.h"
#include "kasp/internal.h"
#include "kasp/zone.h"
#include "shared.h"

/*!
 * Initialize KASP zone structure.
 */
void dnssec_kasp_zone_init(dnssec_kasp_zone_t *zone)
{
	if (!zone) {
		return;
	}

	clear_struct(zone);
	dnssec_kasp_keyset_init(&zone->keys);
}

/*!
 * Allocate new KASP zone.
 */
_public_
dnssec_kasp_zone_t *dnssec_kasp_zone_new(const char *name)
{
	dnssec_kasp_zone_t *zone = malloc(sizeof(*zone));
	dnssec_kasp_zone_init(zone);

	zone->dname = dname_from_ascii(name);
	if (!zone->dname) {
		dnssec_kasp_zone_free(zone);
		return NULL;
	}

	dname_normalize(zone->dname);
	zone->name = dname_to_ascii(zone->dname);
	if (!zone->name) {
		dnssec_kasp_zone_free(zone);
		return NULL;
	}

	return zone;
}

/*!
 * Free KASP zone.
 */
_public_
void dnssec_kasp_zone_free(dnssec_kasp_zone_t *zone)
{
	if (!zone) {
		return;
	}

	dnssec_kasp_keyset_empty(&zone->keys);
	free(zone->dname);
	free(zone->name);

	free(zone);
}