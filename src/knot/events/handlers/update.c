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
#include <stdint.h>

#include "contrib/trim.h"
#include "knot/conf/conf.h"
#include "knot/nameserver/update.h"
#include "knot/zone/zone.h"
#include "libknot/errcode.h"

int event_update(conf_t *conf, zone_t *zone)
{
	assert(zone);

	/* Process update list - forward if zone has master, or execute. */
	updates_execute(conf, zone);

	/* Trim extra heap. */
	mem_trim();

	/* Replan event if next update waiting. */
	pthread_mutex_lock(&zone->ddns_lock);

	const bool empty = EMPTY_LIST(zone->ddns_queue);

	pthread_mutex_unlock(&zone->ddns_lock);

	if (!empty) {
		zone_events_schedule(zone, ZONE_EVENT_UPDATE, ZONE_EVENT_NOW);
	}

	return KNOT_EOK;
}
