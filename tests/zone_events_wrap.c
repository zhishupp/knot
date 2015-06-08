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

#include <tap/basic.h>

#include "knot/common/evsched.h"
#include "knot/worker/pool.h"
#include "knot/zone/events/events.h"
#include "knot/zone/zone.h"


struct task *task_assigned;

void __wrap_worker_pool_assign(worker_pool_t *pool, struct task *task)
{
	task_assigned= task;
	diag("call __wrap_worker_pool_assign");
}

event_t *ev_scheduled;

int __wrap_evsched_schedule(event_t *ev, uint32_t dt)
{
	ev_scheduled=ev;
	diag("call __wrap_evsched_schedule, %u",dt);
	return KNOT_EOK;
}


zone_event_type_t callback_type;
zone_t *callback_zone;
/*!
 * \brief Wrapper for all event callbacks
 */
int event_wrapper(zone_event_type_t type, zone_t *zone)
{
	callback_type = type;
	callback_zone = zone;
	return KNOT_EOK;
}

static void test_scheduling(zone_t *zone)
{
	zone_events_schedule(zone, ZONE_EVENT_RELOAD, 10);

	ev_scheduled->cb(ev_scheduled);
	diag("run");
	task_assigned->run(task_assigned);
	ok(callback_type == ZONE_EVENT_RELOAD, "correct callback called");
}


int main(void)
{
	plan_lazy();

	int r;

	evsched_t sched = { 0 };
	worker_pool_t *pool = NULL;
	zone_t zone = { 0 };

	r = evsched_init(&sched, NULL);
	ok(r == KNOT_EOK, "create scheduler");

	pool = worker_pool_create(1);
	ok(pool != NULL, "create worker pool");

	r = zone_events_init(&zone);
	ok(r == KNOT_EOK, "zone events init");

	r = zone_events_setup(&zone, pool, &sched, NULL);
	ok(r == KNOT_EOK, "zone events setup");

	test_scheduling(&zone);


	zone_events_deinit(&zone);
	worker_pool_destroy(pool);
	evsched_deinit(&sched);

	return 0;
}


int __wrap_event_reload(zone_t *zone)
{
	return event_wrapper(ZONE_EVENT_RELOAD,zone);
}

int __wrap_event_refresh(zone_t *zone)
{
	return event_wrapper(ZONE_EVENT_REFRESH,zone);
}

int __wrap_event_xfer(zone_t *zone)
{
	return event_wrapper(ZONE_EVENT_XFER,zone);
}

int __wrap_event_update(zone_t *zone)
{
	return event_wrapper(ZONE_EVENT_UPDATE,zone);
}

int __wrap_event_expire(zone_t *zone)
{
	return event_wrapper(ZONE_EVENT_EXPIRE,zone);
}

int __wrap_event_flush(zone_t *zone)
{
	return event_wrapper(ZONE_EVENT_FLUSH,zone);
}

int __wrap_event_notify(zone_t *zone)
{
	return event_wrapper(ZONE_EVENT_NOTIFY,zone);
}

int __wrap_event_dnssec(zone_t *zone)
{
	return event_wrapper(ZONE_EVENT_DNSSEC,zone);
}