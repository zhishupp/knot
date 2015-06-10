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
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

#include "knot/common/evsched.h"
#include "knot/worker/pool.h"
#include "knot/zone/events/events.h"
#include "knot/zone/zone.h"
#include <syslog.h>

// mock objects

struct task *task_assigned;

void __wrap_worker_pool_assign(worker_pool_t * pool, struct task *task)
{
	task_assigned = task;
}

event_t *ev_scheduled;

int __wrap_evsched_schedule(event_t * ev, uint32_t dt)
{
	check_expected(dt);
	ev_scheduled = ev;
	return KNOT_EOK;
}

int __wrap_evsched_cancel(event_t * ev)
{
	check_expected_ptr(ev);
	return KNOT_EOK;
}

/*!
 * \brief Wrapper for all event callbacks
 */
int event_callback_wrapper(zone_event_type_t type, zone_t * zone)
{
	check_expected(type);
	check_expected_ptr(zone);

	return mock();
}

int __wrap_log_msg_zone(int priority, const knot_dname_t * zone,
			const char *fmt, ...)
{
	check_expected(priority);
	return 0;
}

//! \brief context for each testcase
typedef struct test_context  {
	evsched_t sched;
	worker_pool_t *pool;
	zone_t zone;
} test_context _t;

//! \brief create test context
int setup(void **state)
{
	ev_scheduled = NULL;
	task_assigned = NULL;

	*state = malloc(sizeof(test_context _t));
	if (state == NULL) {
		return 1;
	}

	test_context _t *ctx = *state;

	evsched_init(&ctx->sched, NULL);

	ctx->pool = worker_pool_create(1);
	if (ctx->pool == NULL) {
		return 2;
	}
	if (zone_events_init(&ctx->zone) != KNOT_EOK) {
		return 3;
	}
	if (zone_events_setup(&ctx->zone, ctx->pool, &ctx->sched, NULL) !=
	    KNOT_EOK) {
		return 4;
	}
	return 0;
}

//! \brief destroy test context
int teardown(void **state)
{
	test_context _t *ctx = *state;

	expect_value(__wrap_evsched_cancel, ev, ctx->zone.events.event);
	zone_events_deinit(&ctx->zone);

	worker_pool_destroy(ctx->pool);
	evsched_deinit(&ctx->sched);
	free(ctx);
	*state = NULL;
	return 0;
}

void one_correct_task_scheduled(void **state)
{
	test_context _t *ctx = *state;

	expect_value(__wrap_evsched_schedule, dt, 10 * 1000);
	zone_events_schedule(&ctx->zone, ZONE_EVENT_RELOAD, 10);

	ev_scheduled->cb(ev_scheduled);

	expect_value(event_callback_wrapper, type, ZONE_EVENT_RELOAD);
	expect_value(event_callback_wrapper, zone, &ctx->zone);
	will_return(event_callback_wrapper, KNOT_EOK);

	task_assigned->run(task_assigned);
}

//! \brief second task is scheduled before the first
void two_correct_task_scheduled(void **state)
{
	test_context _t *ctx = *state;

	expect_value(__wrap_evsched_schedule, dt, 10 * 1000);
	zone_events_schedule(&ctx->zone, ZONE_EVENT_RELOAD, 10);

	expect_value(__wrap_evsched_schedule, dt, 8 * 1000);
	expect_value(__wrap_evsched_schedule, dt, 10 * 1000);
	zone_events_schedule(&ctx->zone, ZONE_EVENT_REFRESH, 8);

	ev_scheduled->cb(ev_scheduled);

	expect_value(event_callback_wrapper, type, ZONE_EVENT_REFRESH);
	expect_value(event_callback_wrapper, zone, &ctx->zone);
	will_return(event_callback_wrapper, KNOT_EOK);

	task_assigned->run(task_assigned);

	ev_scheduled->cb(ev_scheduled);

	expect_value(event_callback_wrapper, type, ZONE_EVENT_RELOAD);
	expect_value(event_callback_wrapper, zone, &ctx->zone);
	will_return(event_callback_wrapper, KNOT_EOK);
	task_assigned->run(task_assigned);
}

void double_call_event_wrap(void **state)
{
	test_context _t *ctx = *state;

	expect_value(__wrap_evsched_schedule, dt, 10 * 1000);
	zone_events_schedule(&ctx->zone, ZONE_EVENT_RELOAD, 10);

	ev_scheduled->cb(ev_scheduled);

	expect_value(event_callback_wrapper, type, ZONE_EVENT_RELOAD);
	expect_value(event_callback_wrapper, zone, &ctx->zone);
	will_return(event_callback_wrapper, KNOT_EOK);

	// double call, should run only once
	task_assigned->run(task_assigned);
	task_assigned->run(task_assigned);

	expect_value(__wrap_evsched_schedule, dt, 10000 * 1000);
	zone_events_schedule(&ctx->zone, ZONE_EVENT_XFER, 10000);

	ev_scheduled->cb(ev_scheduled);

	// check log if event callback failed
	expect_value(event_callback_wrapper, type, ZONE_EVENT_XFER);
	expect_value(event_callback_wrapper, zone, &ctx->zone);
	will_return(event_callback_wrapper, KNOT_ERROR);
	expect_value(__wrap_log_msg_zone, priority, LOG_ERR);
	task_assigned->run(task_assigned);
}

/*!
 * \brief Schedule all events and check the right order
 */
void all_events(void **state)
{
	test_context _t *ctx = *state;

	expect_value_count(__wrap_evsched_schedule, dt, 1000, -1);

	for (int i = ZONE_EVENT_INVALID + 1; i < ZONE_EVENT_COUNT; ++i) {
		zone_events_schedule(&ctx->zone, i, 1);
		expect_value(event_callback_wrapper, type, i);
		expect_value(event_callback_wrapper, zone, &ctx->zone);
	}

	will_return_always(event_callback_wrapper, KNOT_EOK);

	for (int i = 0; i < ZONE_EVENT_COUNT; ++i) {
		ev_scheduled->cb(ev_scheduled);
		task_assigned->run(task_assigned);
	}
}

void freeze(void **state)
{
	test_context _t *ctx = *state;

	expect_value(__wrap_evsched_cancel, ev, ctx->zone.events.event);

	zone_events_freeze(&ctx->zone);

	// test check for not calling evsched_schedule

	zone_events_schedule(&ctx->zone, ZONE_EVENT_RELOAD, 10);

	zone_events_enqueue(&ctx->zone, ZONE_EVENT_REFRESH);
}

void zone_events_enqueue_running(void **state)
{
	test_context _t *ctx = *state;
	time_t now = time(NULL);

	expect_value(__wrap_evsched_schedule, dt, 0);
	zone_events_schedule_at(&ctx->zone, ZONE_EVENT_EXPIRE, now - 100);

	ev_scheduled->cb(ev_scheduled);

	expect_value(__wrap_evsched_schedule, dt, 0);
	zone_events_enqueue(&ctx->zone, ZONE_EVENT_RELOAD);

	expect_value(event_callback_wrapper, type, ZONE_EVENT_EXPIRE);
	expect_value(event_callback_wrapper, zone, &ctx->zone);
	will_return(event_callback_wrapper, KNOT_EOK);

	task_assigned->run(task_assigned);

	expect_value(event_callback_wrapper, type, ZONE_EVENT_RELOAD);
	expect_value(event_callback_wrapper, zone, &ctx->zone);
	will_return(event_callback_wrapper, KNOT_EOK);

	task_assigned->run(task_assigned);
}

void zone_events_enqueue_not_running(void **state)
{
	test_context _t *ctx = *state;

	zone_events_enqueue(&ctx->zone, ZONE_EVENT_EXPIRE);

	zone_events_enqueue(&ctx->zone, ZONE_EVENT_RELOAD);

	expect_value(event_callback_wrapper, type, ZONE_EVENT_EXPIRE);
	expect_value(event_callback_wrapper, zone, &ctx->zone);
	will_return(event_callback_wrapper, KNOT_EOK);

	expect_value(__wrap_evsched_schedule, dt, 0);

	assert_non_null(task_assigned);
	task_assigned->run(task_assigned);

	task_assigned = NULL;
	assert_non_null(ev_scheduled);
	ev_scheduled->cb(ev_scheduled);

	expect_value(event_callback_wrapper, type, ZONE_EVENT_RELOAD);
	expect_value(event_callback_wrapper, zone, &ctx->zone);
	will_return(event_callback_wrapper, KNOT_EOK);

	assert_non_null(task_assigned);
	task_assigned->run(task_assigned);
}

int main(void)
{
	cmocka_set_message_output(CM_OUTPUT_TAP);

	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(one_correct_task_scheduled, setup, teardown),
		cmocka_unit_test_setup_teardown(two_correct_task_scheduled, setup, teardown),
		cmocka_unit_test_setup_teardown(double_call_event_wrap, setup, teardown),
		cmocka_unit_test_setup_teardown(all_events, setup, teardown),
		cmocka_unit_test_setup_teardown(zone_events_enqueue_running, setup, teardown),
		cmocka_unit_test_setup_teardown(zone_events_enqueue_not_running, setup, teardown),
		cmocka_unit_test_setup_teardown(freeze, setup, teardown),
	};

	cmocka_run_group_tests(tests, NULL, NULL);

	return 0;
}

int __wrap_event_reload(zone_t * zone)
{
	return event_callback_wrapper(ZONE_EVENT_RELOAD, zone);
}

int __wrap_event_refresh(zone_t * zone)
{
	return event_callback_wrapper(ZONE_EVENT_REFRESH, zone);
}

int __wrap_event_xfer(zone_t * zone)
{
	return event_callback_wrapper(ZONE_EVENT_XFER, zone);
}

int __wrap_event_update(zone_t * zone)
{
	return event_callback_wrapper(ZONE_EVENT_UPDATE, zone);
}

int __wrap_event_expire(zone_t * zone)
{
	return event_callback_wrapper(ZONE_EVENT_EXPIRE, zone);
}

int __wrap_event_flush(zone_t * zone)
{
	return event_callback_wrapper(ZONE_EVENT_FLUSH, zone);
}

int __wrap_event_notify(zone_t * zone)
{
	return event_callback_wrapper(ZONE_EVENT_NOTIFY, zone);
}

int __wrap_event_dnssec(zone_t * zone)
{
	return event_callback_wrapper(ZONE_EVENT_DNSSEC, zone);
}
