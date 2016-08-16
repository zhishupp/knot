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

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <urcu.h>
#include <uv.h>
#ifdef HAVE_CAP_NG_H
#include <cap-ng.h>
#endif /* HAVE_CAP_NG_H */

#include "dnssec/random.h"
#include "knot/server/tcp-handler.h"
#include "knot/common/log.h"
#include "knot/nameserver/process_query.h"
#include "knot/query/layer.h"
#include "contrib/macros.h"
#include "contrib/mempattern.h"
#include "contrib/sockaddr.h"
#include "contrib/ucw/mempool.h"

enum handle_type {
	UNKNOWN = 0,
	TCP_CLIENT,
	TCP_SERVER,
};

enum query_state {
	WRITE,
	NODATA,
	DONE,
};

/*! \brief TCP context data. */
typedef struct loop_ctx {
	server_t *server;           /*!< Name server structure. */
	unsigned clients;
	unsigned thread_id;         /*!< Thread identifier. */
	dthread_t * thread;
	unsigned *iostate;
	iohandler_t *handler;
	ifacelist_t* old_ifaces;
} loop_ctx_t;

typedef struct tcp_ctx {
	void (*free)(void *);
	enum handle_type type;
} tcp_ctx_t;

typedef struct tcp_client {
	tcp_ctx_t ctx;
	uv_tcp_t handle;
	uint64_t timeout;
	knot_layer_t layer;
	struct process_query_param param;
	knot_mm_t mm;
	uint8_t *buf_pos;
	size_t buf_len;
	uint8_t buf[KNOT_WIRE_MAX_PKTSIZE + 2];
} tcp_client_t;

typedef struct tcp_server {
	tcp_ctx_t ctx;
	uv_tcp_t handle;
	server_t *server;
	unsigned thread_id;
	ref_t *ifaces_ref;
} tcp_server_t;

typedef struct write_ctx {
	uv_write_t req;
	tcp_client_t *client;
	uv_buf_t tx[2];
	knot_pkt_t *ans;
	uint16_t pktsize;
	uint8_t buf[KNOT_WIRE_MAX_PKTSIZE];
} write_ctx_t;


static int client_serve(tcp_client_t *client);
static void on_connection(uv_stream_t* server, int status);
static void on_read(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf);
static void on_write (uv_write_t* req, int status);
static void on_close_free(uv_handle_t* handle);

static void client_free(void *ctx)
{
	tcp_client_t *client = ctx;
	mp_delete(client->layer.mm->ctx);
	mp_delete(client->mm.ctx);
}

static tcp_client_t *client_alloc(uv_loop_t *loop)
{
	knot_mm_t mm_tmp = { 0 };
	mm_ctx_mempool(&mm_tmp, 16 * MM_DEFAULT_BLKSIZE);
	tcp_client_t *client = mm_alloc(&mm_tmp, sizeof(tcp_client_t));
	memset(client, 0, sizeof(tcp_client_t));
	client->mm = mm_tmp;

	client->handle.data = client;
	client->ctx.free = client_free;
	client->ctx.type = TCP_CLIENT;
	client->buf_pos = client->buf;

	uv_tcp_init(loop, &client->handle);

	knot_mm_t *query_mm = mm_alloc(&client->mm, sizeof(knot_mm_t));
	mm_ctx_mempool(query_mm, 16 * MM_DEFAULT_BLKSIZE);
	knot_layer_init(&client->layer, query_mm, process_query_layer());
	return client;
}

static void server_free(void *ctx)
{
	tcp_server_t *server = ctx;
	ref_release(server->ifaces_ref);
	free(server);
}

static int server_alloc_listen(tcp_server_t **res, uv_loop_t *loop, int fd, ref_t *ref)
{
	tcp_server_t *server;
	if (loop == NULL || res == NULL) {
		return KNOT_EINVAL;
	}
	server = malloc(sizeof(tcp_server_t));
	if (server==NULL) {
		return KNOT_ENOMEM;
	}
	memset(server, 0, sizeof(tcp_server_t));
	server->ctx.free = server_free;
	server->ctx.type = TCP_SERVER;
	uv_tcp_init(loop, &server->handle);
	uv_tcp_open(&server->handle, fd);
	server->handle.data = server;
	server->ifaces_ref = ref;
	ref_retain(server->ifaces_ref);
	int ret = uv_listen((uv_stream_t *) &server->handle, TCP_BACKLOG_SIZE, on_connection);
	if (ret  < 0) {
		struct sockaddr_storage ss;
		int addrlen = sizeof(struct sockaddr_storage);
		uv_tcp_getsockname(&server->handle, (struct sockaddr *)&ss, &addrlen);
		char addr_str[SOCKADDR_STRLEN] = {0};
		sockaddr_tostr(addr_str, sizeof(addr_str), (struct sockaddr *)&ss);
		log_error("cannot open socket, address '%s' (%s)", addr_str, uv_strerror(ret));
		return KNOT_ERROR;
	}
	*res = server;
	return KNOT_EOK;
}

static write_ctx_t *write_ctx_alloc(knot_mm_t *mm)
{
	write_ctx_t *res = mm_alloc(mm, sizeof(write_ctx_t));
	memset(res, 0, sizeof(write_ctx_t));
	res->tx[0].base = (char *)&res->pktsize;
	res->tx[0].len = sizeof(uint16_t);
	res->tx[1].base = (char *)res->buf;
	res->tx[1].len = KNOT_WIRE_MAX_PKTSIZE;
	res->ans = knot_pkt_new(res->tx[1].base, res->tx[1].len, mm);
	res->req.data = res;
	return res;
}

static int generate_answer(tcp_client_t *client, write_ctx_t *write)
{
	/* Timeout. */
	rcu_read_lock();
	int timeout = 1000 * conf()->cache.srv_tcp_idle_timeout;
	rcu_read_unlock();
	client->timeout = uv_now(client->handle.loop) + timeout;

	/* Resolve until NOOP or finished. */
	int state = client->layer.state;

	while (state & (KNOT_STATE_PRODUCE|KNOT_STATE_FAIL)) {
		state = knot_layer_produce(&client->layer, write->ans);
		if (state & KNOT_STATE_FAIL) {
		}
		/* Send, if response generation passed and wasn't ignored. */
		if (write->ans->size > 0 && !(state & (KNOT_STATE_FAIL|KNOT_STATE_NOOP))) {
			write->pktsize = htons(write->ans->size);
			write->tx[1].base = (char *)write->ans->wire;
			write->tx[1].len = write->ans->size;
			uv_write(&write->req, (uv_stream_t *)&client->handle, write->tx, 2, on_write);
			return WRITE;
		}
	}
	knot_layer_finish(&client->layer);
	log_debug("knot_layer:finnish");
	return DONE;
}

static void client_save_buffer(tcp_client_t *client)
{
	size_t available = client->buf + client->buf_len - client->buf_pos;
	if (available > 0) {
		memmove(client->buf, client->buf_pos, available);
		client->buf_len = available;
	} else {
		client->buf_len = 0;
	}
	client->buf_pos = client->buf;
}

static int client_serve(tcp_client_t *client)
{
	size_t available = client->buf + client->buf_len - client->buf_pos;
	if (available >= sizeof(uint16_t)) {
		uint16_t pktsize = ntohs(*(uint16_t *)client->buf_pos);
		if (available - 2 >= pktsize) {
			client->buf_pos += 2;
			knot_pkt_t *query = knot_pkt_new(client->buf_pos, pktsize, client->layer.mm);
			client->buf_pos += pktsize;

			/* Initialize processing layer. */
			knot_layer_begin(&client->layer, &client->param);
			write_ctx_t *write = write_ctx_alloc(client->layer.mm);
			write->client = client;

			/* Input packet. */
			knot_pkt_parse(query, 0);
			knot_layer_consume(&client->layer, query);
			return generate_answer(client, write);
		}
	}
	return NODATA;
}

static void read_buffer_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
	tcp_client_t *client = handle->data;
	buf->base = (char *)client->buf + client->buf_len;
	buf->len = KNOT_WIRE_MAX_PKTSIZE + 2 - client->buf_len;
}

static void on_read(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
	if (nread == UV_EOF || nread < 0) {
		uv_close((uv_handle_t*)handle, on_close_free);
		return;
	}

	tcp_client_t *client = handle->data;

	client->buf_len += nread;

	int state;
	while ((state = client_serve(client)) == DONE) {
		mp_flush(client->layer.mm->ctx);
	}
	if (state == WRITE) {
		uv_read_stop(handle);
	} else {
		client_save_buffer(client);
	}
}

static void on_write (uv_write_t* req, int status)
{
	write_ctx_t *write = req->data;

	if (generate_answer(write->client, write) == DONE) {
		int state;
		while ((state = client_serve(write->client)) == DONE) {
			mp_flush(write->client->layer.mm->ctx);
		}
		if (state == NODATA) {
			client_save_buffer(write->client);
			uv_read_start((uv_stream_t *)&write->client->handle,
			              read_buffer_alloc, on_read);
		}
	}
}

static void on_connection(uv_stream_t* server, int status)
{
	if (status == -1) {
		return;
	}

	loop_ctx_t *tcp = server->loop->data;
	tcp_client_t *client = client_alloc(server->loop);

	/* Timeout. */
	rcu_read_lock();
	int timeout = 1000 * conf()->cache.srv_tcp_hshake_timeout;
	int max_clients = conf()->cache.srv_max_tcp_clients;
	rcu_read_unlock();
	client->timeout = uv_now(client->handle.loop) + timeout;

	/* int max_per_thread = MAX(max_clients / tcp->server->handlers[IO_TCP].size, 1);
	tcp->clients++;
	if (tcp->clients >= max_per_thread) {

	}*/

	/* From libuv documentation:
	 * When the uv_connection_cb callback is called it is guaranteed
	 * that this function will complete successfully the first time.
	 */
	uv_accept(server, (uv_stream_t*) &client->handle);
	uv_read_start((uv_stream_t*) &client->handle, read_buffer_alloc, on_read);

	// Layer param init
	struct sockaddr_storage *ss = mm_alloc(&client->mm ,sizeof(struct sockaddr_storage));
	memset(ss, 0, sizeof(struct sockaddr_storage));
	uv_fileno((uv_handle_t *)&client->handle, &client->param.socket);
	client->param.remote = ss;
	client->param.server = tcp->server;
	client->param.thread_id = tcp->thread_id;
	/* Receive peer name. */
	int addrlen = sizeof(struct sockaddr_storage);
	uv_tcp_getpeername(&client->handle, (struct sockaddr *)ss, &addrlen);
}

static void on_close_free(uv_handle_t* handle)
{
	if (handle->type == UV_TCP) {
		tcp_ctx_t *ctx = handle->data;
		if (ctx != NULL) {
			ctx->free(ctx);
		}
	}
}

static void close_client(uv_handle_t* handle, void* arg)
{
	if (handle->type == UV_TCP) {
		tcp_ctx_t *ctx = handle->data;
		if (ctx->type == TCP_CLIENT) {
			uv_close(handle, on_close_free);
		}
	}
}

static void close_tcp(uv_handle_t* handle, void* arg)
{
	if (handle->type == UV_TCP) {
		tcp_ctx_t *ctx = handle->data;
		if (ctx->type == TCP_SERVER) {
			tcp_server_t *server = handle->data;
			server->handle.io_watcher.fd = 0;
		}
		uv_close(handle, on_close_free);
	}
}

static void close_all(uv_handle_t* handle, void* arg)
{
	if (handle->type == UV_TCP) {
		tcp_ctx_t *ctx = handle->data;
		if (ctx->type == TCP_SERVER) {
			tcp_server_t *server = handle->data;
			server->handle.io_watcher.fd = 0;
			log_debug("tcp");
		}
	}
	log_debug("handle_close");
	uv_close(handle, on_close_free);

}

static void close_handle_fd(uv_handle_t* handle, void* arg)
{
	int fd=-1;
	uv_fileno(handle, &fd);
	if (fd == *((int *)arg)) {
		uv_close(handle, on_close_free);
	}
}

static void reconfigure_loop(uv_loop_t *loop)
{
	loop_ctx_t *tcp = loop->data;
	iface_t *i = NULL;

	uv_walk(loop, close_tcp, NULL);
	/*uv_walk(loop, close_client, NULL);
	if (tcp->old_ifaces != NULL) {
		WALK_LIST(i, tcp->old_ifaces->u) {
			uv_walk(loop, close_handle_fd, &i->fd_tcp);
		}
		ref_release(&tcp->old_ifaces->ref);
	}*/

	rcu_read_lock();
	tcp->old_ifaces  = tcp->handler->server->ifaces;
	int multiproccess = tcp->server->handlers[IO_TCP].size > 1;
	WALK_LIST(i, tcp->handler->server->ifaces->l) {
		tcp_server_t *server;
		if (server_alloc_listen(&server, loop, i->fd_tcp,
		    &tcp->old_ifaces->ref) == KNOT_EOK) {
			uv_tcp_simultaneous_accepts(&server->handle, !multiproccess);
		}
	}
	rcu_read_unlock();
}

static void cancel_check(uv_idle_t* handle)
{
	loop_ctx_t *tcp = handle->loop->data;
	dthread_t *thread = tcp->thread;
	/* Check for cancellation. */
	if (dt_is_cancelled(thread)) {
		uv_stop(handle->loop);
	}

	/* Check handler state. */
	if (unlikely(*tcp->iostate & ServerReload)) {
		*tcp->iostate &= ~ServerReload;
		reconfigure_loop(handle->loop);
	}
}

static void sweep_client(uv_handle_t* handle, void* arg)
{
	tcp_ctx_t *ctx = handle->data;
	if (handle->type != UV_TCP || ctx->type != TCP_CLIENT) {
		return;
	}
	tcp_client_t *client = handle->data;
	uint64_t sweep_time = *((uint64_t *)arg);
	if (client->timeout != 0 && client->timeout < sweep_time) {
		char addr_str[SOCKADDR_STRLEN] = {0};
		sockaddr_tostr(addr_str, sizeof(addr_str), (struct sockaddr *)client->param.remote);
		log_notice("TCP, terminated inactive client, address '%s'", addr_str);
		uv_close(handle, on_close_free);
	}
}

static void tcp_sweep(uv_timer_t *timer) {
	uint64_t sweep_time = uv_now(timer->loop);
	uv_walk(timer->loop, sweep_client, &sweep_time);
}

int tcp_master(dthread_t *thread)
{
	if (!thread || !thread->data) {
		return KNOT_EINVAL;
	}

	loop_ctx_t tcp;
	memset(&tcp, 0, sizeof(loop_ctx_t));
	tcp.handler = (iohandler_t *)thread->data;
	if (tcp.handler->server == NULL || tcp.handler->server->ifaces == NULL) {
		return KNOT_EINVAL;
	}

	tcp.server = tcp.handler->server;
	tcp.thread_id = tcp.handler->thread_id[dt_get_id(thread)];
	tcp.thread = thread;
	tcp.iostate = &tcp.handler->thread_state[dt_get_id(thread)];

	uv_loop_t loop;
	uv_loop_init(&loop);
	loop.data = &tcp;

	uv_idle_t cancel_point;
	uv_idle_init(&loop, &cancel_point);
	uv_idle_start(&cancel_point, cancel_check);

	uv_timer_t sweep_timer;
	uv_timer_init(&loop, &sweep_timer);
	uv_timer_start(&sweep_timer, tcp_sweep, 0, TCP_SWEEP_INTERVAL * 1000);

	reconfigure_loop(&loop);
	*tcp.iostate &= ~ServerReload;

	int ret = uv_run(&loop, UV_RUN_DEFAULT);
	uv_walk(&loop, close_all, NULL);
	uv_run(&loop, UV_RUN_ONCE);
	uv_loop_close(&loop);

	ref_release(&tcp.old_ifaces->ref);
	return ret;
}
