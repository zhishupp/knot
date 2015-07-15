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

#include "libknot/internal/namedb/namedb.h"
#include "libknot/internal/namedb/namedb_internal.h"

void namedb_deinit(namedb_t *ctx)
{
	ctx->api->deinit(ctx->db);
	ctx->db = NULL;
}

int namedb_begin_txn(namedb_t *ctx, namedb_txn_t *txn, unsigned flags)
{
	return ctx->api->txn_begin(ctx->db, txn, flags);
}

int namedb_commit_txn(namedb_t *ctx, namedb_txn_t *txn)
{
	return ctx->api->txn_commit(txn);
}

void namedb_abort_txn(namedb_t *ctx, namedb_txn_t *txn)
{
	ctx->api->txn_abort(txn);
}

int namedb_count(namedb_t *ctx, namedb_txn_t *txn)
{
	return ctx->api->count(txn);
}

int namedb_clear(namedb_t *ctx, namedb_txn_t *txn)
{
	return ctx->api->clear(txn);
}

int namedb_find(namedb_t *ctx, namedb_txn_t *txn,
                namedb_val_t *key, namedb_val_t *val, unsigned flags)
{
	return ctx->api->find(txn, key, val, flags);
}
int namedb_insert(namedb_t *ctx, namedb_txn_t *txn,
                  namedb_val_t *key, namedb_val_t *val, unsigned flags)
{
	return ctx->api->insert(txn, key, val, flags);
}

int namedb_del(namedb_t *ctx, namedb_txn_t *txn, namedb_val_t *key)
{
	return ctx->api->del(txn, key);
}

namedb_iter_t *namedb_begin_iter(namedb_t *ctx, namedb_txn_t *txn,
                                 unsigned flags)
{
	return ctx->api->iter_begin(txn, flags);
}
namedb_iter_t *namedb_seek_iter(namedb_t *ctx, namedb_iter_t *iter,
                                namedb_val_t *key, unsigned flags)
{
	return ctx->api->iter_seek(iter, key, flags);
}

namedb_iter_t *namedb_next_iter(namedb_t *ctx, namedb_iter_t *iter)
{
	return ctx->api->iter_next(iter);
}

void namedb_finish_iter(namedb_t *ctx, namedb_iter_t *iter)
{
	ctx->api->iter_finish(iter);
}

int namedb_key_iter(namedb_t *ctx, namedb_iter_t *iter, namedb_val_t *key)
{
	return ctx->api->iter_key(iter, key);
}

int namedb_val_iter(namedb_t *ctx, namedb_iter_t *iter, namedb_val_t *val)
{
	return ctx->api->iter_val(iter, val);
}
