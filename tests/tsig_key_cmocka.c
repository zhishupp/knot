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
#include <unistd.h>

#include "libknot/errcode.h"
#include "libknot/tsig.h"


int setup(void **state)
{
	knot_tsig_key_t *key = malloc(sizeof(knot_tsig_key_t));
	if (key == NULL){
		return 1;
	}
	memset(key, 0, sizeof(knot_tsig_key_t));
	*state = key;
	return 0;
}

int teardown(void **state)
{
	knot_tsig_key_deinit((knot_tsig_key_t *)*state);
	free(*state);
	return 0;
}


void key_init_missing_name(void **state)
{
	knot_tsig_key_t key = { 0 };
	int r;
	r = knot_tsig_key_init(&key,"hmac-md5", NULL, "Wg==");
	assert_int_equal(r, KNOT_EINVAL);
	r = knot_tsig_key_init(&key,"hmac-md5", "", "Wg==");
	assert_int_not_equal(r, KNOT_EOK);
}

void key_init_missing_secret(void **state)
{
	knot_tsig_key_t key = { 0 };
	int r;
	r = knot_tsig_key_init(&key,"hmac-md5", "name", NULL);
	assert_int_equal(r, KNOT_EINVAL);
}

void key_init_ivalid_hmac(void **state)
{
	knot_tsig_key_t key = { 0 };
	int r;
	r = knot_tsig_key_init(&key,"hmac-md5", "name", NULL);
	assert_int_equal(r, KNOT_EINVAL);
}

void key_init_default_algorith(void **state)
{
	knot_tsig_key_t *key = *state;
	int r;
	r = knot_tsig_key_init(key, NULL, "key.name", "Wg==");

	assert_int_equal(r, KNOT_EOK);
	assert_int_equal(key->algorithm, DNSSEC_TSIG_HMAC_MD5);
	assert_string_equal(key->name, (uint8_t *)"\x3""key""\x4""name");
	assert_memory_equal(key->secret.data, (uint8_t *)"\x5a", 1);
}

void key_init_sha1(void **state)
{
	knot_tsig_key_t *key = *state;
	int r;
	r = knot_tsig_key_init(key, "hmac-sha1", "knot.dns.", "c2VjcmV0");

	assert_int_equal(r, KNOT_EOK);
	assert_int_equal(key->algorithm, DNSSEC_TSIG_HMAC_SHA1);
	assert_string_equal(key->name, (uint8_t *)"\x4""knot""\x3""dns");
	assert_memory_equal(key->secret.data, (uint8_t *)"secret", 6);
}

void key_init_str_missing_value(void **state)
{
	knot_tsig_key_t key = { 0 };
	int r;
	r = knot_tsig_key_init_str(&key, NULL);
	assert_int_equal(r, KNOT_EINVAL);
}

void key_init_str_malformed(void **state)
{
	knot_tsig_key_t key = { 0 };
	int r;
	r = knot_tsig_key_init_str(&key, "this is malformed");
	assert_int_not_equal(r, KNOT_EOK);
}

void key_init_str_invalid_hmac(void **state)
{
	knot_tsig_key_t key = { 0 };
	int r;
	r = knot_tsig_key_init_str(&key, "hmac-sha51299:key:Wg==");
	assert_int_not_equal(r, KNOT_EOK);
}

void key_init_str_default_algorithm(void **state)
{
	knot_tsig_key_t *key = *state;
	int r;
	r= knot_tsig_key_init_str(key, "tsig.key:YmFuYW5ha2V5");

	assert_int_equal(r, KNOT_EOK);
	assert_int_equal(key->algorithm, DNSSEC_TSIG_HMAC_MD5);
	assert_string_equal(key->name, (uint8_t *)"\x4""tsig""\x3""key");
	assert_memory_equal(key->secret.data, (uint8_t *)"bananakey", 9);
}

void key_init_str_sha384(void **state)
{
	knot_tsig_key_t *key = *state;
	int r;
	r= knot_tsig_key_init_str(key, "hmac-sha384:strong.key:YXBwbGVrZXk=");

	assert_int_equal(r, KNOT_EOK);
	assert_int_equal(key->algorithm, DNSSEC_TSIG_HMAC_SHA384);
	assert_string_equal(key->name, (uint8_t *)"\x6""strong""\x3""key");
	assert_memory_equal(key->secret.data, (uint8_t *)"applekey", 8);
}

void key_init_file_no_filename(void **state)
{
	knot_tsig_key_t key = { 0 };
	int r;
	r = knot_tsig_key_init_file(&key, NULL);
	assert_int_equal(r, KNOT_EINVAL);
}


void key_init_file_not_exists(void **state)
{
	knot_tsig_key_t key = { 0 };
	int r;
	r = knot_tsig_key_init_file(&key, "/this-really-should-not-exist");
	assert_int_not_equal(r, KNOT_EOK);
}



typedef struct test_context {
	knot_tsig_key_t *key;
	char filename[20];
	int fd;
} test_context_t;

/*!
 * \brief setup for test key init from file
 */
int setup_file(void **state)
{
	*state = malloc(sizeof(test_context_t));
	test_context_t *ctx = *state;
	if (ctx == NULL) {
		return 1;
	}
	if (setup((void **)&ctx->key) != 0) {
		return 2;
	}
	strcpy(ctx->filename,"testkey.XXXXXX");
	ctx->fd = mkstemp(ctx->filename);
	if(ctx->fd == -1) {
		fail_msg("failed to create temporary file");
	}
	return 0;
}

int teardown_file(void **state)
{
	test_context_t *ctx = *state;
	close(ctx->fd);
	unlink(ctx->filename);
	teardown((void**)&ctx->key);
	free(ctx);
	return 0;
}

void key_init_file_malformed(void **state)
{
	test_context_t *ctx = *state;
	char *content = "malformed";

	write(ctx->fd, content, strlen(content));
	int r;
	r= knot_tsig_key_init_file(ctx->key, ctx->filename);

	assert_int_not_equal(r, KNOT_EOK);
}

void key_init_file_sha512(void **state)
{
	test_context_t *ctx = *state;
	char *content = "hmac-sha512:django.one:V2hvJ3MgdGhhdCBzdHVtYmxpbmcgYX"
			"JvdW5kIGluIHRoZSBkYXJrPw==\n\n\n";

	write(ctx->fd, content, strlen(content));
	int r;
	r= knot_tsig_key_init_file(ctx->key, ctx->filename);

	assert_int_equal(r, KNOT_EOK);
	assert_int_equal(ctx->key->algorithm, DNSSEC_TSIG_HMAC_SHA512);
	assert_string_equal(ctx->key->name, (uint8_t *)"\x6""django""\x3""one");
	assert_memory_equal(ctx->key->secret.data, (uint8_t *) "Who's that "
			    "stumbling around in the dark?", 40);
}

void key_init_file_without_newline(void **state)
{
	test_context_t *ctx = *state;
	char *content = "hmac-sha512:django.two:"
			"UHJlcGFyZSB0byBnZXQgd2luZ2VkIQ==";

	write(ctx->fd, content, strlen(content));
	int r;
	r= knot_tsig_key_init_file(ctx->key, ctx->filename);

	assert_int_equal(r, KNOT_EOK);
	assert_int_equal(ctx->key->algorithm, DNSSEC_TSIG_HMAC_SHA512);
	assert_string_equal(ctx->key->name, (uint8_t *)"\x6""django""\x3""two");
	assert_memory_equal(ctx->key->secret.data,
			    (uint8_t *) "Prepare to get winged!", 22);
}

void key_init_file_white_spaces(void **state)
{
	test_context_t *ctx = *state;
	char *content = "\thmac-sha1:test:Wg== \n";

	write(ctx->fd, content, strlen(content));
	int r;
	r= knot_tsig_key_init_file(ctx->key, ctx->filename);

	assert_int_equal(r, KNOT_EOK);
	assert_int_equal(ctx->key->algorithm, DNSSEC_TSIG_HMAC_SHA1);
	assert_string_equal(ctx->key->name, (uint8_t *)"\x4""test");
	assert_memory_equal(ctx->key->secret.data, (uint8_t *) "\x5a", 1);
}

void key_copy_invalid(void **state)
{
	knot_tsig_key_t key;
	assert_int_not_equal(knot_tsig_key_copy(NULL, &key), KNOT_EOK);
	assert_int_not_equal(knot_tsig_key_copy(&key, NULL), KNOT_EOK);
}

void key_copy_simple(void **state)
{
	knot_tsig_key_t key = {
		.algorithm = DNSSEC_TSIG_HMAC_SHA1,
		.name = (uint8_t *)"\x4""copy""\x2""me",
		.secret.size = 6,
		.secret.data = (uint8_t *)"orange"
	};
	knot_tsig_key_t copy = { 0 };
	assert_int_equal(knot_tsig_key_copy(&copy, &key), KNOT_EOK);
	assert_int_equal(copy.algorithm, key.algorithm);
	assert_string_equal(copy.name, key.name);
	assert_memory_equal(copy.secret.data, key.secret.data, key.secret.size);

	knot_tsig_key_deinit(&copy);
}

void key_deinit(void **state)
{
	knot_tsig_key_t key = { 0 };
	int r = knot_tsig_key_init(&key, NULL, "a.key.name", "Wg==");
	assert_int_equal(r, KNOT_EOK);

	uint8_t * data_ptr = key.secret.data;

	knot_tsig_key_deinit(&key);

	knot_tsig_key_t null_key = { 0 };
	assert_memory_equal(&key, &null_key, sizeof(knot_tsig_key_t));

	assert_int_not_equal(*data_ptr, 0x5a);
}


int main(void)
{
	cmocka_set_message_output(CM_OUTPUT_TAP);

	const struct CMUnitTest tests[] = {
		cmocka_unit_test(key_init_missing_name),
		cmocka_unit_test(key_init_missing_secret),
		cmocka_unit_test(key_init_ivalid_hmac),
		cmocka_unit_test_setup_teardown(key_init_default_algorith, setup, teardown),
		cmocka_unit_test_setup_teardown(key_init_sha1, setup, teardown),
		cmocka_unit_test(key_init_str_missing_value),
		cmocka_unit_test(key_init_str_malformed),
		cmocka_unit_test(key_init_str_invalid_hmac),
		cmocka_unit_test_setup_teardown(key_init_str_default_algorithm, setup, teardown),
		cmocka_unit_test_setup_teardown(key_init_str_sha384, setup, teardown),
		cmocka_unit_test(key_init_file_no_filename),
		cmocka_unit_test(key_init_file_not_exists),
		cmocka_unit_test_setup_teardown(key_init_file_malformed, setup_file, teardown_file),
		cmocka_unit_test_setup_teardown(key_init_file_sha512, setup_file, teardown_file),
		cmocka_unit_test_setup_teardown(key_init_file_without_newline, setup_file, teardown_file),
		cmocka_unit_test_setup_teardown(key_init_file_white_spaces, setup_file, teardown_file),
		cmocka_unit_test(key_copy_invalid),
		cmocka_unit_test(key_copy_simple),
		cmocka_unit_test(key_deinit),
	};

	cmocka_run_group_tests(tests, NULL, NULL);

	return 0;
}