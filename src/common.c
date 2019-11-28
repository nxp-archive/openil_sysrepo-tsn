/**
 * @file common.c
 * @author Xiaolin He
 * @brief common functions for the project.
 *
 * Copyright 2019 NXP
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/inotify.h>
#include <pthread.h>
#include <errno.h>

#include "common.h"

static pthread_mutex_t tsn_mutex;

void init_tsn_mutex(void)
{
	pthread_mutex_init(&tsn_mutex, NULL);
}

void destroy_tsn_mutex(void)
{
	pthread_mutex_destroy(&tsn_mutex);
}

void init_tsn_socket(void)
{
	pthread_mutex_lock(&tsn_mutex);
	genl_tsn_init();
}

void close_tsn_socket(void)
{
	genl_tsn_close();
	pthread_mutex_unlock(&tsn_mutex);
}

inline uint64_t cal_base_time(struct base_time_s *basetime)
{
	return ((basetime->seconds * 1000000000) + basetime->nanoseconds);
}

inline uint64_t cal_cycle_time(struct cycle_time_s *cycletime)
{
	return ((cycletime->numerator * 1000000000) / cycletime->denominator);
}

int errno2sp(int errtsn)
{
	int errsp = 0;

	switch (errtsn) {
	case SR_ERR_OK:
		break;
	case EINVAL:
		errsp = SR_ERR_INVAL_ARG;
		break;
	case ENOMEM:
		errsp = SR_ERR_NOMEM;
		break;
	default:
		errsp = SR_ERR_INVAL_ARG;
		break;
	}

	return errsp;
}
void print_change(sr_change_oper_t oper, sr_val_t *val_old,
		sr_val_t *val_new)
{
	switch (oper) {
	case SR_OP_CREATED:
		if (val_new) {
			printf("\n created new value: ");
			sr_print_val(val_new);
		}
		break;
	case SR_OP_DELETED:
		if (val_old) {
			printf("\n deleted old value: ");
			sr_print_val(val_old);
		}
		break;
	case SR_OP_MODIFIED:
		if (val_old && val_new) {
			printf("\n modified:\nold value ");
			sr_print_val(val_old);
			printf("new value ");
			sr_print_val(val_new);
		}
		break;
	case SR_OP_MOVED:
		if (val_new) {
			printf("\n moved: %s after %s", val_new->xpath,
			       val_old ? val_old->xpath : NULL);
		}
		break;
	}
}

void print_subtree_changes(sr_session_ctx_t *session, const char *xpath)
{
	int rc = SR_ERR_OK;
	sr_change_iter_t *it = NULL;
	sr_change_oper_t oper;
	sr_val_t *old_value = NULL;
	sr_val_t *new_value = NULL;

	rc = sr_get_changes_iter(session, xpath, &it);
	if (rc != SR_ERR_OK) {
		printf("Get changes iter failed for xpath %s", xpath);
		return;
	}

	printf("\n ========== START OF CHANGES ==================\n");
	while (SR_ERR_OK == (rc = sr_get_change_next(session, it,
					&oper, &old_value, &new_value))) {
		print_change(oper, old_value, new_value);
		sr_free_val(old_value);
		sr_free_val(new_value);
	}
	printf("\n ========== END OF CHANGES ==================\n");
}

void print_config_iter(sr_session_ctx_t *session, const char *path)
{
	sr_val_t *values = NULL;
	size_t count = 0;
	int rc = SR_ERR_OK;

	if (!path || !session)
		return;

	rc = sr_get_items(session, path, &values, &count);
	if (rc != SR_ERR_OK) {
		printf("Error by sr_get_items: %s", sr_strerror(rc));
		return;
	}
	for (size_t i = 0; i < count; i++)
		sr_print_val(&values[i]);

	sr_free_values(values, count);
}

void print_ev_type(sr_notif_event_t event)
{
	switch (event) {
	case SR_EV_VERIFY:
		printf("\n--- verify mode ---\n");
		break;
	case SR_EV_ENABLED:
		printf("\n--- enable mode ---\n");
		break;
	case SR_EV_APPLY:
		printf("\n--- apply mode ---\n");
		break;
	case SR_EV_ABORT:
		printf("\n--- abort mode ---\n");
		break;
	default:
		printf("\n--- unknown mode ---\n");
		break;
	}
}

int str_to_num(int type, char *str, uint64_t *num)
{
	char *char_ptr;
	char ch;
	int len;
	int base = 0;
	int i;

	char_ptr = str;
	len = strlen(str);
	if ((strncmp(str, "0x", 2) == 0) || (strncmp(str, "0X", 2) == 0)) {
		char_ptr += 2;
		for (i = 2; i < len; i++) {
			ch = *char_ptr;
			if ((ch < '0') || ((ch > '9') && (ch < 'A')) ||
			    ((ch > 'F') && (ch < 'a')) || (ch > 'f'))
				goto err;

			char_ptr++;
		}
		base = 16;
		goto convert;
	}

	char_ptr = str;
	char_ptr += len - 1;
	ch = *char_ptr;
	if ((ch == 'b') || (ch == 'B')) {
		char_ptr = str;
		for (i = 0; i < len - 1; i++) {
			ch = *char_ptr;
			if ((ch < '0') || (ch > '1'))
				goto err;

			char_ptr++;
		}
		base = 2;
		goto convert;
	}

	char_ptr = str;
	if (*char_ptr == '0') {
		char_ptr++;
		for (i = 1; i < len; i++) {
			ch = *char_ptr;
			if ((ch < '0') || (ch > '7'))
				goto err;

			char_ptr++;
		}
		base = 8;
		goto convert;
	}

	char_ptr = str;
	for (i = 0; i < len; i++) {
		ch = *char_ptr;
		if ((ch < '0') || (ch > '9'))
			goto err;

		char_ptr++;
	}
	base = 10;

convert:
	errno = 0;
	*num = strtoul(str, NULL, base);
	if (errno == ERANGE)
		goto err;
	// check type limit
	switch (type) {
	case NUM_TYPE_S8:
		if ((*num < -127) || (*num > 127))
			goto err;
		break;
	case NUM_TYPE_U8:
		if (*num > 255)
			goto err;
		break;
	case NUM_TYPE_S16:
		if ((*num < -32767) || (*num > 32767))
			goto err;
		break;
	case NUM_TYPE_U16:
		if (*num > 65535)
			goto err;
		break;
	case NUM_TYPE_S32:
		if ((*num < -2147483647) || (*num > 2147483647))
			goto err;
		break;
	case NUM_TYPE_U32:
		if (*num > 4294967295)
			goto err;
		break;
	case NUM_TYPE_S64:
		if ((*num < -9223372036854775807) ||
		    (*num > 9223372036854775807))
			goto err;
		break;
	case NUM_TYPE_U64:
		if (*num > 0xFFFFFFFFFFFFFFFF)
			goto err;
		break;
	default:
		goto err;
	}
	return SR_ERR_OK;
err:
	return SR_ERR_INVAL_ARG;
}
