/**
 * @file qbu.c
 * @author Xiaolin He
 * @brief Application to configure TSN-QBU function based on sysrepo datastore.
 *
 * Copyright 2019-2020 NXP
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
#include <cjson/cJSON.h>

#include "common.h"
#include "main.h"
#include "qbu.h"

void clr_qbu(sr_val_t *val, uint32_t *tc, uint8_t *pt,
		sr_change_oper_t *oper)
{
	char *tc_str;
	sr_xpath_ctx_t xp_ctx = {0};
	char *nodename;

	if (!val || val->type == SR_LIST_T
	    || val->type == SR_CONTAINER_PRESENCE_T)
		return;

	tc_str = sr_xpath_key_value(val->xpath,
				    "frame-preemption-status-table",
				    "traffic-class", &xp_ctx);
	if (!tc_str)
		return;

	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(val->xpath);
	if (strcmp(nodename, "traffic-class") == 0)
		*tc = val->data.uint8_val;
	else if (strcmp(nodename, "frame-preemption-status") == 0)
		*pt &= ~(1 << *tc);
}

int parse_qbu(sr_val_t *val, uint32_t *tc, uint8_t *pt,
		sr_change_oper_t *oper)
{
	char *tc_str;
	sr_xpath_ctx_t xp_ctx = {0};
	char *nodename;
	int rc;

	if (val->type == SR_LIST_T || val->type == SR_CONTAINER_PRESENCE_T)
		return 1;

	tc_str = sr_xpath_key_value(val->xpath,
				    "frame-preemption-status-table",
				    "traffic-class", &xp_ctx);
	if (!tc_str)
		return 1;

	rc = 0;
	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(val->xpath);
	if (strcmp(nodename, "traffic-class") == 0) {
		*tc = val->data.uint8_val;
	} else if (strcmp(nodename, "frame-preemption-status") == 0) {
		if (oper && *oper == SR_OP_DELETED)
			*pt &= ~(1 << *tc);
		else if (strcmp(val->data.string_val, "preemptable") == 0)
			*pt ^=  (1 << *tc);
	} else {
		rc = 1;
	}

	return rc;
}

int abort_qbu_config(sr_session_ctx_t *session, char *path,
		uint32_t *tc_num, uint8_t *pt_num)
{
	int rc = SR_ERR_OK;
	sr_change_oper_t oper;
	sr_val_t *old_value;
	sr_val_t *new_value;
	sr_change_iter_t *it;
	char err_msg[MSG_MAX_LEN] = {0};

	rc = sr_get_changes_iter(session, path, &it);
	if (rc != SR_ERR_OK) {
		snprintf(err_msg, MSG_MAX_LEN,
			 "Get changes from %s failed", path);
		sr_set_error(session, err_msg, path);

		printf("ERROR: Get changes from %s failed\n", path);
		goto out;
	}
	while (SR_ERR_OK == (rc = sr_get_change_next(session, it, &oper,
						     &old_value,
						     &new_value))) {
		if (oper == SR_OP_DELETED) {
			if (old_value) {
				clr_qbu(old_value, tc_num, pt_num, &oper);
				continue;
			} else {
				pt_num = 0;
			}
		}
		parse_qbu(old_value, tc_num, pt_num, &oper);
	}
	if (rc == SR_ERR_NOT_FOUND)
		rc = SR_ERR_OK;

out:
	return rc;
}

int config_qbu_per_port(sr_session_ctx_t *session, char *path, bool abort,
		char *ifname)
{
	int rc = SR_ERR_OK;
	sr_change_oper_t oper;
	sr_val_t *values;
	size_t count;
	size_t i;
	uint32_t tc_num = 0;
	uint8_t pt_num = 0;
	int valid = 0;
	char xpath[XPATH_MAX_LEN] = {0};
	char err_msg[MSG_MAX_LEN] = {0};

	rc = sr_get_items(session, path, &values, &count);
	if (rc == SR_ERR_NOT_FOUND) {
		/*
		 * If can't find any item, we should check whether this
		 * container was deleted.
		 */
		if (is_del_oper(session, path)) {
			printf("WARN: %s was deleted, disable %s",
			       path, "this Instance.\n");
			pt_num = 0;
			goto config_qbu;
		} else {
			printf("WARN: %s sr_get_items: %s\n", __func__,
			       sr_strerror(rc));
			return SR_ERR_OK;
		}
	} else if (rc != SR_ERR_OK) {
		snprintf(err_msg, MSG_MAX_LEN,
			 "Get items from %s failed", path);
		sr_set_error(session, err_msg, path);

		printf("ERROR: %s sr_get_items: %s\n", __func__,
		       sr_strerror(rc));
		return rc;
	}

	for (i = 0; i < count; i++) {
		if (values[i].type == SR_LIST_T
		    || values[i].type == SR_CONTAINER_PRESENCE_T)
			continue;

		if (!parse_qbu(&values[i], &tc_num, &pt_num, &oper))
			valid++;
	}
	if (!valid)
		return rc;

	if (abort) {
		rc = abort_qbu_config(session, path, &tc_num, &pt_num);
		if (rc != SR_ERR_OK)
			goto cleanup;
	}

config_qbu:
	init_tsn_socket();
	rc = tsn_qbu_set(ifname, pt_num);
	close_tsn_socket();
	if (rc < 0) {
		snprintf(xpath, XPATH_MAX_LEN, "%s[name='%s']/%s:*//*",
			 IF_XPATH, ifname, QBU_MODULE_NAME);
		snprintf(err_msg, MSG_MAX_LEN, "Set Qbu error: %s",
			 strerror(-rc));
		sr_set_error(session, err_msg, xpath);

		printf("set qbu error, %s!\n", strerror(-rc));
		rc = errno2sp(-rc);
		goto cleanup;
	}

cleanup:
	sr_free_values(values, count);

	return rc;
}

int qbu_config(sr_session_ctx_t *session, const char *path, bool abort)
{
	int rc = SR_ERR_OK;
	sr_xpath_ctx_t xp_ctx = {0};
	sr_change_iter_t *it;
	sr_val_t *old_value;
	sr_val_t *new_value;
	sr_val_t *value;
	sr_change_oper_t oper;
	char *ifname;
	char ifname_bak[IF_NAME_MAX_LEN] = {0};
	char xpath[XPATH_MAX_LEN] = {0};
	char err_msg[MSG_MAX_LEN] = {0};

	rc = sr_get_changes_iter(session, path, &it);
	if (rc != SR_ERR_OK) {
		snprintf(err_msg, MSG_MAX_LEN, "Get changes from %s failed",
			 path);
		sr_set_error(session, err_msg, path);

		printf("ERROR: %s sr_get_changes_iter: %s\n", __func__,
		       sr_strerror(rc));
		goto cleanup;
	}

	while (SR_ERR_OK == (rc = sr_get_change_next(session, it,
					&oper, &old_value, &new_value))) {
		value = new_value ? new_value : old_value;
		ifname = sr_xpath_key_value(value->xpath, "interface",
					    "name", &xp_ctx);
		if (!ifname)
			continue;

		if (strcmp(ifname, ifname_bak)) {
			snprintf(ifname_bak, IF_NAME_MAX_LEN, "%s", ifname);
			snprintf(xpath, XPATH_MAX_LEN,
				 "%s[name='%s']/%s:*//*", IF_XPATH, ifname,
				 QBU_MODULE_NAME);
			rc = config_qbu_per_port(session, xpath, abort, ifname);
			if (rc != SR_ERR_OK)
				break;
		}
	}
	if (rc == SR_ERR_NOT_FOUND)
		rc = SR_ERR_OK;
cleanup:
	return rc;
}

int qbu_subtree_change_cb(sr_session_ctx_t *session, const char *path,
		sr_notif_event_t event, void *private_ctx)
{
	int rc = SR_ERR_OK;
	char xpath[XPATH_MAX_LEN] = {0};

	snprintf(xpath, XPATH_MAX_LEN, "%s/%s:*//*", IF_XPATH,
		 QBU_MODULE_NAME);
	switch (event) {
	case SR_EV_VERIFY:
	case SR_EV_ENABLED:
		rc = qbu_config(session, xpath, false);
		break;
	case SR_EV_APPLY:
		break;
	case SR_EV_ABORT:
		rc = qbu_config(session, xpath, true);
		break;
	default:
		break;
	}

	return rc;
}
