/**
 * @file qci_sg.c
 * @author Xiaolin He
 * @brief Implementation of Stream Gate function based on sysrepo
 * datastore.
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
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <cjson/cJSON.h>

#include "common.h"
#include "main.h"
#include "qci.h"

#define CFG_CHANGE (QCIPSFP_NM ":config-change")
#define ADMIN_CTR_LIST_LEN (QCIPSFP_NM ":admin-control-list-length")
#define ADMIN_CT_EXT (QCIPSFP_NM ":admin-cycle-time-extension")
#define GC_DUE_OCT_RX_EN (QCIPSFP_NM ":gate-closed-due-to-invalid-rx-enable")
#define GC_DUE_OCT_RX (QCIPSFP_NM ":gate-closed-due-to-invalid-rx")
#define GC_DUE_OCT_EX_EN (QCIPSFP_NM ":gate-closed-due-octets-exceeded-enable")
#define GC_DUE_OCT_EX (QCIPSFP_NM ":gate-closed-due-octets-exceeded")

struct std_qci_list *sg_list_head;

void clr_qci_sg(sr_session_ctx_t *session, sr_val_t *value,
		struct std_sg *sgi)
{
	sr_xpath_ctx_t xp_ctx = {0};
	char *nodename;
	char *index;
	uint64_t u64_val;
	struct tsn_qci_psfp_gcl *entry = sgi->sgconf.admin.gcl;

	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		return;

	if (!strcmp(nodename, "gate-enable")) {
		sgi->enable = false;
	} else if (!strcmp(nodename, "stream-gate-instance-id")) {
		sgi->sg_handle = 0;
	} else if (!strcmp(nodename, "admin-gate-states")) {
		sgi->sgconf.admin.gate_states = false;
	} else if (!strcmp(nodename, "admin-ipv")) {
		sgi->sgconf.admin.init_ipv = -1;
	} else if (!strcmp(nodename, ADMIN_CTR_LIST_LEN)) {
		sgi->sgconf.admin.control_list_length = 0;
	} else if (!strcmp(nodename, "gate-state-value")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "admin-control-list",
					   "index", &xp_ctx);
		u64_val = strtoul(index, NULL, 0);

		(entry + u64_val)->gate_state = false;
	} else if (!strcmp(nodename, "ipv-value")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "admin-control-list",
					   "index", &xp_ctx);
		u64_val = strtoul(index, NULL, 0);

		(entry + u64_val)->ipv = -1;
	} else if (!strcmp(nodename, "time-interval-value")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "admin-control-list",
					   "index", &xp_ctx);
		u64_val = strtoul(index, NULL, 0);

		(entry + u64_val)->time_interval = 0;
	} else if (!strcmp(nodename, "interval-octet-max")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "admin-control-list",
					   "index", &xp_ctx);
		u64_val = strtoul(index, NULL, 0);

		(entry + u64_val)->octet_max = 0;
	} else if (!strcmp(nodename, "numerator")) {
		sgi->cycletime.numerator = 0;
	} else if (!strcmp(nodename, "denominator")) {
		sgi->cycletime.denominator = 0;
		sgi->cycletime_f = false;
	} else if (!strcmp(nodename, "seconds")) {
		sgi->basetime.seconds = 0;
	} else if (!strcmp(nodename, "nanoseconds")) {
		sgi->basetime.nanoseconds = 0;
		sgi->basetime_f = false;
	} else if (!strcmp(nodename, ADMIN_CT_EXT)) {
		sgi->sgconf.admin.cycle_time_extension = 0;
	} else if (!strcmp(nodename, CFG_CHANGE)) {
		sgi->sgconf.config_change = false;
	} else if (!strcmp(nodename, GC_DUE_OCT_RX_EN)) {
		sgi->sgconf.block_invalid_rx_enable = false;
	} else if (!strcmp(nodename, GC_DUE_OCT_RX)) {
		sgi->sgconf.block_invalid_rx = false;
	} else if (!strcmp(nodename, GC_DUE_OCT_EX_EN)) {
		sgi->sgconf.block_octets_exceeded_enable = value->data.bool_val;
	} else if (!strcmp(nodename, GC_DUE_OCT_EX)) {
		sgi->sgconf.block_octets_exceeded = false;
	}
}

int parse_qci_sg(sr_session_ctx_t *session, sr_val_t *value,
		struct std_sg *sgi)
{
	int rc = SR_ERR_OK;
	sr_xpath_ctx_t xp_ctx = {0};
	uint8_t u8_val = 0;
	uint64_t u64_val = 0;
	char *nodename;
	char *num_str;
	char *index;
	char err_msg[MSG_MAX_LEN] = {0};
	struct tsn_qci_psfp_gcl *entry = sgi->sgconf.admin.gcl;

	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		goto out;

	if (!strcmp(nodename, "gate-enable")) {
		sgi->enable = value->data.bool_val;
	} else if (!strcmp(nodename, "stream-gate-instance-id")) {
		sgi->sg_handle = value->data.uint32_val;
	} else if (!strcmp(nodename, "admin-gate-states")) {
		num_str = value->data.enum_val;
		if (!strcmp(num_str, "open")) {
			sgi->sgconf.admin.gate_states = true;
		} else if (!strcmp(num_str, "closed")) {
			sgi->sgconf.admin.gate_states = false;
		} else {
			snprintf(err_msg, MSG_MAX_LEN, "Invalid '%s'", num_str);
			sr_set_error(session, err_msg, value->xpath);

			printf("ERROR: Invalid '%s' in %s!\n", num_str,
			       value->xpath);
			rc = SR_ERR_INVAL_ARG;
			goto out;
		}
	} else if (!strcmp(nodename, "admin-ipv")) {
		pri2num(value->data.enum_val, &sgi->sgconf.admin.init_ipv);
	} else if (!strcmp(nodename, ADMIN_CTR_LIST_LEN)) {
		u8_val = (uint8_t)value->data.int32_val;
		sgi->sgconf.admin.control_list_length = u8_val;
	} else if (!strcmp(nodename, "gate-state-value")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "admin-control-list",
					   "index", &xp_ctx);
		u64_val = strtoul(index, NULL, 0);
		if (u64_val >= sgi->sgconf.admin.control_list_length)
			goto out;

		num_str = value->data.enum_val;
		if (!strcmp(num_str, "open")) {
			(entry + u64_val)->gate_state = true;
		} else if (!strcmp(num_str, "closed")) {
			(entry + u64_val)->gate_state = false;
		} else {
			snprintf(err_msg, MSG_MAX_LEN, "Invalid '%s'", num_str);
			sr_set_error(session, err_msg, value->xpath);
			rc = SR_ERR_INVAL_ARG;
			goto out;
		}
	} else if (!strcmp(nodename, "ipv-value")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "admin-control-list",
					   "index", &xp_ctx);
		u64_val = strtoul(index, NULL, 0);
		if (u64_val >= sgi->sgconf.admin.control_list_length)
			goto out;

		pri2num(value->data.enum_val, &(entry + u64_val)->ipv);
	} else if (!strcmp(nodename, "time-interval-value")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "admin-control-list",
					   "index", &xp_ctx);
		u64_val = strtoul(index, NULL, 0);
		if (u64_val >= sgi->sgconf.admin.control_list_length)
			goto out;

		(entry + u64_val)->time_interval = value->data.uint32_val;
	} else if (!strcmp(nodename, "interval-octet-max")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "admin-control-list",
					   "index", &xp_ctx);
		u64_val = strtoul(index, NULL, 0);
		if (u64_val >= sgi->sgconf.admin.control_list_length)
			goto out;

		(entry + u64_val)->octet_max = value->data.uint32_val;
	} else if (!strcmp(nodename, "numerator")) {
		sgi->cycletime.numerator = value->data.uint32_val;
	} else if (!strcmp(nodename, "denominator")) {
		sgi->cycletime.denominator = value->data.uint32_val;
		if (!sgi->cycletime.denominator) {
			snprintf(err_msg, MSG_MAX_LEN,
				 "The value of %s is zero", value->xpath);
			sr_set_error(session, err_msg, value->xpath);

			printf("ERROR: denominator is zero!\n");
			rc = SR_ERR_INVAL_ARG;
			goto out;
		}
		sgi->cycletime_f = true;
	} else if (!strcmp(nodename, "seconds")) {
		sgi->basetime.seconds = value->data.uint64_val;
		sgi->basetime_f = true;
	} else if (!strcmp(nodename, "nanoseconds")) {
		sgi->basetime.nanoseconds = (uint64_t)value->data.uint32_val;
		sgi->basetime_f = true;
	} else if (!strcmp(nodename, ADMIN_CT_EXT)) {
		sgi->sgconf.admin.cycle_time_extension = value->data.int32_val;
	} else if (!strcmp(nodename, CFG_CHANGE)) {
		sgi->sgconf.config_change = value->data.bool_val;
	} else if (!strcmp(nodename, GC_DUE_OCT_RX_EN)) {
		sgi->sgconf.block_invalid_rx_enable = value->data.bool_val;
	} else if (!strcmp(nodename, GC_DUE_OCT_RX)) {
		sgi->sgconf.block_invalid_rx = value->data.bool_val;
	} else if (!strcmp(nodename, GC_DUE_OCT_EX_EN)) {
		sgi->sgconf.block_octets_exceeded_enable = value->data.bool_val;
	} else if (!strcmp(nodename, GC_DUE_OCT_EX)) {
		sgi->sgconf.block_octets_exceeded = value->data.bool_val;
	}

out:
	return rc;
}

int get_sg_per_port_per_id(sr_session_ctx_t *session, const char *path)
{
	int rc = SR_ERR_OK;
	sr_change_iter_t *it;
	sr_xpath_ctx_t xp_ctx_cp = {0};
	sr_xpath_ctx_t xp_ctx_id = {0};
	sr_change_oper_t oper;
	sr_val_t *old_value;
	sr_val_t *new_value;
	sr_val_t *value;
	char err_msg[MSG_MAX_LEN] = {0};
	char *cpname;
	char *sg_id;
	uint32_t sgid = 0;
	struct std_qci_list *cur_node = NULL;
	char sgid_bak[IF_NAME_MAX_LEN] = "unknown";

	rc = sr_get_changes_iter(session, path, &it);

	if (rc != SR_ERR_OK) {
		snprintf(err_msg, MSG_MAX_LEN,
			 "Get changes from %s failed", path);
		sr_set_error(session, err_msg, path);

		printf("ERROR: %s sr_get_changes_iter: %s", __func__,
		       sr_strerror(rc));
		goto out;
	}

	while (SR_ERR_OK == (rc = sr_get_change_next(session, it,
					&oper, &old_value, &new_value))) {
		value = new_value ? new_value : old_value;
		if (!value)
			continue;

		sg_id = sr_xpath_key_value(value->xpath,
					    "stream-gate-instance-table",
					    "stream-gate-instance-id",
					    &xp_ctx_id);

		if ((!sg_id) || !strncmp(sg_id, sgid_bak, IF_NAME_MAX_LEN))
			continue;

		snprintf(sgid_bak, IF_NAME_MAX_LEN, "%s", sg_id);

		sgid = strtoul(sg_id, NULL, 0);
		cpname = sr_xpath_key_value(value->xpath, "component",
					    "name", &xp_ctx_cp);
		if (!cpname)
			continue;

		if (!sg_list_head) {
			sg_list_head = new_list_node(QCI_T_SG, cpname, sgid);
			if (!sg_list_head) {
				snprintf(err_msg, MSG_MAX_LEN, "%s in %s\n",
					 "Create new node failed",
					 value->xpath);
				sr_set_error(session, err_msg, path);
				rc = SR_ERR_NOMEM;
				goto out;
			}
			continue;
		}
		cur_node = is_node_in_list(sg_list_head, cpname, sgid,
					   QCI_T_SG);
		if (!cur_node) {
			cur_node = new_list_node(QCI_T_SG, cpname, sgid);
			if (!cur_node) {
				snprintf(err_msg, MSG_MAX_LEN, "%s in %s\n",
					 "Create new node failed",
					 value->xpath);
				sr_set_error(session, err_msg, path);
				rc = SR_ERR_NOMEM;
				goto out;
			}

			add_node2list(sg_list_head, cur_node);
		}
	}
	if (rc == SR_ERR_NOT_FOUND)
		rc = SR_ERR_OK;

out:
	return rc;
}

int abort_sg_config(sr_session_ctx_t *session, char *path,
		struct std_qci_list *node)
{
	int rc = SR_ERR_OK;
	sr_change_oper_t oper;
	sr_val_t *old_value;
	sr_val_t *new_value;
	sr_change_iter_t *it;
	char err_msg[MSG_MAX_LEN] = {0};

	rc = sr_get_changes_iter(session, path, &it);
	if (rc != SR_ERR_OK) {
		snprintf(err_msg, MSG_MAX_LEN, "Get changes from %s failed",
			 path);
		sr_set_error(session, err_msg, path);
		printf("ERROR: Get changes from %s failed\n", path);
		goto out;
	}

	while (SR_ERR_OK == (rc = sr_get_change_next(session, it, &oper,
						     &old_value,
						     &new_value))) {
		if (oper == SR_OP_DELETED) {
			if (!old_value)
				continue;

			clr_qci_sg(session, old_value, node->sg_ptr);
			continue;
		}
		parse_qci_sg(session, new_value, node->sg_ptr);
	}

	if (rc == SR_ERR_NOT_FOUND)
		rc = SR_ERR_OK;

out:
	return rc;
}

int parse_sg_per_port_per_id(sr_session_ctx_t *session, bool abort)
{
	int rc = SR_ERR_OK;
	sr_val_t *values;
	size_t count;
	size_t i;
	char err_msg[MSG_MAX_LEN] = {0};
	struct std_qci_list *cur_node = sg_list_head;
	char xpath[XPATH_MAX_LEN] = {0,};

	while (cur_node) {
		snprintf(xpath, XPATH_MAX_LEN,
			 "%s[name='%s']%s[stream-gate-instance-id='%u']//*",
			 BRIDGE_COMPONENT_XPATH, cur_node->sg_ptr->port,
			 SGI_XPATH, cur_node->sg_ptr->sg_id);
		if (abort) {
			rc = abort_sg_config(session, xpath, cur_node);
			if (rc != SR_ERR_OK)
				goto out;

			cur_node = cur_node->next;
			continue;
		}

		rc = sr_get_items(session, xpath, &values, &count);
		if (rc == SR_ERR_NOT_FOUND) {
			rc = SR_ERR_OK;
			cur_node = cur_node->next;
			/*
			 * If can't find any item, we should check whether this
			 * container was deleted.
			 */
			if (is_del_oper(session, xpath)) {
				printf("WARN: %s was deleted, disable %s",
				       xpath, "this Instance.\n");
				cur_node->sg_ptr->enable = false;
			} else {
				printf("WARN: %s sr_get_items: %s\n", __func__,
				       sr_strerror(rc));
				del_list_node(cur_node->pre, QCI_T_SG);
			}
			continue;
		} else if (rc != SR_ERR_OK) {
			snprintf(err_msg, MSG_MAX_LEN,
				 "Get items from %s failed", xpath);
			sr_set_error(session, err_msg, xpath);
			printf("ERROR: %s sr_get_items: %s\n", __func__,
			       sr_strerror(rc));

			goto out;
		} else {
			for (i = 0; i < count; i++) {
				if (values[i].type == SR_LIST_T ||
				    values[i].type == SR_CONTAINER_PRESENCE_T)
					continue;

				rc = parse_qci_sg(session, &values[i],
						  cur_node->sg_ptr);
				if (rc != SR_ERR_OK) {
					cur_node->apply_st = APPLY_PARSE_ERR;
					sr_free_values(values, count);
					del_list_node(cur_node, QCI_T_SG);
					goto out;
				}
			}
			sr_free_values(values, count);
			cur_node->apply_st = APPLY_PARSE_SUC;

			cur_node = cur_node->next;
		}
	}

out:
	return rc;
}

int config_sg(sr_session_ctx_t *session)
{
	int rc = SR_ERR_OK;
	char err_msg[MSG_MAX_LEN] = {0};
	struct std_qci_list *cur_node = sg_list_head;
	char xpath[XPATH_MAX_LEN] = {0,};
	uint64_t time;
	struct tsn_qci_psfp_sgi_conf *sgi;

	init_tsn_socket();
	while (cur_node) {
		sgi = &cur_node->sg_ptr->sgconf;
		if (cur_node->sg_ptr->basetime_f) {
			time = cal_base_time(&cur_node->sg_ptr->basetime);
			sgi->admin.base_time = time;
		}
		if (cur_node->sg_ptr->cycletime_f) {
			time = cal_cycle_time(&cur_node->sg_ptr->cycletime);
			sgi->admin.cycle_time = time;
		}
		/* set new stream gates configuration */
		rc = tsn_qci_psfp_sgi_set(cur_node->sg_ptr->port,
					  cur_node->sg_ptr->sg_handle,
					  cur_node->sg_ptr->enable, sgi);
		if (rc < 0) {
			sprintf(err_msg,
				"failed to set stream gate, %s!",
				strerror(-rc));
			snprintf(xpath, XPATH_MAX_LEN,
				 "%s[name='%s']%s[%s='%u']//*",
				 "stream-gate-instance-id",
				 BRIDGE_COMPONENT_XPATH, cur_node->sf_ptr->port,
				 SGI_XPATH, cur_node->sg_ptr->sg_id);
			sr_set_error(session, err_msg, xpath);
			cur_node->apply_st = APPLY_SET_ERR;
			goto cleanup;
		} else {
			cur_node->apply_st = APPLY_SET_SUC;
		}
		if (cur_node->next == NULL)
			break;
		cur_node = cur_node->next;
	}

cleanup:
	close_tsn_socket();

	return rc;
}

int qci_sg_config(sr_session_ctx_t *session, const char *path, bool abort)
{
	int rc = SR_ERR_OK;

	if (!abort) {
		rc = get_sg_per_port_per_id(session, path);
		if (rc != SR_ERR_OK)
			goto out;
	}
	if (!sg_list_head)
		goto out;

	rc = parse_sg_per_port_per_id(session, abort);
	if (rc != SR_ERR_OK)
		goto out;

	rc = config_sg(session);
out:
	return rc;
}

int qci_sg_subtree_change_cb(sr_session_ctx_t *session, const char *path,
		sr_notif_event_t event, void *private_ctx)
{
	int rc = SR_ERR_OK;
	char xpath[XPATH_MAX_LEN] = {0,};

	snprintf(xpath, XPATH_MAX_LEN, "%s%s//*", BRIDGE_COMPONENT_XPATH,
		 QCISG_XPATH);
	switch (event) {
	case SR_EV_VERIFY:
		rc = qci_sg_config(session, xpath, false);
		break;
	case SR_EV_ENABLED:
		rc = qci_sg_config(session, xpath, false);
		break;
	case SR_EV_APPLY:
		free_list(sg_list_head, QCI_T_SG);
		sg_list_head = NULL;
		break;
	case SR_EV_ABORT:
		rc = qci_sg_config(session, xpath, true);
		free_list(sg_list_head, QCI_T_SG);
		sg_list_head = NULL;
		break;
	default:
		break;
	}

	return rc;
}
