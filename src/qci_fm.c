/**
 * @file qci_fm.c
 * @author Xiaolin He
 * @brief Implementation of Flow meter function based on sysrepo
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

struct std_qci_list *fm_list_head;

void clr_qci_fm(sr_session_ctx_t *session, sr_val_t *value,
		struct std_fm *fmi)
{
	sr_xpath_ctx_t xp_ctx = {0};
	char *nodename;

	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		return;

	if (!strcmp(nodename, "ieee802-dot1q-qci-augment:flow-meter-enabled"))
		fmi->enable = false;
	else if (!strcmp(nodename, "committed-information-rate"))
		fmi->fmconf.cir = 0;
	else if (!strcmp(nodename, "committed-burst-size"))
		fmi->fmconf.cbs = 0;
	else if (!strcmp(nodename, "excess-information-rate"))
		fmi->fmconf.eir = 0;
	else if (!strcmp(nodename, "excess-burst-size"))
		fmi->fmconf.ebs = 0;
	else if (!strcmp(nodename, "coupling-flag"))
		fmi->fmconf.cf = false;
	else if (!strcmp(nodename, "color-mode"))
		fmi->fmconf.cm = false;
	else if (!strcmp(nodename, "drop-on-yellow"))
		fmi->fmconf.drop_on_yellow  = false;
	else if (!strcmp(nodename, "mark-all-frames-red-enable"))
		fmi->fmconf.mark_red_enable = false;
}

int parse_qci_fm(sr_session_ctx_t *session, sr_val_t *value,
		struct std_fm *fmi)
{
	int rc = SR_ERR_OK;
	sr_xpath_ctx_t xp_ctx = {0};
	char *nodename;
	char *num_str;
	char err_msg[MSG_MAX_LEN] = {0};

	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		goto out;

	if (!strcmp(nodename, "ieee802-dot1q-qci-augment:flow-meter-enabled")) {
		fmi->enable = value->data.bool_val;
	} else if (!strcmp(nodename, "committed-information-rate")) {
		fmi->fmconf.cir = value->data.uint64_val / 1000;
	} else if (!strcmp(nodename, "committed-burst-size")) {
		fmi->fmconf.cbs = value->data.uint32_val;
	} else if (!strcmp(nodename, "excess-information-rate")) {
		fmi->fmconf.eir = value->data.uint64_val / 1000;
	} else if (!strcmp(nodename, "excess-burst-size")) {
		fmi->fmconf.ebs = value->data.uint32_val;
	} else if (!strcmp(nodename, "coupling-flag")) {
		num_str = value->data.enum_val;
		if (!strcmp(num_str, "zero")) {
			fmi->fmconf.cf = false;
		} else if (!strcmp(num_str, "one")) {
			fmi->fmconf.cf = true;
		} else {
			snprintf(err_msg, MSG_MAX_LEN, "Invalid '%s'", num_str);
			sr_set_error(session, err_msg, value->xpath);

			printf("ERROR: Invalid '%s' in %s!\n", num_str,
			       value->xpath);
			rc = SR_ERR_INVAL_ARG;
			goto out;
		}
	} else if (!strcmp(nodename, "color-mode")) {
		num_str = value->data.enum_val;
		if (!strcmp(num_str, "color-blind")) {
			fmi->fmconf.cm = false;
		} else if (!strcmp(num_str, "color-aware")) {
			fmi->fmconf.cm = true;
		} else {
			snprintf(err_msg, MSG_MAX_LEN, "Invalid '%s'", num_str);
			sr_set_error(session, err_msg, value->xpath);

			printf("ERROR: Invalid '%s' in %s!\n", num_str,
			       value->xpath);
			rc = SR_ERR_INVAL_ARG;
			goto out;
		}
	} else if (!strcmp(nodename, "drop-on-yellow")) {
		fmi->fmconf.drop_on_yellow  = value->data.bool_val;
	} else if (!strcmp(nodename, "mark-all-frames-red-enable")) {
		fmi->fmconf.mark_red_enable = value->data.bool_val;
	}

out:
	return rc;
}

int get_fm_per_port_per_id(sr_session_ctx_t *session, const char *path)
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
	char *fm_id;
	uint32_t fmid = 0;
	struct std_qci_list *cur_node = NULL;
	char fmid_bak[IF_NAME_MAX_LEN] = "unknown";

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

		fm_id = sr_xpath_key_value(value->xpath,
					    "flow-meter-instance-table",
					    "flow-meter-instance-id",
					    &xp_ctx_id);

		if ((!fm_id) || !strncmp(fm_id, fmid_bak, IF_NAME_MAX_LEN))
			continue;

		snprintf(fmid_bak, IF_NAME_MAX_LEN, "%s", fm_id);

		fmid = strtoul(fm_id, NULL, 0);
		cpname = sr_xpath_key_value(value->xpath, "component",
					    "name", &xp_ctx_cp);
		if (!cpname)
			continue;

		if (!fm_list_head) {
			fm_list_head = new_list_node(QCI_T_FM, cpname, fmid);
			if (!fm_list_head) {
				snprintf(err_msg, MSG_MAX_LEN, "%s in %s\n",
					 "Create new node failed",
					 value->xpath);
				sr_set_error(session, err_msg, path);
				rc = SR_ERR_NOMEM;
				goto out;
			}
			continue;
		}
		cur_node = is_node_in_list(fm_list_head, cpname, fmid,
					   QCI_T_FM);
		if (!cur_node) {
			cur_node = new_list_node(QCI_T_FM, cpname, fmid);
			if (!cur_node) {
				snprintf(err_msg, MSG_MAX_LEN, "%s in %s\n",
					 "Create new node failed",
					 value->xpath);
				sr_set_error(session, err_msg, path);
				rc = SR_ERR_NOMEM;
				goto out;
			}

			add_node2list(fm_list_head, cur_node);
		}
	}
	if (rc == SR_ERR_NOT_FOUND)
		rc = SR_ERR_OK;

out:
	return rc;
}

int abort_fm_config(sr_session_ctx_t *session, char *path,
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

			clr_qci_fm(session, old_value, node->fm_ptr);
			continue;
		}
		parse_qci_fm(session, new_value, node->fm_ptr);
	}

	if (rc == SR_ERR_NOT_FOUND)
		rc = SR_ERR_OK;

out:
	return rc;
}

int parse_fm_per_port_per_id(sr_session_ctx_t *session, bool abort)
{
	int rc = SR_ERR_OK;
	sr_val_t *values;
	size_t count;
	size_t i;
	char err_msg[MSG_MAX_LEN] = {0};
	struct std_qci_list *cur_node = fm_list_head;
	char xpath[XPATH_MAX_LEN] = {0,};

	while (cur_node) {
		snprintf(xpath, XPATH_MAX_LEN,
			 "%s[name='%s']%s[flow-meter-instance-id='%u']//*",
			 BRIDGE_COMPONENT_XPATH, cur_node->fm_ptr->port,
			 FMI_XPATH, cur_node->fm_ptr->fm_id);

		if (abort) {
			rc = abort_fm_config(session, xpath, cur_node);
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
				cur_node->fm_ptr->enable = false;
			} else {
				printf("WARN: %s sr_get_items: %s\n", __func__,
				       sr_strerror(rc));
				del_list_node(cur_node->pre, QCI_T_FM);
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

				rc = parse_qci_fm(session, &values[i],
						  cur_node->fm_ptr);
				if (rc != SR_ERR_OK) {
					cur_node->apply_st = APPLY_PARSE_ERR;
					sr_free_values(values, count);
					del_list_node(cur_node, QCI_T_FM);
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

int config_fm(sr_session_ctx_t *session)
{
	int rc = SR_ERR_OK;
	char err_msg[MSG_MAX_LEN] = {0};
	struct std_qci_list *cur_node = fm_list_head;
	char xpath[XPATH_MAX_LEN] = {0,};

	init_tsn_socket();
	while (cur_node) {
		/* set new flow meter configuration */
		rc = tsn_qci_psfp_fmi_set(cur_node->fm_ptr->port,
					  cur_node->fm_ptr->fm_id,
					  cur_node->fm_ptr->enable,
					  &(cur_node->fm_ptr->fmconf));
		if (rc < 0) {
			sprintf(err_msg,
				"failed to set flow meter, %s!",
				strerror(-rc));
			snprintf(xpath, XPATH_MAX_LEN,
				 "%s[name='%s']%s[%s='%u']//*",
				 "flow-meter-instance-id",
				 BRIDGE_COMPONENT_XPATH, cur_node->fm_ptr->port,
				 FMI_XPATH, cur_node->fm_ptr->fm_id);
			sr_set_error(session, err_msg, xpath);
			cur_node->apply_st = APPLY_SET_ERR;
			goto cleanup;
		} else {
			cur_node->apply_st = APPLY_SET_SUC;
		}
		cur_node = cur_node->next;
	}

cleanup:
	close_tsn_socket();

	return rc;
}

int qci_fm_config(sr_session_ctx_t *session, const char *path, bool abort)
{
	int rc = SR_ERR_OK;

	if (!abort) {
		rc = get_fm_per_port_per_id(session, path);
		if (rc != SR_ERR_OK)
			goto out;
	}
	if (!fm_list_head)
		goto out;

	rc = parse_fm_per_port_per_id(session, abort);
	if (rc != SR_ERR_OK)
		goto out;

	rc = config_fm(session);
out:
	return rc;
}

int qci_fm_subtree_change_cb(sr_session_ctx_t *session, const char *path,
		sr_notif_event_t event, void *private_ctx)
{
	int rc = SR_ERR_OK;
	char xpath[XPATH_MAX_LEN] = {0,};

	snprintf(xpath, XPATH_MAX_LEN, "%s%s//*", BRIDGE_COMPONENT_XPATH,
		 QCIFM_XPATH);
	switch (event) {
	case SR_EV_VERIFY:
		rc = qci_fm_config(session, xpath, false);
		break;
	case SR_EV_ENABLED:
		rc = qci_fm_config(session, xpath, false);
		break;
	case SR_EV_APPLY:
		free_list(fm_list_head, QCI_T_FM);
		fm_list_head = NULL;
		break;
	case SR_EV_ABORT:
		rc = qci_fm_config(session, xpath, true);
		free_list(fm_list_head, QCI_T_FM);
		fm_list_head = NULL;
		break;
	default:
		break;
	}

	return rc;
}
