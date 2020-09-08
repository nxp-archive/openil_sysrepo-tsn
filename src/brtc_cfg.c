/**
 * @file brtc_cfg.c
 * @author hongbo wang
 * @brief Application to configure bridge vlan based on sysrepo datastore.
 *
 * Copyright 2020 NXP
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

#include "brtc_cfg.h"

struct item_qdisc {
	char action[MAX_PARA_LEN];
	char block[MAX_PARA_LEN];
	char ifname[MAX_PARA_LEN];
};

struct item_filter {
	uint16_t vlan_id;
	uint16_t priority;
	uint16_t src_port;
	uint16_t dst_port;

	char src_ip[MAX_PARA_LEN];
	char dst_ip[MAX_PARA_LEN];
	char src_mac[MAX_PARA_LEN];
	char dst_mac[MAX_PARA_LEN];
	char action[MAX_PARA_LEN];
	char protocol[MAX_PARA_LEN];
	char parent[MAX_PARA_LEN];
	char type[MAX_PARA_LEN];
	char skip_type[MAX_PARA_LEN];
	char ifname[MAX_PARA_LEN];
	char action_spec[MAX_ACTION_LEN];
};

struct item_cfg {
	bool valid;
	uint32_t vid;
	uint8_t sub_flag;
	struct item_qdisc qdisc;
	struct item_filter filter;
};
static struct item_cfg sitem_conf;

static char stc_cmd[MAX_CMD_LEN];
static char stc_subcmd[MAX_CMD_LEN];

static int change_mac_format(char *pbuf)
{
	int i = 0;

	if (!pbuf)
		return -1;

	for (i = 0; i < strlen(pbuf); i++) {
		if (pbuf[i] == '-')
			pbuf[i] = ':';
	}

	return 0;
}

static int parse_node(sr_session_ctx_t *session, sr_val_t *value,
			struct item_cfg *conf)
{
	int rc = SR_ERR_OK;
	sr_xpath_ctx_t xp_ctx = {0};
	char *strval = NULL;
	char *nodename = NULL;

	if (!session || !value || !conf)
		return rc;

	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		goto ret_tag;

	strval = value->data.string_val;

	if (!strcmp(nodename, "tc-flower-id")) {
		memset(conf, 0, sizeof(struct item_cfg));
	} else if (!strcmp(nodename, "qdisc")) {
		conf->sub_flag = SUB_ITEM_QDISC;
	} else if (!strcmp(nodename, "filter")) {
		conf->sub_flag = SUB_ITEM_FILTER;
	} else if (!strcmp(nodename, "action")) {
		if (conf->sub_flag == SUB_ITEM_QDISC)
			_PARA(conf->qdisc.action, MAX_PARA_LEN, strval);
		else if (conf->sub_flag == SUB_ITEM_FILTER)
			_PARA(conf->filter.action, MAX_PARA_LEN, strval);
	} else if (!strcmp(nodename, "interface")) {
		if (conf->sub_flag == SUB_ITEM_QDISC)
			_PARA(conf->qdisc.ifname, MAX_PARA_LEN, strval);
		else if (conf->sub_flag == SUB_ITEM_FILTER)
			_PARA(conf->filter.ifname, MAX_PARA_LEN, strval);
	} else if (!strcmp(nodename, "block")) {
		if (conf->sub_flag == SUB_ITEM_QDISC)
			_PARA(conf->qdisc.block, MAX_PARA_LEN, strval);
	} else if (!strcmp(nodename, "protocol")) {
		if (conf->sub_flag == SUB_ITEM_FILTER)
			_PARA(conf->filter.protocol, MAX_PARA_LEN, strval);
	} else if (!strcmp(nodename, "parent")) {
		if (conf->sub_flag == SUB_ITEM_FILTER)
			_PARA(conf->filter.parent, MAX_PARA_LEN, strval);
	} else if (!strcmp(nodename, "filter_type")) {
		if (conf->sub_flag == SUB_ITEM_FILTER)
			_PARA(conf->filter.type, MAX_PARA_LEN, strval);
	} else if (!strcmp(nodename, "skip_type")) {
		if (conf->sub_flag == SUB_ITEM_FILTER)
			_PARA(conf->filter.skip_type, MAX_PARA_LEN, strval);
	} else if (!strcmp(nodename, "vlan_id")) {
		if (conf->sub_flag == SUB_ITEM_FILTER)
			conf->filter.vlan_id = value->data.uint16_val;
	} else if (!strcmp(nodename, "priority")) {
		if (conf->sub_flag == SUB_ITEM_FILTER)
			conf->filter.priority = value->data.uint16_val;
	} else if (!strcmp(nodename, "src_ip")) {
		if (conf->sub_flag == SUB_ITEM_FILTER)
			_PARA(conf->filter.src_ip, MAX_PARA_LEN, strval);
	} else if (!strcmp(nodename, "dst_ip")) {
		if (conf->sub_flag == SUB_ITEM_FILTER)
			_PARA(conf->filter.dst_ip, MAX_PARA_LEN, strval);
	} else if (!strcmp(nodename, "src_port")) {
		if (conf->sub_flag == SUB_ITEM_FILTER)
			conf->filter.src_port = value->data.uint16_val;
	} else if (!strcmp(nodename, "dst_port")) {
		if (conf->sub_flag == SUB_ITEM_FILTER)
			conf->filter.dst_port = value->data.uint16_val;
	} else if (!strcmp(nodename, "src_mac")) {
		if (conf->sub_flag == SUB_ITEM_FILTER) {
			_PARA(conf->filter.src_mac, MAX_PARA_LEN, strval);
			change_mac_format(conf->filter.src_mac);
		}
	} else if (!strcmp(nodename, "dst_mac")) {
		if (conf->sub_flag == SUB_ITEM_FILTER) {
			_PARA(conf->filter.dst_mac, MAX_PARA_LEN, strval);
			change_mac_format(conf->filter.dst_mac);
		}
	} else if (!strcmp(nodename, "action_spec")) {
		if (conf->sub_flag == SUB_ITEM_FILTER) {
			conf->valid = true;
			_PARA(conf->filter.action_spec, MAX_ACTION_LEN, strval);
		}
	}

ret_tag:
	return rc;
}

static int parse_item(sr_session_ctx_t *session, char *path,
			struct item_cfg *conf)
{
	size_t i;
	size_t count;
	int rc = SR_ERR_OK;
	sr_val_t *values = NULL;
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
			goto cleanup;
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

		rc = parse_node(session, &values[i], conf);
	}

cleanup:
	sr_free_values(values, count);

	return rc;
}

static int parse_config(sr_session_ctx_t *session, const char *path)
{
	int rc = SR_ERR_OK;
	sr_change_oper_t oper;
	char *ifname = NULL;
	sr_val_t *value = NULL;
	sr_val_t *old_value = NULL;
	sr_val_t *new_value = NULL;
	sr_change_iter_t *it = NULL;
	sr_xpath_ctx_t xp_ctx = {0};
	char xpath[XPATH_MAX_LEN] = {0};
	char err_msg[MSG_MAX_LEN] = {0};
	char ifname_bak[MAX_VLAN_LEN] = {0};
	struct item_cfg *conf = &sitem_conf;

	memset(conf, 0, sizeof(struct item_cfg));

	snprintf(xpath, XPATH_MAX_LEN, "%s//*", path);

	rc = sr_get_changes_iter(session, xpath, &it);
	if (rc != SR_ERR_OK) {
		snprintf(err_msg, MSG_MAX_LEN,
			 "Get changes from %s failed", xpath);
		sr_set_error(session, err_msg, xpath);

		printf("ERROR: %s sr_get_changes_iter: %s\n", __func__,
		       sr_strerror(rc));
		goto cleanup;
	}

	while (SR_ERR_OK == (rc = sr_get_change_next(session, it,
					&oper, &old_value, &new_value))) {

		value = new_value ? new_value : old_value;
		if (!value)
			continue;

		ifname = sr_xpath_key_value(value->xpath, "bridge",
					    "name", &xp_ctx);

		sr_free_val(old_value);
		sr_free_val(new_value);

		if (!ifname)
			continue;

		if (!strcmp(ifname, ifname_bak))
			continue;
		snprintf(ifname_bak, MAX_VLAN_LEN, "%s", ifname);

		rc = parse_item(session, xpath, conf);
		if (rc != SR_ERR_OK)
			break;
	}

	if (rc == SR_ERR_NOT_FOUND)
		rc = SR_ERR_OK;

cleanup:
	return rc;
}

static int set_config(sr_session_ctx_t *session, bool abort)
{
	pid_t sysret = 0;
	int rc = SR_ERR_OK;
	struct item_cfg *conf = &sitem_conf;

	if (abort) {
		memset(conf, 0, sizeof(struct item_cfg));
		return rc;
	}

	if (!conf->valid)
		return rc;

	if ((strlen(conf->qdisc.action) == 0)
			|| (strlen(conf->qdisc.ifname) == 0))
		return rc;

	if ((strlen(conf->filter.action) == 0)
			|| (strlen(conf->filter.ifname) == 0))
		return rc;

	snprintf(stc_cmd, MAX_CMD_LEN, "tc qdisc %s dev %s %s\n",
		conf->qdisc.action, conf->qdisc.ifname, conf->qdisc.block);
	system(stc_cmd);
	printf("qdisc: %s\n", stc_cmd);

	snprintf(stc_cmd, MAX_CMD_LEN, "tc filter %s dev %s ",
		conf->filter.action, conf->filter.ifname);

	if (strlen(conf->filter.parent) > 0) {
		snprintf(stc_subcmd, MAX_CMD_LEN, "parent %s ",
				conf->filter.parent);
		strncat(stc_cmd, stc_subcmd, MAX_CMD_LEN - 1 - strlen(stc_cmd));
	}
	if (strlen(conf->filter.protocol) > 0) {
		snprintf(stc_subcmd, MAX_CMD_LEN, "protocol %s ",
				conf->filter.protocol);
		strncat(stc_cmd, stc_subcmd, MAX_CMD_LEN - 1 - strlen(stc_cmd));
	}
	if (strlen(conf->filter.type) > 0) {
		snprintf(stc_subcmd, MAX_CMD_LEN, "%s ", conf->filter.type);
		strncat(stc_cmd, stc_subcmd, MAX_CMD_LEN - 1 - strlen(stc_cmd));
	}
	if (strlen(conf->filter.skip_type) > 0) {
		snprintf(stc_subcmd, MAX_CMD_LEN, "%s ",
				conf->filter.skip_type);
		strncat(stc_cmd, stc_subcmd, MAX_CMD_LEN - 1 - strlen(stc_cmd));
	}
	if (conf->filter.vlan_id > 0) {
		snprintf(stc_subcmd, MAX_CMD_LEN, "vlan_id %d ",
				conf->filter.vlan_id);
		strncat(stc_cmd, stc_subcmd, MAX_CMD_LEN - 1 - strlen(stc_cmd));
	}
	if (conf->filter.priority > 0) {
		snprintf(stc_subcmd, MAX_CMD_LEN, "vlan_prio %d ",
				conf->filter.priority);
		strncat(stc_cmd, stc_subcmd, MAX_CMD_LEN - 1 - strlen(stc_cmd));
	}
	if (strlen(conf->filter.src_ip) > 0) {
		snprintf(stc_subcmd, MAX_CMD_LEN, "src_ip %s ",
				conf->filter.src_ip);
		strncat(stc_cmd, stc_subcmd, MAX_CMD_LEN - 1 - strlen(stc_cmd));
	}
	if (strlen(conf->filter.dst_ip) > 0) {
		snprintf(stc_subcmd, MAX_CMD_LEN, "dst_ip %s ",
				conf->filter.dst_ip);
		strncat(stc_cmd, stc_subcmd, MAX_CMD_LEN - 1 - strlen(stc_cmd));
	}
	if (conf->filter.src_port > 0) {
		snprintf(stc_subcmd, MAX_CMD_LEN, "src_port %d ",
				conf->filter.src_port);
		strncat(stc_cmd, stc_subcmd, MAX_CMD_LEN - 1 - strlen(stc_cmd));
	}
	if (conf->filter.dst_port > 0) {
		snprintf(stc_subcmd, MAX_CMD_LEN, "dst_port %d ",
				conf->filter.dst_port);
		strncat(stc_cmd, stc_subcmd, MAX_CMD_LEN - 1 - strlen(stc_cmd));
	}
	if (strlen(conf->filter.src_mac) > 0) {
		snprintf(stc_subcmd, MAX_CMD_LEN, "src_mac %s ",
				conf->filter.src_mac);
		strncat(stc_cmd, stc_subcmd, MAX_CMD_LEN - 1 - strlen(stc_cmd));
	}
	if (strlen(conf->filter.dst_mac) > 0) {
		snprintf(stc_subcmd, MAX_CMD_LEN, "dst_mac %s ",
				conf->filter.dst_mac);
		strncat(stc_cmd, stc_subcmd, MAX_CMD_LEN - 1 - strlen(stc_cmd));
	}
	if (strlen(conf->filter.action_spec) > 0) {
		snprintf(stc_subcmd, MAX_CMD_LEN, "action %s ",
				conf->filter.action_spec);
		strncat(stc_cmd, stc_subcmd, MAX_CMD_LEN - 1 - strlen(stc_cmd));
	}
	sysret = system(stc_cmd);
	if (SYSCALL_OK(sysret))
		rc = SR_ERR_OK;
	else
		rc = SR_ERR_INVAL_ARG;
	printf("filter: %s\n", stc_cmd);

	return rc;
}

int brtc_subtree_change_cb(sr_session_ctx_t *session, const char *path,
		sr_notif_event_t event, void *private_ctx)
{
	int rc = SR_ERR_OK;
	char xpath[XPATH_MAX_LEN] = {0};

	snprintf(xpath, XPATH_MAX_LEN, "%s", path);

	switch (event) {
	case SR_EV_VERIFY:
		rc = parse_config(session, xpath);
		if (rc == SR_ERR_OK)
			rc = set_config(session, false);
		break;
	case SR_EV_ENABLED:
		rc = parse_config(session, xpath);
		if (rc == SR_ERR_OK)
			rc = set_config(session, false);
		break;
	case SR_EV_APPLY:
		break;
	case SR_EV_ABORT:
		rc = set_config(session, true);
		break;
	default:
		break;
	}

	return rc;
}
