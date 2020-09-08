/**
 * @file cb_streamid.c
 * @author Xiaolin He
 * @brief Implementation of Stream Identify function based on sysrepo
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
#include "cb_streamid.h"
#include "qci.h"

struct std_cb_stream_list *stream_head;

static bool stc_cfg_flag;
static bool stc_qdisc_flag;
static struct tc_qci_stream_para sqci_stream_para;

char *get_interface_name(void)
{
	return sqci_stream_para.ifname;
}

struct std_cb_stream_list *new_stream_list_node(char *port, uint32_t index)
{
	struct std_cb_stream_list *stream_list;
	struct std_cb_stream *stream_ptr;

	stream_list = calloc(1, sizeof(struct std_cb_stream_list));
	if (!stream_list)
		return NULL;

	stream_ptr = calloc(1, sizeof(struct std_cb_stream));
	if (!stream_ptr) {
		free(stream_list);
		return NULL;
	}

	stream_list->stream_ptr = stream_ptr;
	stream_list->apply_st = APPLY_NONE;
	snprintf(stream_list->stream_ptr->port, IF_NAME_MAX_LEN, "%s", port);
	stream_list->stream_ptr->index = index;
	stream_list->next = NULL;
	stream_list->pre = NULL;
	stream_ptr->cbconf.handle = -1;
	return stream_list;
}

void del_stream_list_node(struct std_cb_stream_list *node)
{
	if (!node)
		return;

	if (node->pre)
		node->pre->next = node->next;
	if (node->stream_ptr)
		free(node->stream_ptr);
	free(node);
}

void free_stream_list(struct std_cb_stream_list *l_head)
{
	if (!l_head)
		return;

	if (l_head->next)
		free_stream_list(l_head->next);

	del_stream_list_node(l_head);
}

struct std_cb_stream_list *find_stream_in_list(struct std_cb_stream_list *list,
		char *port, uint32_t index)
{
	struct std_cb_stream_list *node = list;

	while (node) {
		if (!strncmp(port, node->stream_ptr->port, IF_NAME_MAX_LEN)
		    && (node->stream_ptr->index == index))
			goto out;
		else
			node = node->next;
	}
out:
	return node;
}

void add_stream2list(struct std_cb_stream_list *list,
		struct std_cb_stream_list *node)
{
	struct std_cb_stream_list *last = list;

	if (!list) {
		list = node;
		return;
	}

	while (last->next)
		last = last->next;

	last->next = node;
}

int parse_vlan_tag(sr_session_ctx_t *session, sr_val_t *value, uint8_t *vlan)
{
	int rc = SR_ERR_OK;
	char err_msg[MSG_MAX_LEN] = {0};
	char *vlan_str = value->data.enum_val;

	if (!strcmp(vlan_str, "tagged")) {
		*vlan = 1;
	} else if (!strcmp(vlan_str, "priority")) {
		*vlan = 2;
	} else if (!strcmp(vlan_str, "all")) {
		*vlan = 3;
	} else {
		snprintf(err_msg, MSG_MAX_LEN, "Invalid '%s'", vlan_str);
		sr_set_error(session, err_msg, value->xpath);

		printf("ERROR: Invalid '%s' in %s!\n", vlan_str,
		       value->xpath);
		rc = SR_ERR_INVAL_ARG;
	}
	return rc;
}

int parse_mac_address(char *mac_str, uint64_t *mac,
	char *err_msg, char *path)
{
	int rc = SR_ERR_OK;
	char *temp;
	uint64_t ul = 0;
	int i = 0;
	uint64_t byte[6] = {0};

	if (strlen(mac_str) != 17) {
		rc = SR_ERR_INVAL_ARG;
		sprintf(err_msg, "length of '%s' in path '%s'should be 17!",
			mac_str, path);
		goto out;
	}
	temp = strtok(mac_str, "-");

	ul = strtoul(temp, NULL, 16);
	i = 0;
	byte[i++] = ul;
	while (1) {
		temp = strtok(NULL, "-");
		if (temp != NULL) {
			if (strlen(temp) != 2) {
				rc = SR_ERR_INVAL_ARG;
				sprintf(err_msg,
					"'%s' in '%s' is in wrong format!",
					mac_str, path);
				goto out;
			}
			ul = strtoul(temp, NULL, 16);
			byte[i++] = (uint8_t)ul;
		} else {
			break;
		}
	}
	if (i != 6) {
		rc = SR_ERR_INVAL_ARG;
		sprintf(err_msg, "'%s' in '%s' is in wrong format!",
			mac_str, path);
		goto out;
	}
	for (i = 0, ul = 0; i < 6; i++)
		ul = (ul << 8) + byte[i];

	*mac = ul;
out:
	return rc;
}

/************************************************************************
 *
 * Init value of items in abort callback.
 *
 ************************************************************************/
void clr_cb_streamid(sr_session_ctx_t *session, sr_val_t *value,
		struct std_cb_stream *stream)
{
	sr_xpath_ctx_t xp_ctx = {0};
	char *nodename;

	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		return;

	if (!strcmp(nodename, "stream-id-enabled")) {
		stream->enable = false;
	} else if (!strcmp(nodename, "stream-handle")) {
		stream->cbconf.handle = 0;
	} else if (!strcmp(nodename, "in-facing-output-port-list")) {
		stream->cbconf.ifac_oport = 0;
	} else if (!strcmp(nodename, "out-facing-output-port-list")) {
		stream->cbconf.ofac_oport = 0;
	} else if (!strcmp(nodename, "in-facing-input-port-list")) {
		stream->cbconf.ifac_iport = 0;
	} else if (!strcmp(nodename, "out-facing-input-port-list")) {
		stream->cbconf.ofac_iport = 0;
	} else if (!strcmp(nodename, "identification-type")) {
		stream->cbconf.type = 0;
	} else if (!strcmp(nodename, "lan-path-id")) {
	} else if (!strcmp(nodename, "dest-address")) {
		if (stream->cbconf.type == STREAMID_IP)
			stream->cbconf.para.iid.dmac = 0;
		else if (stream->cbconf.type == STREAMID_NULL)
			stream->cbconf.para.nid.dmac = 0;
	} else if (!strcmp(nodename, "source-address")) {
		stream->cbconf.para.sid.smac = 0;
	} else if (!strcmp(nodename, "vlan-tagged")) {
		if (stream->cbconf.type == STREAMID_SMAC_VLAN)
			stream->cbconf.para.sid.tagged = 0;
		else if (stream->cbconf.type == STREAMID_NULL)
			stream->cbconf.para.nid.tagged = 0;
	} else if (!strcmp(nodename, "vlan-id")) {
		if (stream->cbconf.type == STREAMID_NULL)
			stream->cbconf.para.nid.vid = 0;
		else if (stream->cbconf.type == STREAMID_SMAC_VLAN)
			stream->cbconf.para.sid.vid = 0;
		else if (stream->cbconf.type == STREAMID_IP)
			stream->cbconf.para.iid.vid = 0;
	} else if (!strcmp(nodename, "down-dest-address")) {
		stream->cbconf.para.did.down_dmac = 0;
	} else if (!strcmp(nodename, "down-vlan-tagged")) {
		if (stream->cbconf.type == STREAMID_DMAC_VLAN)
			stream->cbconf.para.did.down_tagged = 0;
		else if (stream->cbconf.type == STREAMID_IP)
			stream->cbconf.para.iid.tagged = 0;
	} else if (!strcmp(nodename, "down-vlan-id")) {
		stream->cbconf.para.did.down_vid = 0;
	} else if (!strcmp(nodename, "down-priority")) {
		stream->cbconf.para.did.down_prio = 0;
	} else if (!strcmp(nodename, "up-dest-address")) {
		stream->cbconf.para.did.up_dmac = 0;
	} else if (!strcmp(nodename, "up-vlan-tagged")) {
		stream->cbconf.para.did.up_tagged = 0;
	} else if (!strcmp(nodename, "up-vlan-id")) {
		stream->cbconf.para.did.up_vid = 0;
	} else if (!strcmp(nodename, "up-priority")) {
		stream->cbconf.para.did.down_prio = 0;
	} else if (!strcmp(nodename, "ipv4-address")) {
	} else if (!strcmp(nodename, "ipv6-address")) {
	} else if (!strcmp(nodename, "dscp")) {
		stream->cbconf.para.iid.dscp = 0;
	} else if (!strcmp(nodename, "next-protocol")) {
		stream->cbconf.para.iid.npt = 0;
	} else if (!strcmp(nodename, "source-port")) {
		stream->cbconf.para.iid.dscp = 0;
	} else if (!strcmp(nodename, "dest-port")) {
		stream->cbconf.para.iid.dscp = 0;
	}
}

/************************************************************************
 *
 * Get items' values from datastore.
 *
 ************************************************************************/
int parse_cb_streamid(sr_session_ctx_t *session, sr_val_t *value,
		struct std_cb_stream *stream)
{
	struct tc_qci_stream_para *para = &sqci_stream_para;
	int rc = SR_ERR_OK;
	sr_xpath_ctx_t xp_ctx = {0};
	uint8_t u8_val = 0;
	uint16_t u16_val = 0;
	uint64_t u64_val = 0;
	char *nodename;
	char *num_str;
	char err_msg[MSG_MAX_LEN] = {0};

	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		goto out;

	if (!strcmp(nodename, "stream-id-enabled")) {
		stream->enable = value->data.bool_val;
		para->enable = value->data.bool_val;
	} else if (!strcmp(nodename, "stream-handle")) {
		stream->cbconf.handle = value->data.uint32_val;
	} else if (!strcmp(nodename, "in-facing-output-port-list")) {
		stream->cbconf.ifac_oport = value->data.uint32_val;
	} else if (!strcmp(nodename, "out-facing-output-port-list")) {
		stream->cbconf.ofac_oport = value->data.uint32_val;
	} else if (!strcmp(nodename, "in-facing-input-port-list")) {
		stream->cbconf.ifac_iport = value->data.uint32_val;
	} else if (!strcmp(nodename, "out-facing-input-port-list")) {
		stream->cbconf.ofac_iport = value->data.uint32_val;
	} else if (!strcmp(nodename, "identification-type")) {
		num_str = value->data.enum_val;
		if (!strcmp(num_str, "null")) {
			stream->cbconf.type = STREAMID_NULL;
		} else if (!strcmp(num_str, "source-mac-and-vlan")) {
			stream->cbconf.type = STREAMID_SMAC_VLAN;
		} else if (!strcmp(num_str, "dest-mac-and-vlan")) {
			stream->cbconf.type = STREAMID_DMAC_VLAN;
		} else if (!strcmp(num_str, "ip-octuple")) {
			stream->cbconf.type = STREAMID_IP;
		} else {
			snprintf(err_msg, MSG_MAX_LEN, "Invalid '%s'", num_str);
			sr_set_error(session, err_msg, value->xpath);

			printf("ERROR: Invalid '%s' in %s!\n", num_str,
			       value->xpath);
			rc = SR_ERR_INVAL_ARG;
			goto out;
		}
	} else if (!strcmp(nodename, "lan-path-id")) {
	} else if (!strcmp(nodename, "dest-address")) {
		rc = parse_mac_address(value->data.string_val, &u64_val,
				       err_msg, value->xpath);
		if (rc != SR_ERR_OK) {
			sr_set_error(session, err_msg, value->xpath);
			printf("%s\n", err_msg);
			goto out;
		}

		if (stream->cbconf.type == STREAMID_IP)
			stream->cbconf.para.iid.dmac = u64_val;
		else if (stream->cbconf.type == STREAMID_NULL)
			stream->cbconf.para.nid.dmac = u64_val;
		para->dmac = u64_val;
	} else if (!strcmp(nodename, "source-address")) {
		rc = parse_mac_address(value->data.string_val, &u64_val,
				       err_msg, value->xpath);
		if (rc != SR_ERR_OK) {
			sr_set_error(session, err_msg, value->xpath);
			printf("%s\n", err_msg);
			goto out;
		}
		stream->cbconf.para.sid.smac = u64_val;
		para->smac = u64_val;
	} else if (!strcmp(nodename, "vlan-tagged")) {
		rc = parse_vlan_tag(session, value, &u8_val);
		if (rc != SR_ERR_OK)
			goto out;

		if (stream->cbconf.type == STREAMID_SMAC_VLAN)
			stream->cbconf.para.sid.tagged = u8_val;
		else if (stream->cbconf.type == STREAMID_NULL)
			stream->cbconf.para.nid.tagged = u8_val;
	} else if (!strcmp(nodename, "vlan-id")) {
		u16_val = value->data.uint16_val;
		if (stream->cbconf.type == STREAMID_NULL)
			stream->cbconf.para.nid.vid = u16_val;
		else if (stream->cbconf.type == STREAMID_SMAC_VLAN)
			stream->cbconf.para.sid.vid = u16_val;
		else if (stream->cbconf.type == STREAMID_IP)
			stream->cbconf.para.iid.vid = u16_val;
		para->vid = u16_val;
	} else if (!strcmp(nodename, "down-dest-address")) {
		rc = parse_mac_address(value->data.string_val, &u64_val,
				       err_msg, value->xpath);
		if (rc != SR_ERR_OK) {
			sr_set_error(session, err_msg, value->xpath);
			printf("%s\n", err_msg);
			goto out;
		}
		stream->cbconf.para.did.down_dmac = u64_val;
	} else if (!strcmp(nodename, "down-vlan-tagged")) {
		rc = parse_vlan_tag(session, value, &u8_val);
		if (rc != SR_ERR_OK)
			goto out;

		if (stream->cbconf.type == STREAMID_DMAC_VLAN)
			stream->cbconf.para.did.down_tagged = u8_val;
		else if (stream->cbconf.type == STREAMID_IP)
			stream->cbconf.para.iid.tagged = u8_val;
	} else if (!strcmp(nodename, "down-vlan-id")) {
		stream->cbconf.para.did.down_vid = value->data.uint16_val;
	} else if (!strcmp(nodename, "down-priority")) {
		stream->cbconf.para.did.down_prio = value->data.uint8_val;
	} else if (!strcmp(nodename, "up-dest-address")) {
		rc = parse_mac_address(value->data.string_val, &u64_val,
				       err_msg, value->xpath);
		if (rc != SR_ERR_OK) {
			sr_set_error(session, err_msg, value->xpath);
			printf("%s\n", err_msg);
			goto out;
		}
		stream->cbconf.para.did.up_dmac = u64_val;
	} else if (!strcmp(nodename, "up-vlan-tagged")) {
		rc = parse_vlan_tag(session, value, &u8_val);
		if (rc != SR_ERR_OK)
			goto out;

		stream->cbconf.para.did.up_tagged = u8_val;
	} else if (!strcmp(nodename, "up-vlan-id")) {
		stream->cbconf.para.did.up_vid = value->data.uint16_val;
	} else if (!strcmp(nodename, "up-priority")) {
		stream->cbconf.para.did.down_prio = value->data.uint8_val;
	} else if (!strcmp(nodename, "ipv4-address")) {
		struct in_addr i4_addr;

		rc = inet_pton(AF_INET, value->data.string_val, &i4_addr);
		if (rc != 1) {
			rc = SR_ERR_INVAL_ARG;
			goto out;
		}
		para->i4_addr.s_addr = i4_addr.s_addr;
	} else if (!strcmp(nodename, "ipv6-address")) {
		struct in6_addr i6_addr;

		rc = inet_pton(AF_INET6, value->data.string_val, &i6_addr);
		if (rc != 1) {
			rc = SR_ERR_INVAL_ARG;
			goto out;
		}
	} else if (!strcmp(nodename, "dscp")) {
		stream->cbconf.para.iid.dscp = value->data.uint8_val;
	} else if (!strcmp(nodename, "next-protocol")) {
		num_str = value->data.enum_val;
		if (!strcmp(num_str, "UDP"))
			stream->cbconf.para.iid.npt = 0;
		else if (!strcmp(num_str, "TCP"))
			stream->cbconf.para.iid.npt = 1;
		else if (!strcmp(num_str, "SCTP"))
			stream->cbconf.para.iid.npt = 2;
		else if (!strcmp(num_str, "none"))
			stream->cbconf.para.iid.npt = 3;
	} else if (!strcmp(nodename, "source-port")) {
		stream->cbconf.para.iid.dscp = value->data.uint16_val;
		para->sport = value->data.uint16_val;
	} else if (!strcmp(nodename, "dest-port")) {
		stream->cbconf.para.iid.dscp = value->data.uint16_val;
		para->dport = value->data.uint16_val;
	}

	para->set_flag = true;

out:
	return rc;
}

/************************************************************************
 *
 * Process changes in one port and apply them to device.
 *
 ************************************************************************/
int get_streamid_per_port_per_id(sr_session_ctx_t *session, const char *path)
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
	char *index;
	uint32_t stream_id = 0;
	struct std_cb_stream_list *cur_node = NULL;
	char index_bak[IF_NAME_MAX_LEN] = "unknown";

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

		index = sr_xpath_key_value(value->xpath,
					    "stream-identity-table", "index",
					    &xp_ctx_id);

		if ((!index) || !strncmp(index, index_bak, IF_NAME_MAX_LEN))
			continue;

		snprintf(index_bak, IF_NAME_MAX_LEN, "%s", index);

		stream_id = strtoul(index, NULL, 0);
		cpname = sr_xpath_key_value(value->xpath, "component",
					    "name", &xp_ctx_cp);
		if (!cpname)
			continue;

		snprintf(sqci_stream_para.ifname, IF_NAME_MAX_LEN, "%s", cpname);

		if (!stream_head) {
			stream_head = new_stream_list_node(cpname,
							   stream_id);
			if (!stream_head) {
				snprintf(err_msg, MSG_MAX_LEN, "%s in %s\n",
					 "Create new node failed",
					 value->xpath);
				sr_set_error(session, err_msg, path);
				rc = SR_ERR_NOMEM;
				goto out;
			}
			continue;
		}
		cur_node = find_stream_in_list(stream_head, cpname, stream_id);
		if (!cur_node) {
			cur_node = new_stream_list_node(cpname, stream_id);
			if (!cur_node) {
				snprintf(err_msg, MSG_MAX_LEN, "%s in %s\n",
					 "Create new node failed",
					 value->xpath);
				sr_set_error(session, err_msg, path);
				rc = SR_ERR_NOMEM;
				goto out;
			}

			add_stream2list(stream_head, cur_node);
		}
	}
	if (rc == SR_ERR_NOT_FOUND)
		rc = SR_ERR_OK;

out:
	return rc;
}

int abort_streamid_config(sr_session_ctx_t *session, char *path,
		struct std_cb_stream_list *node)
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

			clr_cb_streamid(session, old_value, node->stream_ptr);
			continue;
		}
		parse_cb_streamid(session, new_value, node->stream_ptr);
	}

	if (rc == SR_ERR_NOT_FOUND)
		rc = SR_ERR_OK;

out:
	return rc;
}

int parse_streamid_per_port_per_id(sr_session_ctx_t *session, bool abort)
{
	int rc = SR_ERR_OK;
	sr_val_t *values;
	size_t count;
	size_t i;
	char err_msg[MSG_MAX_LEN] = {0};
	struct std_cb_stream_list *cur_node = stream_head;
	struct tc_qci_stream_para *para = &sqci_stream_para;
	char xpath[XPATH_MAX_LEN] = {0,};

	while (cur_node) {
		snprintf(xpath, XPATH_MAX_LEN,
			 "%s[name='%s']%s[index='%u']//*",
			 BRIDGE_COMPONENT_XPATH, cur_node->stream_ptr->port,
			 CB_STREAMID_TABLE_XPATH,
			 cur_node->stream_ptr->index);
		if (abort) {
			rc = abort_streamid_config(session, xpath, cur_node);
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
				cur_node->stream_ptr->enable = false;
				para->enable = false;
				para->set_flag = true;
				rc = SR_ERR_OK;
			} else {
				printf("ERROR: %s sr_get_items: %s\n", __func__,
				       sr_strerror(rc));
				del_stream_list_node(cur_node);
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

				rc = parse_cb_streamid(session, &values[i],
						       cur_node->stream_ptr);
				if (rc != SR_ERR_OK) {
					cur_node->apply_st = APPLY_PARSE_ERR;
					sr_free_values(values, count);
					del_stream_list_node(cur_node);
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

int config_streamid(sr_session_ctx_t *session)
{
	int rc = SR_ERR_OK;
	char err_msg[MSG_MAX_LEN] = {0};
	struct std_cb_stream_list *cur_node = stream_head;
	char xpath[XPATH_MAX_LEN] = {0,};

	init_tsn_socket();
	while (cur_node) {
		/* set new flow meter configuration */
		rc = tsn_cb_streamid_set(cur_node->stream_ptr->port,
					 cur_node->stream_ptr->index,
					 cur_node->stream_ptr->enable,
					 &(cur_node->stream_ptr->cbconf));
		if (rc < 0) {
			sprintf(err_msg,
				"failed to set stream-id, %s!",
				strerror(-rc));
			snprintf(xpath, XPATH_MAX_LEN,
				 "%s[name='%s']%s[index='%u']//*",
				 BRIDGE_COMPONENT_XPATH,
				 cur_node->stream_ptr->port,
				 CB_STREAMID_TABLE_XPATH,
				 cur_node->stream_ptr->index);
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

int cb_streamid_config(sr_session_ctx_t *session, const char *path, bool abort)
{
	int rc = SR_ERR_OK;

	if (!abort) {
		rc = get_streamid_per_port_per_id(session, path);
		if (rc != SR_ERR_OK)
			goto out;
	}
	if (!stream_head)
		goto out;

	rc = parse_streamid_per_port_per_id(session, abort);
	if (rc != SR_ERR_OK)
		goto out;

	if (stc_cfg_flag)
		rc = qci_check_parameter();
	else
		rc = config_streamid(session);

out:
	return rc;
}

static inline void mac_u64_to_str(uint64_t mac, char *buf, int len)
{
	uint8_t macs[6];
	int offset = 40;
	int i = 0;

	for (i = 0; i < 6; i++) {
		macs[i] = (mac >> offset) & 0xFF;
		offset -= 8;
	}
	snprintf(buf, len, "%02X:%02X:%02X:%02X:%02X:%02X ",
		macs[0], macs[1], macs[2], macs[3], macs[4], macs[5]);
}

int cb_streamid_del_tc_config(char *buf, int len)
{
	struct tc_qci_stream_para *para = &sqci_stream_para;
	char sub_buf[SUB_CMD_LEN];

	snprintf(buf, len, "tc filter del dev %s ingress;", para->ifname);

	snprintf(sub_buf, SUB_CMD_LEN, "tc qdisc del dev %s ingress;", para->ifname);
	strncat(buf, sub_buf, len - 1 - strlen(buf));

	printf("cmd:%s\n", buf);
	system(buf);

	para->set_flag = false;
	stc_qdisc_flag = false;

	return 0;
}

int cb_streamid_get_para(char *buf, int len)
{
	struct tc_qci_stream_para *para = &sqci_stream_para;
	char sub_buf[SUB_CMD_LEN];
	uint16_t vid = 0;
	int pri = 0;

	if (!para->set_flag || !buf || !len)
		return 0;

	if (!para->enable)
		return cb_streamid_del_tc_config(buf, len);

	if (!stc_qdisc_flag) {
		snprintf(sub_buf, SUB_CMD_LEN, "tc qdisc add dev %s ingress", para->ifname);
		system(sub_buf);
		stc_qdisc_flag = true;
	}

	snprintf(sub_buf, SUB_CMD_LEN, "tc filter del dev %s ingress;", para->ifname);
	strncat(buf, sub_buf, len - 1 - strlen(buf));

	snprintf(sub_buf, SUB_CMD_LEN, "tc filter add dev %s ", para->ifname);
	strncat(buf, sub_buf, len - 1 - strlen(buf));

	snprintf(sub_buf, SUB_CMD_LEN, "protocol 802.1Q parent ffff: flower skip_sw ");
	strncat(buf, sub_buf, len - 1 - strlen(buf));

	if (para->dmac) {
		strncat(buf, "dst_mac ", len - 1 - strlen(buf));
		mac_u64_to_str(para->dmac, sub_buf, SUB_CMD_LEN);
		strncat(buf, sub_buf, len - 1 - strlen(buf));
	}

	if (para->smac) {
		strncat(buf, "src_mac ", len - 1 - strlen(buf));
		mac_u64_to_str(para->dmac, sub_buf, SUB_CMD_LEN);
		strncat(buf, sub_buf, len - 1 - strlen(buf));
	}

	if (para->dport) {
		snprintf(sub_buf, SUB_CMD_LEN, "dst_port %d ", para->dport);
		strncat(buf, sub_buf, len - 1 - strlen(buf));
	}

	if (para->sport) {
		snprintf(sub_buf, SUB_CMD_LEN, "src_port %d ", para->sport);
		strncat(buf, sub_buf, len - 1 - strlen(buf));
	}

	if (para->vid) {
		if (para->vid < MAX_VLAN_ID) {
			pri = 0;
			vid = para->vid;
		} else {
			pri = (para->vid >> 13) & 0x07;
			vid = para->vid & (MAX_VLAN_ID - 1);
		}

		if (vid > 0) {
			snprintf(sub_buf, SUB_CMD_LEN, "vlan_id %d ", vid);
			strncat(buf, sub_buf, len - 1 - strlen(buf));
		}

		if (pri > 0) {
			snprintf(sub_buf, SUB_CMD_LEN, "vlan_prio %d ", pri);
			strncat(buf, sub_buf, len - 1 - strlen(buf));
		}
	}

	if (!para->dmac && !para->smac && !para->dport && !para->sport && !para->vid) {
		snprintf(sub_buf, SUB_CMD_LEN, "matchall ");
		strncat(buf, sub_buf, len - 1 - strlen(buf));
	}

	return (int)strlen(buf);
}

int cb_streamid_clear_para(void)
{
	memset(&sqci_stream_para, 0, sizeof(sqci_stream_para));
	return 0;
}

/************************************************************************
 *
 * Callback for CB-Stream-Identification configuration.
 *
 ************************************************************************/
int cb_streamid_subtree_change_cb(sr_session_ctx_t *session, const char *path,
		sr_notif_event_t event, void *private_ctx)
{
	int rc = SR_ERR_OK;
	char xpath[XPATH_MAX_LEN] = {0,};

	snprintf(xpath, XPATH_MAX_LEN, "%s/%s:*//*", BRIDGE_COMPONENT_XPATH,
		 CB_STREAMID_MODULE_NAME);

#ifdef SYSREPO_TSN_TC
	stc_cfg_flag = true;
	qci_set_xpath(xpath);
	qci_set_session(session);
#else
	stc_cfg_flag = false;
#endif

	switch (event) {
	case SR_EV_VERIFY:
		rc = cb_streamid_config(session, xpath, false);
		break;
	case SR_EV_ENABLED:
		rc = cb_streamid_config(session, xpath, false);
		break;
	case SR_EV_APPLY:
		free_stream_list(stream_head);
		stream_head = NULL;
		break;
	case SR_EV_ABORT:
		rc = cb_streamid_config(session, xpath, true);
		free_stream_list(stream_head);
		stream_head = NULL;
		break;
	default:
		break;
	}

	return rc;
}
