/**
 * @file mac_cfg.c
 * @author hongbo wang
 * @brief Application to configure mac address based on sysrepo datastore.
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

#include "mac_cfg.h"

struct item_cfg {
	bool valid;
	char ifname[IF_NAME_MAX_LEN];
	char mac_addr[MAC_ADDR_LEN];
};
static struct item_cfg sitem_conf;

static int get_inet_cfg(char *ifname, int req, void *buf, int len)
{
	int ret = 0;
	int sockfd = 0;
	struct ifreq ifr = {0};
	struct sockaddr_in *sin = NULL;

	if (!ifname || !buf)
		return -1;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		PRINT("create socket failed! ret:%d\n", sockfd);
		return -2;
	}

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);

	ret = ioctl(sockfd, req, &ifr);
	close(sockfd);
	if (ret < 0) {
		PRINT("ioctl error! ret:%d\n", ret);
		return -3;
	}

	if (req == SIOCGIFHWADDR) {
		memcpy(buf, &ifr.ifr_ifru.ifru_hwaddr.sa_data, len);
	} else {
		sin = (struct sockaddr_in *)&ifr.ifr_addr;
		memcpy((struct in_addr *)buf, &sin->sin_addr, len);
	}

	return 0;
}

int get_inet_mac(char *ifname, uint8_t *buf, int len)
{
	return get_inet_cfg(ifname, SIOCGIFHWADDR, buf, len);
}

static int set_inet_cfg(char *ifname, int req, void *buf, int len)
{
	int ret = 0;
	int sockfd = 0;
	struct ifreq ifr = {0};
	struct sockaddr_in *sin = NULL;

	if (!ifname || !buf)
		return -1;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		PRINT("create socket failed! ret:%d\n", sockfd);
		return -2;
	}

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);

	ret = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
	if (ret < 0) {
		PRINT("%s:can not find \"%s\"\n", __func__, ifname);
		return -3;
	}

	if (req == SIOCSIFHWADDR) {
		memcpy(&ifr.ifr_ifru.ifru_hwaddr.sa_data, buf, len);
		ifr.ifr_addr.sa_family = ARPHRD_ETHER;
	} else {
		sin = (struct sockaddr_in *)&ifr.ifr_addr;
		sin->sin_family = AF_INET;
		memcpy(&sin->sin_addr, (struct in_addr *)buf, len);
	}

	ret = ioctl(sockfd, req, &ifr);
	close(sockfd);
	if (ret < 0) {
		PRINT("%s ioctl error! ret:%d\n", __func__, ret);
		return -4;
	}

	return 0;
}

int set_inet_mac(char *ifname, uint8_t *buf, int len)
{
	return set_inet_cfg(ifname, SIOCSIFHWADDR, buf, len);
}

int convert_mac_address(char *str, uint8_t *pbuf, int buflen)
{
	int i = 0;
	int ret = 0;
	int len = 0;
	int cnt = 0;
	uint32_t data = 0;
	char *pmac = NULL;
	char buf[32] = {0};

	if (!str || !pbuf)
		return -1;

	snprintf(buf, sizeof(buf), "%s", str);
	pmac = buf;

	len = strlen(buf);
	for (i = 0; i < (len + 1); i++) {
		if ((buf[i] == '-') || (buf[i] == ':') || (buf[i] == '\0')) {
			buf[i] = '\0';
			ret = sscanf(pmac, "%02X", &data);
			if (ret != 1)
				return -2;

			if (cnt < buflen)
				pbuf[cnt++] = data & 0xFF;

			pmac = buf + i + 1;
		}
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

	if (!strcmp(nodename, "address")) {
		if (!conf->valid) {
			snprintf(conf->mac_addr, MAC_ADDR_LEN, "%s", strval);
			conf->valid = true;
		}
	} else if (!strcmp(nodename, "name")) {
		if (!conf->valid)
			snprintf(conf->ifname, IF_NAME_MAX_LEN, "%s", strval);
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
	char ifname_bak[IF_NAME_MAX_LEN] = {0};
	struct item_cfg *conf = &sitem_conf;

	memset(conf, 0, sizeof(struct item_cfg));

	snprintf(xpath, XPATH_MAX_LEN, "%s//*", BRIDGE_XPATH);

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
		snprintf(ifname_bak, IF_NAME_MAX_LEN, "%s", ifname);
		snprintf(conf->ifname, IF_NAME_MAX_LEN, "%s", ifname);

		rc = parse_item(session, xpath, conf);
		if (rc != SR_ERR_OK)
			break;
	}

cleanup:
	if (rc == SR_ERR_NOT_FOUND)
		rc = SR_ERR_OK;

	return rc;
}

static int set_config(sr_session_ctx_t *session, bool abort)
{
	int ret = 0;
	int rc = SR_ERR_OK;
	uint8_t mac[IFHWADDRLEN];
	struct item_cfg *conf = &sitem_conf;

	if (abort) {
		memset(conf, 0, sizeof(struct item_cfg));
		return rc;
	}

	if (!conf->valid)
		return rc;

	/* config mac address */
	convert_mac_address(conf->mac_addr, mac, sizeof(mac));
	ret = set_inet_mac(conf->ifname, mac, sizeof(mac));
	if (ret != 0)
		return SR_ERR_INVAL_ARG;

	PRINT("set_inet_mac ifname:%s mac:%s\n", conf->ifname, conf->mac_addr);

	return rc;
}

int mac_subtree_change_cb(sr_session_ctx_t *session, const char *path,
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
