/**
 * @file qci.h
 * @author Xiaolin He
 * @brief header file for qci_xxx.c.
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

#ifndef __QCI_H_
#define __QCI_H_

#include <tsn/genl_tsn.h>
#include "common.h"

#define QCISFSG_NM "ieee802-dot1q-stream-filters-gates"
#define QCIPSFP_NM "ieee802-dot1q-psfp"
#define QCISF_XPATH "/ieee802-dot1q-stream-filters-gates:stream-filters"
#define QCISG_XPATH "/ieee802-dot1q-stream-filters-gates:stream-gates"
#define QCIFM_XPATH "/ieee802-dot1q-psfp:flow-meters"
#define SFI_XPATH (QCISF_XPATH "/stream-filter-instance-table")
#define SGI_XPATH (QCISG_XPATH "/stream-gate-instance-table")
#define FMI_XPATH (QCIFM_XPATH "/flow-meter-instance-table")

enum qci_type {
	QCI_T_SF = 1,
	QCI_T_SG = 2,
	QCI_T_FM = 3,
};

struct std_sf {
	char port[IF_NAME_MAX_LEN];
	uint32_t sf_id;
	bool enable;
	struct tsn_qci_psfp_sfi_conf sfconf;
};

struct std_sg {
	char port[IF_NAME_MAX_LEN];
	uint32_t sg_handle;
	uint32_t sg_id;
	bool enable;
	struct cycle_time_s cycletime;
	bool cycletime_f;
	struct base_time_s basetime;
	bool basetime_f;
	struct tsn_qci_psfp_sgi_conf sgconf;
};

struct std_fm {
	char port[IF_NAME_MAX_LEN];
	uint32_t fm_id;
	bool enable;
	struct tsn_qci_psfp_fmi fmconf;
};

struct std_qci_list {
	enum apply_status apply_st;
	struct std_qci_list *pre;
	struct std_qci_list *next;

	/* table pointer */
	union {
		struct std_fm *fm_ptr;
		struct std_sg *sg_ptr;
		struct std_sf *sf_ptr;
	};
};

struct tc_qci_stream_para {
	bool set_flag;
	bool enable;
	uint64_t dmac;
	uint64_t smac;
	uint16_t vid;
	uint16_t sport;
	uint16_t dport;
	struct in_addr i4_addr;
	char ifname[IF_NAME_MAX_LEN];
};

struct tc_qci_policer_entry {
	uint32_t id;
	uint32_t eir;  /* unit: bits per second */
	uint32_t ebs;  /* unit: bytes */
	uint32_t cir;
	uint32_t cbs;
};

struct tc_qci_policer_para {
	bool set_flag;
	int entry_cnt;
	struct tc_qci_policer_entry entry[SUB_PARA_LEN];
};

struct tc_qci_gate_acl {
	bool state;
	int8_t ipv;
	uint32_t interval;
};

struct tc_qci_gate_entry {
	uint32_t id;
	bool gate_state;
	uint64_t base_time;
	uint64_t cycle_time;
	uint32_t acl_len;
	struct tc_qci_gate_acl acl[SUB_PARA_LEN];
};

struct tc_qci_gates_para {
	bool set_flag;
	int entry_cnt;
	struct tc_qci_gate_entry entry[SUB_PARA_LEN];
};

#define KBPS (1000)
#define MBPS (1000 * 1000)

struct std_qci_list *new_list_node(enum qci_type type, char *port,
		uint32_t id);
void del_list_node(struct std_qci_list *node, enum qci_type type);
void free_list(struct std_qci_list *l_head, enum qci_type type);
struct std_qci_list *is_node_in_list(struct std_qci_list *list,
		char *port, uint32_t id, enum qci_type type);
void add_node2list(struct std_qci_list *list, struct std_qci_list *node);

int qci_sf_subtree_change_cb(sr_session_ctx_t *session, const char *path,
		sr_notif_event_t event, void *private_ctx);
int qci_sg_subtree_change_cb(sr_session_ctx_t *session, const char *path,
		sr_notif_event_t event, void *private_ctx);
int qci_fm_subtree_change_cb(sr_session_ctx_t *session, const char *path,
		sr_notif_event_t event, void *private_ctx);

int qci_init_para(void);

int cb_streamid_get_para(char *buf, int len);
int cb_streamid_clear_para(void);

int qci_fm_get_para(char *buf, int len);
int qci_fm_clear_para(void);

int qci_sg_get_para(char *buf, int len);
int qci_sg_clear_para(void);

char *get_interface_name(void);

int qci_set_session(sr_session_ctx_t *session);
int qci_set_xpath(char *xpath);
int qci_check_parameter(void);


#endif
