/**
 * @file qci.h
 * @author Xiaolin He
 * @brief header file for qci_xxx.c.
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
#endif
