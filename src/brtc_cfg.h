/**
 * @file brtc_cfg.h
 * @author hongbo wang
 * @brief header file for brtc_cfg.c.
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

#ifndef __BRTC_CFG_H__
#define __BRTC_CFG_H__

#include "common.h"

#define BR_VLAN_XPATH ("/bridge-vlan")
#define BR_TC_XPATH ("/nxp-bridge-vlan-tc-flower:traffic-control")
#define MAX_VLAN_LEN (16)
#define MAX_PARA_LEN (32)
#define MAX_ACTION_LEN (128)
#define MAX_CMD_LEN (512)

#define SUB_ITEM_NONE		(0)
#define SUB_ITEM_QDISC		(1)
#define SUB_ITEM_FILTER		(2)

#define _PARA(a, l, v) snprintf((a), (l), "%s", (v))

int brtc_subtree_change_cb(sr_session_ctx_t *session, const char *path,
		sr_notif_event_t event, void *private_ctx);

#endif
