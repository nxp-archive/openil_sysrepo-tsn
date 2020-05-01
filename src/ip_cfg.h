/**
 * @file ip_cfg.h
 * @author hongbo wang
 * @brief header file for ip_cfg.c.
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

#ifndef __IP_CFG_H__
#define __IP_CFG_H__

#include "common.h"

#ifndef IF_XPATH
#define IF_XPATH ("/ietf-interfaces:interfaces/interface")
#endif

#define IPV4_XPATH	("/ietf-ip:ipv4")
#define IP_MODULE_NAME	("ietf-ip")
#define MAX_IP_NUM	(64)

int ip_subtree_change_cb(sr_session_ctx_t *session, const char *path,
	sr_notif_event_t event, void *private_ctx);

#endif
