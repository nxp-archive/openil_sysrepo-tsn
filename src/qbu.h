/**
 * @file qbu.h
 * @author Xiaolin He
 * @brief header file for qbu.c.
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

#ifndef __QBU_H_
#define __QBU_H_

#define QBU_XPATH "/ieee802-dot1q-preemption:frame-preemption-parameters"
#define QBU_MODULE_NAME "ieee802-dot1q-preemption"

int qbu_subtree_change_cb(sr_session_ctx_t *session, const char *path,
		sr_notif_event_t event, void *private_ctx);

#endif
