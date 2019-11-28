/**
 * @file cb_streamid.h
 * @author Xiaolin He
 * @brief header file for cb_streamid.c.
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

#ifndef __CB_STREAMID_H_
#define __CB_STREAMID_H_

#include <tsn/genl_tsn.h>
#include "common.h"

#define CB_STREAMID_XPATH "/ieee802-dot1q-cb-stream-identification:streams"
#define CB_STREAMID_MODULE_NAME "ieee802-dot1q-cb-stream-identification"
#define CB_STREAMID_TABLE_XPATH (CB_STREAMID_XPATH "/stream-identity-table")

struct std_cb_stream {
	char port[IF_NAME_MAX_LEN];
	uint32_t index;
	bool enable;
	struct tsn_cb_streamid cbconf;
};

struct std_cb_stream_list {
	struct std_cb_stream *stream_ptr;
	enum apply_status apply_st;
	struct std_cb_stream_list *pre;
	struct std_cb_stream_list *next;
};

int cb_streamid_subtree_change_cb(sr_session_ctx_t *session, const char *path,
		sr_notif_event_t event, void *private_ctx);

#endif
