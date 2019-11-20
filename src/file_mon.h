/**
 * @file file_mon.h
 * @author Xiaolin He
 * @brief header file for file_mon.c.
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

#ifndef __FILE_MON_H_
#define __FILE_MON_H_

#define FMON_FLAG_MODIFIED	0x01
#define FMON_FLAG_IGNORED	0x02
#define FMON_FLAG_UPDATE	0x04

#define INOT_NAME_MAX		50
#define MAX_FILE_PATH_LEN	100

struct sr_tsn_callback {
	int callbacks_count;
	struct {
		const char *f_path;
		void (*func)(void);
	} callbacks[];
};

struct file_mon {
	int wd;
	char flags;
};

int sr_tsn_fcb_init(void);

#endif
