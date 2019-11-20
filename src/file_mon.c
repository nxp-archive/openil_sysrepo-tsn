/**
 * @file file_mon.c
 * @author Xiaolin He
 * @brief Monitor the change of specific files.
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <sys/inotify.h>

#include "file_mon.h"
#include "main.h"

/*
 * backup src to target
 */
static int cp_file(const char *src, const char *target)
{
	int target_fd;
	int src_fd;
	mode_t mode;
	uid_t uid;
	gid_t gid;
	struct stat file_inf;
	char buf[4096];
	ssize_t ret;

	if (!src) {
		printf("ERROR: null src in %s\n", __func__);
		return 1;
	}
	if (!target) {
		printf("ERROR: null target in %s\n", __func__);
		return 1;
	}

	src_fd = open(src, O_RDONLY | O_CLOEXEC);
	if (src_fd  == -1) {
		printf("ERROR: Open file '%s' to backup (%s) failed\n",
			    src, strerror(errno));
		return 1;
	}

	/* Get src access rights */
	if (fstat(src_fd, &file_inf) == -1) {
		printf("ERROR: Failed to get info about '%s' to backup (%s).\n",
			     src, strerror(errno));
		uid = geteuid();
		gid = getegid();
		mode = 0600;
	} else {
		uid = file_inf.st_uid;
		gid = file_inf.st_gid;
		mode = file_inf.st_mode;
	}

	target_fd = open(target, O_WRONLY | O_CLOEXEC | O_CREAT | O_TRUNC,
			 mode);
	if (target_fd == -1) {
		printf("ERROR: Unable to create backup file '%s' (%s)\n",
		       target, strerror(errno));
		close(src_fd);
		return 1;
	}
	if (fchown(target_fd, uid, gid) != 0) {
		printf("ERROR: Failed to change owner of '%s' (%s).\n",
		       target, strerror(errno));
	}

	/* if target wasn't created, but rewriting some existing file */
	fchmod(target_fd, mode);

	for (;;) {
		ret = read(src_fd, buf, sizeof(buf));
		if (ret == 0) {
			/* EOF */
			break;
		} else if (ret < 0) {
			printf("ERROR: Creating file '%s' failed (%s).\n",
			       target, strerror(errno));
			break;
		}
		if (write(target_fd, buf, ret) < ret) {
			printf("ERROR: Writing into file '%s' failed (%s).\n",
			       target, strerror(errno));
			break;
		}
	}
	close(src_fd);
	close(target_fd);

	return 0;
}

static int backup_file(const char *src)
{
	char target[MAX_FILE_PATH_LEN];
	int ret;

	if (!src) {
		printf("ERROR: null src in %s\n", __func__);
		return 1;
	}

	snprintf(target, MAX_FILE_PATH_LEN, "%s.bak", src);
	ret = cp_file(src, target);

	return ret;
}

#define INOT_BUFLEN (10 * (sizeof(struct inotify_event) + INOT_NAME_MAX + 1))
static void *file_monitor(void *arg)
{
	int inotify;
	int fd;
	int i;
	int ret;
	struct file_mon *wds;
	char buf[INOT_BUFLEN];
	char *p;
	char path[MAX_FILE_PATH_LEN];
	struct inotify_event *e;

	inotify = inotify_init1(IN_CLOEXEC);
	if (inotify == -1) {
		printf("ERROR: FMON thread failed on initiating inotify: %s.\n",
			    strerror(errno));
		return NULL;
	}

	wds = malloc(sizeof(struct file_mon) * file_clbks.callbacks_count);
	pthread_cleanup_push(free, wds);

	for (i = 0; i < file_clbks.callbacks_count; i++) {
		snprintf(path, MAX_FILE_PATH_LEN,
			 file_clbks.callbacks[i].f_path);

		/* if the file not exits, create it */
		fd = open(path, O_WRONLY | O_CLOEXEC | O_CREAT, 0600);
		if (fd == -1)
			printf("open %s failed\n", path);
		else
			close(fd);

		wds[i].wd = inotify_add_watch(inotify, path,
					      IN_MODIFY | IN_IGNORED |
					      IN_CLOSE_WRITE);
		if (wds[i].wd == -1) {
			printf("ERROR: Unable to monitor '%s' (%s)\n", path,
			       strerror(errno));
		} else {
			/* create backup file with current content */
			backup_file(path);
		}
	}

	/* Monitor loop */
	for (;;) {
		ret = read(inotify, buf, INOT_BUFLEN);
		if (ret == 0) {
			printf("ERROR: Inotify failed (EOF).\n");
			break;
		} else if (ret == -1) {
			if (errno == EINTR)
				continue;

			printf("ERROR: Inotify failed (%s).\n",
			       strerror(errno));
			break;
		}

		for (p = buf; p < buf + ret;) {
			e = (struct inotify_event *)p;

			/* get index of the modified file */
			for (i = 0; i < file_clbks.callbacks_count; i++)
				if (wds[i].wd == e->wd)
					break;

			snprintf(path, MAX_FILE_PATH_LEN,
				 file_clbks.callbacks[i].f_path);
			if (e->mask & IN_IGNORED) {
				/* the file was removed or replaced */
				ret = inotify_add_watch(inotify, path,
							IN_MODIFY | IN_IGNORED
							| IN_CLOSE_WRITE);
				wds[i].wd = ret;
				if (ret == -1)
					printf("ERROR: Add watch for %s: %s\n",
					       path, strerror(errno));
				else
					wds[i].flags |= FMON_FLAG_UPDATE;
			} else {
				if (e->mask & IN_MODIFY)
					wds[i].flags |= FMON_FLAG_MODIFIED;
				if ((e->mask & IN_CLOSE_WRITE) &&
				    (wds[i].flags & FMON_FLAG_MODIFIED))
					wds[i].flags |= FMON_FLAG_UPDATE;
			}

			if (wds[i].flags & FMON_FLAG_UPDATE) {

				if (wds[i].flags & FMON_FLAG_IGNORED) {
					/* ignore our own backup restore */
					wds[i].flags = 0;
					goto next;
				}

				/* null the variables */
				wds[i].flags = 0;

				/* invoke file callback */
				file_clbks.callbacks[i].func();

				/* update backup file */
				backup_file(file_clbks.callbacks[i].f_path);
			}
next:
			p += sizeof(struct inotify_event) + e->len;
		}
	}

	pthread_cleanup_pop(1);
	return NULL;
}

int sr_tsn_fcb_init(void)
{
	int ret;
	pthread_t fmon_thread;

	ret = pthread_create(&fmon_thread, NULL, file_monitor, NULL);
	if (ret != 0)
		printf("Unable to create FMON thread\n");

	pthread_detach(fmon_thread);

	return ret;
}
