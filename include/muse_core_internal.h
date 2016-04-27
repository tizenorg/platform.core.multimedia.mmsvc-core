/*
 * muse-core
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: YoungHun Kim <yh8004.kim@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef __MUSE_CORE_INTERNAL_H__
#define __MUSE_CORE_INTERNAL_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include <errno.h>
#include <err.h>
#include <glib.h>
#include <getopt.h>
#include <unistd.h>
#include <ctype.h>
#include <stdarg.h>
#include <gmodule.h>
#include <stdbool.h>
#include <dlog.h>
#include <syslog.h>
#include <execinfo.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <sys/un.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pthread.h>
#include <mm_error.h>

#undef LOG_TAG
#define LOG_TAG "TIZEN_N_MUSED"
#define LOGFILE "/var/log/mused/muse-server"
#define LOCKFILE "/tmp/.muse_core.lock"
#define SOCKFILE0 "/tmp/.muse_core_socket"
#define SOCKFILE1 "/tmp/.muse_core_data_socket"

#define MUSE_DATA_ROOT_PATH TZ_SYS_DATA_PATH"/mused/"

#define READ		0x02
#define PERSIST	0x10
#define MAX_ERROR_MSG_LEN	256

#define DISPATCHER "dispatcher"
#define CMD_DISPATCHER "cmd_dispatcher"
#define MUSE_FREE(src) { if (src) {g_free(src); src = NULL;} }

#ifdef __cplusplus
}
#endif
#endif	/*__MUSE_CORE_INTERNAL_H__*/
