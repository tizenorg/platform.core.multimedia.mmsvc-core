/*
 * mmsvc-core
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
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

#ifndef __MMSVC_CORE_INTERNAL_H__
#define __MMSVC_CORE_INTERNAL_H__

#ifdef _cplusplus
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
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pthread.h>

#undef LOG_TAG
#define LOG_TAG "TIZEN_N_MUSED"
#define MUSED_DIR "/var/run/mused"
#define LOGFILE "/tmp/mmsvc_core_log"
#define LOCKFILE "/tmp/.mmsvc-core.lock"
#define SOCKFILE0 "/tmp/.mmsvc_core_socket"
#define SOCKFILE1 "/tmp/.mmsvc_core_data_socket"

#define TIMEOUT	0x01
/** Wait for a socket or FD to become readable */
#define READ		0x02
/** Wait for a socket or FD to become writeable */
#define WRITE		0x04
/** Wait for a POSIX signal to be raised*/
#define SIGNAL		0x08
#define PERSIST	0x10
/** Select edge-triggered behavior, if supported by the backend. */
#define EDGETRIGGERED 	0x20

#define DISPATCHER "dispatcher"
#define MMSVC_FREE(src) { if(src) {g_free(src); src = NULL;} }

#ifdef __cplusplus
}
#endif
#endif	/*__MMSVC_CORE_INTERNAL_H__*/
