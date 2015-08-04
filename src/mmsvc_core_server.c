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

#include "mmsvc_core.h"
#include "mmsvc_core_internal.h"
#include "mmsvc_core_config.h"
#include "mmsvc_core_log.h"
#include "mmsvc_core_tool.h"
#include <gst/gst.h>

static void _mmsvc_core_server_setup_syslog(void);
static void _mmsvc_core_server_gst_init(char **cmd);
extern int mmsvc_core_run();

static void _mmsvc_core_server_setup_syslog(void)
{
	int flags = LOG_CONS|LOG_NDELAY|LOG_PID;
	if (isatty(1))
		flags |= LOG_PERROR;

	openlog("mused", flags, LOG_DAEMON);
	LOGD("openlog - mused");
}

static void _mmsvc_core_server_gst_init(char **cmd)
{
	static const int max_argc = 50;
	gint* argc = NULL;
	gchar** argv = NULL;

	LOGD("Enter");

	argc = malloc(sizeof(int));
	argv = malloc(sizeof(gchar*) * max_argc);

	if (!argc || !argv) {
		LOGE("argc ||argv is NULL");
		return;
	}
	memset(argv, 0, sizeof(gchar*) * max_argc);

	/* add initial */
	*argc = 1;
	argv[0] = g_strdup(cmd[0]);
	/* check disable registry scan */
	argv[*argc] = g_strdup("--gst-disable-registry-update");
	(*argc)++;
	LOGD("--gst-disable-registry-update");

	gst_init(argc, &argv);

	MMSVC_FREE(argv);
}

int main(int argc, char **argv)
{
	int result;
	pid_t pid, sid;

	_mmsvc_core_server_setup_syslog();
	_mmsvc_core_server_gst_init(argv);
	mmsvc_core_log_init();
	mmsvc_core_config_init();

	if (argc > 1 && argv)
		mmsvc_core_tool_parse_params(argc, argv);

	/* daemon_init */
	if (getpid() == 1) {
		LOGE("already a daemon");
		exit(0);
	}

	if ((pid = fork()) < 0) {
		LOGE("Could not fork child.");
		exit(0);
	} else if (pid != 0) {
		LOGD("PID : %d, PID CLOSE!!", pid);
		exit(0);
	}

	/* create new session */
	sid = setsid();
	if (sid < 0) {
		LOGE("sid SID : %d, PID CLOSE!!", pid);
		exit(0);
	}

	/* Change the file mode mask */
	umask(0);

	result = chdir("/");
	LOGD("result = %d", result);

	return mmsvc_core_run();
}
