/*
 * muse-core
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

#include "muse_core.h"
#include "muse_core_internal.h"
#include "muse_core_config.h"
#include "muse_core_ipc.h"
#include "muse_core_log.h"
#include "muse_core_tool.h"
#include <gst/gst.h>

static void _muse_core_server_setup_syslog(void);
static void _muse_core_server_gst_init(char **cmd);
extern int muse_core_run();

static void _muse_core_server_setup_syslog(void)
{
	int flags = LOG_CONS|LOG_NDELAY|LOG_PID;
	if (isatty(1))
		flags |= LOG_PERROR;

	openlog("mused", flags, LOG_DAEMON);
	LOGD("openlog - mused");
}

static void _muse_core_server_gst_init(char **cmd)
{
	gint* argc = NULL;
	gchar** argv = NULL;
	GError *err = NULL;
	gboolean ret = FALSE;
	int i;
	int gst_param_cnt;

	gst_param_cnt = muse_core_config_get_instance()->get_gst_param_cnt();
	argc = malloc(sizeof(gint*));
	g_return_val_if_fail(argc != NULL, NULL);

	/* add gst_param */
	argv = malloc(sizeof(gchar*) * (gst_param_cnt + 1));
	g_return_val_if_fail(argv != NULL, NULL);
	memset(argv, 0, sizeof(gchar*) * (gst_param_cnt + 1));

	argv[0] = g_strdup(cmd[0]);
	for (*argc = 1; (*argc) <= gst_param_cnt; (*argc)++)
		argv[*argc] = g_strdup(muse_core_config_get_instance()->get_gst_param_str((*argc) - 1));

	/* initializing gstreamer */
	ret = gst_init_check (argc, &argv, &err);
	if (!ret) {
		LOGE("Could not initialize GStreamer: %s ", err ? err->message : "unknown error occurred");
		if (err)
			g_error_free (err);
	}

	/* release */
	for (i = 0; i < *argc; i++) {
		MUSE_FREE(argv[i]);
	}

	MUSE_FREE(argv);
	MUSE_FREE(argc);
}

int main(int argc, char **argv)
{
	int result;
	pid_t pid, sid;

	_muse_core_server_setup_syslog();
	muse_core_config_init();
	muse_core_log_init();
	muse_core_ipc_init();
	_muse_core_server_gst_init(argv);

	if (argc > 1 && argv)
		muse_core_tool_parse_params(argc, argv);

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
		LOGE("SID : %d, PID CLOSE!!", sid);
		exit(0);
	}

	/* Change the file mode mask */
	umask(0);

	result = chdir("/");
	LOGD("result = %d", result);

	return muse_core_run();
}
