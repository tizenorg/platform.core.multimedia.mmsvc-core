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

#ifndef __MUSE_CORE_PRIVATE_H__
#define __MUSE_CORE_PRIVATE_H__

#include <stdint.h>
#include <glib.h>
#include <gmodule.h>
#include "muse_core_module.h"
#ifdef  __cplusplus
extern "C" {
#endif

typedef gboolean(*MUSE_MODULE_Callback) (GIOChannel * source, GIOCondition condition, gpointer data);

typedef enum {
	MUSE_CHANNEL_MSG,
	MUSE_CHANNEL_DATA,
	MUSE_CHANNEL_MAX
} muse_core_channel_e;

typedef struct muse_core_channel_info {
	GThread * p_gthread;
	int fd;
	union {
		GModule *dll_handle;
		struct {
			GQueue *queue;
			GMutex mutex;
			GCond cond;
		};
	};
} muse_core_channel_info_t;

typedef struct muse_module {
	muse_core_channel_info_t ch[MUSE_CHANNEL_MAX];
	char recvMsg[MUSE_MSG_MAX_LENGTH];
	int msg_offset;
	int api_module;
	int disp_api;
	gpointer usr_data;
	intptr_t handle;
	gboolean is_create_api_called;
} muse_module_t;

typedef struct muse_core {
	int fd;
	int data_fd;
	int type;
	int stop;
	int retval;
	gint running;
} muse_core_t;

gpointer muse_core_main_loop(gpointer data);
muse_core_t *muse_core_new();
gboolean muse_core_connection_handler(GIOChannel * source, GIOCondition condition, gpointer data);

#ifdef __cplusplus
}
#endif
#endif	/*__MUSE_CORE_PRIVATE_H__*/
