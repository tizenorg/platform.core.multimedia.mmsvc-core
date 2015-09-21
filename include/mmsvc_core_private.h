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

#ifndef __MMSVC_CORE_PRIVATE_H__
#define __MMSVC_CORE_PRIVATE_H__

#include <stdint.h>
#include <glib.h>
#include <gmodule.h>

#ifdef  _cplusplus
extern "C" {
#endif

typedef gboolean(*MMSVC_CORE_ClientCallback) (GIOChannel * source, GIOCondition condition, gpointer data);

typedef enum {
	MUSED_CHANNEL_MSG,
	MUSED_CHANNEL_DATA,
	MUSED_CHANNEL_MAX
} mused_channel_e;

typedef struct {
	GThread * p_gthread;
	int fd;
	union {
		GModule *module;
		struct {
			GQueue *queue;
			GMutex mutex;
			GCond cond;
		};
	};
} channel_info;

typedef struct __Module{
	channel_info ch[MUSED_CHANNEL_MAX];
	char recvMsg[MM_MSG_MAX_LENGTH];
	int msg_offset;
	int disp_api;
	gpointer usr_data;
	intptr_t handle;
} _Module;

typedef struct {
	int fd;
	int data_fd;
	int type;
	int stop;
	int retval;
	gint running;
} MUSED;

gpointer mmsvc_core_main_loop(gpointer data);
MUSED *mmsvc_core_new();
gboolean mmsvc_core_connection_handler(GIOChannel * source, GIOCondition condition, gpointer data);

#ifdef __cplusplus
}
#endif
#endif	/*__MMSVC_CORE_PRIVATE_H__*/
