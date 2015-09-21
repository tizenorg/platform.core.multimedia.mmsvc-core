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
#ifndef __MMSVC_CORE_IPC_H__
#define __MMSVC_CORE_IPC_H__

#ifdef _cplusplus
extern "C" {
#endif

#include "mmsvc_core.h"
#include "mmsvc_core_workqueue.h"
#include <tbm_bufmgr.h>

#define MUSED_DATA_HEAD 0xda1a6ead

typedef struct mmsvc_core_ipc {
	tbm_bufmgr bufmgr;
	void (*deinit)(void);
} mmsvc_core_ipc_t;

typedef enum {
	API_CREATE,
	API_DESTROY,
	API_MAX
} api_type_e;

/**
 * @brief Create and send address of server side client infomation structure.
 * @remarks Does NOT guarantee thread safe.
 * @param[in] client The server side client infomation.
 * @param[in] fd socket fd
 */
#define mmsvc_core_send_client_addr(module, fd) \
	do{	\
		char *__sndMsg__; \
		int __len__; \
		__sndMsg__ = mmsvc_core_msg_json_factory_new(0, #module, module, \
				0); \
		__len__ = mmsvc_core_ipc_send_msg(fd, __sndMsg__); \
		mmsvc_core_msg_json_factory_free(__sndMsg__); \
		if (__len__ <= 0) { \
			LOGE("sending message failed"); \
			return PLAYER_ERROR_INVALID_OPERATION; \
		} \
	}while(0)

gboolean mmsvc_core_ipc_job_function(struct mmsvc_core_workqueue_job * job);
int mmsvc_core_ipc_send_msg(int sock_fd, const char *msg);
int mmsvc_core_ipc_recv_msg(int sock_fd, char *msg);

gboolean mmsvc_core_ipc_data_job_function(mmsvc_core_workqueue_job_t * job);
int mmsvc_core_ipc_push_data(int sock_fd, const char *data, int size, int data_id);
char *mmsvc_core_ipc_get_data(Module module);
intptr_t mmsvc_core_ipc_get_handle(Module module);
int mmsvc_core_ipc_set_handle(Module module, intptr_t handle);
void mmsvc_core_ipc_delete_data(char *data);
int mmsvc_core_ipc_get_bufmgr(tbm_bufmgr *bufmgr);
mmsvc_core_ipc_t *mmsvc_core_ipc_get_instance(void);
void mmsvc_core_ipc_init(void);

#ifdef _cplusplus
}
#endif

#endif	/*__MMSVC_CORE_IPC_H__*/
