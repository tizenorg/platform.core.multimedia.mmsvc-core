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
#ifndef __MUSE_CORE_IPC_H__
#define __MUSE_CORE_IPC_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "muse_core.h"
#include "muse_core_workqueue.h"
#include <tbm_bufmgr.h>

#define MUSE_DATA_HEAD 0xda1a6ead
#define MUSE_API "api"
#define MUSE_MODULE "module"
#define MUSE_MODULE_ADDR "module_addr"

typedef struct muse_core_ipc {
	tbm_bufmgr bufmgr;
	GHashTable *client_table;
	gint *key;
	void (*free)(void);
} muse_core_ipc_t;

typedef enum {
	API_CREATE,
	API_DESTROY,
	API_MAX
} muse_core_api_type_e;

gboolean muse_core_ipc_job_function(struct muse_core_workqueue_job * job);
int muse_core_ipc_send_msg(int sock_fd, const char *msg);
int muse_core_ipc_recv_msg(int sock_fd, char *msg);
int muse_core_ipc_recv_msg_ext(muse_client_h muse_client, char *msg);
void muse_core_ipc_set_timeout(int sock_fd, unsigned long timeout_sec);
gboolean muse_core_ipc_data_job_function(muse_core_workqueue_job_t * job);
int muse_core_ipc_push_data(int sock_fd, const char *data, int size, uint64_t data_id);
char *muse_core_ipc_get_data(muse_module_h module);
intptr_t muse_core_ipc_get_handle(muse_module_h module);
int muse_core_ipc_set_handle(muse_module_h module, intptr_t handle);
void muse_core_ipc_delete_data(char *data);
int muse_core_ipc_get_bufmgr(tbm_bufmgr *bufmgr);
muse_core_ipc_t *muse_core_ipc_get_instance(void);
void muse_core_ipc_init(void);

#ifdef _cplusplus
}
#endif

#endif	/*__MUSE_CORE_IPC_H__*/
