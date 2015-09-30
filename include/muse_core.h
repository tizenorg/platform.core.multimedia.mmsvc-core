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

#ifndef __MUSE_CORE_H__
#define __MUSE_CORE_H__

#ifdef  _cplusplus
extern "C" {
#endif

#define MUSE_URI_MAX_LENGTH 4096
#define MUSE_MSG_MAX_LENGTH 1024*1024

typedef struct pmuse_module * muse_module_t;

typedef enum {
	MUSE_MODULE_EVENT_SHUTDOWN = 0,
	MUSE_MODULE_EVENT_DEBUG_INFO_DUMP,
	MUSE_MODULE_EVENT_MAX
} muse_module_event_e;

int muse_core_run(void);
void muse_core_cmd_dispatch(muse_module_t module, muse_module_event_e ev);
void muse_core_connection_close(int sock_fd);
int muse_core_client_new(void);
int muse_core_client_new_data_ch(void);
int muse_core_client_get_msg_fd(muse_module_t module);
int muse_core_client_get_data_fd(muse_module_t module);
void muse_core_client_set_cust_data(muse_module_t module, void *data);
void *muse_core_client_get_cust_data(muse_module_t module);
char *muse_core_client_get_msg(muse_module_t module);
int muse_core_client_get_capi(muse_module_t module);
void muse_core_worker_exit(muse_module_t module);
unsigned muse_core_get_atomic_uint(void);

#ifdef __cplusplus
}
#endif
#endif	/*__MUSE_CORE_H__*/
