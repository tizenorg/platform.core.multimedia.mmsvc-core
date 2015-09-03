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

#ifndef __MMSVC_CORE_H__
#define __MMSVC_CORE_H__

#ifdef  _cplusplus
extern "C" {
#endif

#define MM_URI_MAX_LENGTH 4096
#define MM_MSG_MAX_LENGTH 1024*1024

typedef struct __Client * Client;

typedef enum {
	MUSED_DOMAIN_EVENT_DEFINED = 0,
	MUSED_DOMAIN_EVENT_UNDEFINED = 1,
	MUSED_DOMAIN_EVENT_STARTED = 2,
	MUSED_DOMAIN_EVENT_STOPPED = 3,
	MUSED_DOMAIN_EVENT_SHUTDOWN = 4,
	MUSED_DOMAIN_EVENT_CRASHED = 5
} mused_domain_event_e;

int mmsvc_core_run(void);
void mmsvc_core_cmd_dispatch(Client client, mused_domain_event_e ev);
void mmsvc_core_connection_close(int sock_fd);
int mmsvc_core_client_new(void);
int mmsvc_core_client_new_data_ch(void);
int mmsvc_core_client_get_msg_fd(Client client);
int mmsvc_core_client_get_data_fd(Client client);
void mmsvc_core_client_set_cust_data(Client client, void *data);
void *mmsvc_core_client_get_cust_data(Client client);
char *mmsvc_core_client_get_msg(Client client);
int mmsvc_core_client_get_capi(Client client);
void mmsvc_core_worker_exit(Client client);
unsigned mmsvc_core_get_atomic_uint(void);

#ifdef __cplusplus
}
#endif
#endif	/*__MMSVC_CORE_H__*/
