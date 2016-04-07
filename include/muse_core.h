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

#ifndef __MUSE_CORE_H__
#define __MUSE_CORE_H__

#ifdef  __cplusplus
extern "C" {
#endif

#define MUSE_URI_MAX_LENGTH 4096
#define MUSE_MSG_MAX_LENGTH 4096

typedef struct muse_module * muse_module_h;

typedef enum {
	MUSE_MODULE_COMMAND_INITIALIZE = 0,
	MUSE_MODULE_COMMAND_SHUTDOWN,
	MUSE_MODULE_COMMAND_DEBUG_INFO_DUMP,
	MUSE_MODULE_COMMAND_MAX
} muse_module_command_e;

int muse_core_run(void);
void muse_core_cmd_dispatch(muse_module_h module, muse_module_command_e cmd);
void muse_core_connection_close(int sock_fd);
int muse_core_client_new(void);
int muse_core_client_new_data_ch(void);
int muse_core_client_get_msg_fd(muse_module_h module);
int muse_core_client_get_data_fd(muse_module_h module);
void muse_core_client_set_cust_data(muse_module_h module, void *data);
void *muse_core_client_get_cust_data(muse_module_h module);
char *muse_core_client_get_msg(muse_module_h module);
int muse_core_client_get_capi(muse_module_h module);
int muse_core_client_set_value(muse_module_h module, const char *value_name, int set_value);
int muse_core_client_get_value(muse_module_h module, const char *value_name, int *get_value);
void muse_core_worker_exit(muse_module_h module);
unsigned muse_core_get_atomic_uint(void);

#ifdef __cplusplus
}
#endif
#endif	/*__MUSE_CORE_H__*/
