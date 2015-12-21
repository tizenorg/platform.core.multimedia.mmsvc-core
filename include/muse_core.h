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

#ifdef  __cplusplus
extern "C" {
#endif

#define MUSE_URI_MAX_LENGTH 4096
#define MUSE_MSG_MAX_LENGTH 4096

typedef struct muse_module * muse_module_h;

typedef enum {
	MUSE_MODULE_EVENT_SHUTDOWN = 0,
	MUSE_MODULE_EVENT_DEBUG_INFO_DUMP,
	MUSE_MODULE_EVENT_MAX
} muse_module_event_e;

typedef enum {
	MUSE_MODULE_STATE_NULL = 0,
	MUSE_MODULE_STATE_READY,
	MUSE_MODULE_STATE_PREPARE,
	MUSE_MODULE_STATE_PREVIEW,
	MUSE_MODULE_STATE_PLAYING,
	MUSE_MODULE_STATE_CAPTURING,
	MUSE_MODULE_STATE_RECORDING,
	MUSE_MODULE_STATE_PAUSED,
	MUSE_MODULE_STATE_MAX
} muse_module_state_e;

typedef enum {
	MUSE_MODULE_CAM_FLASH_OFF = 0,
	MUSE_MODULE_CAM_FALSH_ON,
	MUSE_MODULE_CAM_FALSH_MAX
} muse_module_cam_flash_state_e;

typedef enum {
	MUSE_MODULE_CAM_SHUTTER_SOUND_POLICY_ON = 0,
	MUSE_MODULE_CAM_SHUTTER_SOUND_POLICY_OFF,
	MUSE_MODULE_CAM_SHUTTER_SOUND_POLICY_MAX
} muse_module_cam_shutter_sound_policy_e;

int muse_core_run(void);
void muse_core_cmd_dispatch(muse_module_h module, muse_module_event_e ev);
void muse_core_connection_close(int sock_fd);
int muse_core_client_new(void);
int muse_core_client_new_data_ch(void);
int muse_core_client_get_msg_fd(muse_module_h module);
int muse_core_client_get_data_fd(muse_module_h module);
void muse_core_client_set_cust_data(muse_module_h module, void *data);
void *muse_core_client_get_cust_data(muse_module_h module);
char *muse_core_client_get_msg(muse_module_h module);
int muse_core_client_get_capi(muse_module_h module);
void muse_core_client_set_state(muse_module_h module, muse_module_state_e module_state);
int muse_core_client_get_state(muse_module_h module);
void muse_core_cam_client_set_flash_state(muse_module_h module, muse_module_cam_flash_state_e cam_flash_state);
int muse_core_cam_client_get_flash_state(muse_module_h module);
void muse_core_cam_client_set_shutter_sound_policy_value(muse_module_h module, muse_module_cam_shutter_sound_policy_e cam_shutter_sound_policy);
int muse_core_cam_client_get_shutter_sound_policy_value(muse_module_h module);
void muse_core_worker_exit(muse_module_h module);
unsigned muse_core_get_atomic_uint(void);

#ifdef __cplusplus
}
#endif
#endif	/*__MUSE_CORE_H__*/
