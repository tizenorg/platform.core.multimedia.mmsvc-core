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

#ifndef __MMSVC_CORE_MSG_JSON_H__
#define __MMSVC_CORE_MSG_JSON_H__

#ifdef _cplusplus
extern "C" {
#endif

#include <glib.h>

#define PARAM_HANDLE		"handle"
#define PARAM_RETURN		"ret"
#define PARAM_EVENT			"event"

typedef enum {
	MMSVC_PLAYER,
	MMSVC_CAMERA,
	MMSVC_RECORDER,
	MMSVC_CLIENT_MAX
} mmsvc_api_client_e;

typedef enum {
	MUSED_TYPE_INT = 1,
	MUSED_TYPE_INT64,
	MUSED_TYPE_POINTER,
	MUSED_TYPE_DOUBLE,
	MUSED_TYPE_STRING,
	MUSED_TYPE_ARRAY,
	MUSED_TYPE_ANY,
	MUSED_TYPE_MAX
} mused_type_e;

typedef enum {
	MUSED_MSG_PARSE_ERROR_NONE,
	MUSED_MSG_PARSE_ERROR_CONTINUE,
	MUSED_MSG_PARSE_ERROR_OTHER,
	MUSED_MSG_PARSE_ERROR_MAX
} mused_msg_parse_err_e;

char * mmsvc_core_msg_json_factory_new(int api, const char *arg_name, int64_t arg, ...);
void mmsvc_core_msg_json_factory_free(char * msg);
gboolean mmsvc_core_msg_json_deserialize(char *key, char* buf, void *data, mused_msg_parse_err_e *err);
gboolean mmsvc_core_msg_json_deserialize_type(
		char *key, char* buf, void *data,
		mused_msg_parse_err_e *err, mused_type_e m_type);
gboolean mmsvc_core_msg_json_deserialize_len(
		char *key, char* buf, int *parse_len, void *data,
		mused_msg_parse_err_e *err, mused_type_e m_type);

#ifdef _cplusplus
}
#endif

#endif	/*__MMSVC_CORE_MSG_JSON_H__*/
