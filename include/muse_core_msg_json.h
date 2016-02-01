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

#ifndef __MUSE_CORE_MSG_JSON_H__
#define __MUSE_CORE_MSG_JSON_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>

#define MUSE_PARAM_HANDLE		"handle"
#define MUSE_PARAM_RETURN		"ret"
#define MUSE_PARAM_EVENT	 		"event"

typedef enum {
	MUSE_TYPE_INT = 1,
	MUSE_TYPE_INT64,
	MUSE_TYPE_POINTER,
	MUSE_TYPE_DOUBLE,
	MUSE_TYPE_STRING,
	MUSE_TYPE_ARRAY,
	MUSE_TYPE_ANY,
	MUSE_TYPE_MAX
} muse_core_type_e;

typedef enum {
	MUSE_MSG_PARSE_ERROR_NONE,
	MUSE_MSG_PARSE_ERROR_CONTINUE,
	MUSE_MSG_PARSE_ERROR_OTHER,
	MUSE_MSG_PARSE_ERROR_MAX
} muse_core_msg_parse_err_e;

char * muse_core_msg_json_factory_new(int api, ...);
void muse_core_msg_json_factory_free(char * msg);
gboolean muse_core_msg_json_deserialize(
		const char *key, char* buf, int *parse_len, void *data,
		muse_core_msg_parse_err_e *err, muse_core_type_e m_type);

#ifdef __cplusplus
}
#endif

#endif	/*__MUSE_CORE_MSG_JSON_H__*/
