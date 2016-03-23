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

#include <json.h>
#include "muse_core_msg_json.h"
#include "muse_core_log.h"
#include "muse_core_ipc.h"
#include "muse_core_internal.h"

static json_object *_muse_core_msg_json_find_obj(json_object * jobj, const char *find_key)
{
	size_t key_len = 0;

	g_return_val_if_fail(jobj != NULL, NULL);

	g_return_val_if_fail(find_key != NULL, NULL);

	key_len = strlen(find_key);

	json_object_object_foreach(jobj, key, val) {
		if (strlen(key) == key_len && !memcmp(key, find_key, key_len))
			return val;
	}

	return NULL;
}

static void _muse_core_msg_json_set_error(muse_core_msg_parse_err_e *err, int jerr)
{
	if (err != NULL) {
		switch (jerr) {
		case json_tokener_success:
			*err = MUSE_MSG_PARSE_ERROR_NONE;
			break;
		case json_tokener_continue:
			*err = MUSE_MSG_PARSE_ERROR_CONTINUE;
			break;
		default:
			*err = MUSE_MSG_PARSE_ERROR_OTHER;
			break;
		}
	}
}

static json_object *_muse_core_msg_json_tokener_parse_len(const char *str, int *len, muse_core_msg_parse_err_e *err)
{
	struct json_tokener *tok;
	struct json_object *obj;

	g_return_val_if_fail(str != NULL, NULL);

	tok = json_tokener_new();

	g_return_val_if_fail(tok != NULL, NULL);

	obj = json_tokener_parse_ex(tok, str, strlen(str));
	g_return_val_if_fail(obj != NULL, NULL);

	if (len)
		*len = tok->char_offset;

	if (tok->err != json_tokener_success) {
		LOGE("Json Error(%d) : %s", tok->err, json_tokener_error_desc(tok->err));
		json_object_put(obj);
		obj = NULL;
	}
	_muse_core_msg_json_set_error(err, tok->err);

	json_tokener_free(tok);
	return obj;
}

static void _muse_core_msg_json_factory_args(json_object *jobj, va_list ap)
{
	int type;
	char *name;

	while ((type = va_arg(ap, int)) != 0) {
		name = va_arg(ap, char *);
		LOGD("[type:#%d] key: %s ", type, name);
		switch (type) {
		case MUSE_TYPE_INT:
			json_object_object_add(jobj, name, json_object_new_int(va_arg(ap, int32_t)));
			break;
		case MUSE_TYPE_INT64:
			json_object_object_add(jobj, name, json_object_new_int64(va_arg(ap, int64_t)));
			break;
		case MUSE_TYPE_POINTER:
			if (sizeof(intptr_t) == 8)
				json_object_object_add(jobj, name, json_object_new_int64(va_arg(ap, intptr_t)));
			else
				json_object_object_add(jobj, name, json_object_new_int(va_arg(ap, intptr_t)));
			break;
		case MUSE_TYPE_DOUBLE:
			json_object_object_add(jobj, name, json_object_new_double(va_arg(ap, double)));
			break;
		case MUSE_TYPE_STRING:
			json_object_object_add(jobj, name, json_object_new_string(va_arg(ap, char *)));
			break;
		case MUSE_TYPE_ARRAY:
			{
				int len = va_arg(ap, int);
				int *value = va_arg(ap, int *);
				int i;
				json_object *jarr = json_object_new_array();

				for (i = 0; i < len; i++)
					json_object_array_add(jarr, json_object_new_int(value[i]));
				json_object_object_add(jobj, name, jarr);
			}
			break;
		default:
			LOGE("Unexpected type");
		}
	}
}

char *muse_core_msg_json_factory_new(int api, ...)
{
	json_object *jobj;
	const char *jsonMsg;
	char *sndMsg;
	va_list ap;

	jobj = json_object_new_object();

	g_return_val_if_fail(jobj != NULL, NULL);

	json_object_object_add(jobj, MUSE_API, json_object_new_int(api));

	va_start(ap, api);
	_muse_core_msg_json_factory_args(jobj, ap);
	va_end(ap);

	jsonMsg = json_object_to_json_string(jobj);
	sndMsg = g_strdup(jsonMsg);
	muse_core_log_get_instance()->set_msg(sndMsg);

	LOGD("json msg : %s", sndMsg);

	json_object_put(jobj);

	return sndMsg;
}

void muse_core_msg_json_factory_free(char *msg)
{
	MUSE_FREE(msg);
}

gboolean muse_core_msg_json_deserialize(
		const char *key, char* buf, int *parse_len, void *data,
		muse_core_msg_parse_err_e *err, muse_core_type_e m_type)
{
	int j_type;
	json_object *val, *jobj;

	g_return_val_if_fail(key != NULL, FALSE);
	g_return_val_if_fail(buf != NULL, FALSE);
	g_return_val_if_fail(data != NULL, FALSE);

	jobj = _muse_core_msg_json_tokener_parse_len(buf, parse_len, err);
	g_return_val_if_fail(jobj != NULL, FALSE);

	val = _muse_core_msg_json_find_obj(jobj, key);
	if (!val) {
		LOGE("\"%s\" key is not founded", key);
		json_object_put(jobj);
		return FALSE;
	}

	j_type = json_object_get_type(val);
	switch (j_type) {
	case json_type_null:
		LOGD("json_type_null\n");
		break;
	case json_type_boolean:
		LOGD("json_type_boolean (%s)          value: %d", key, json_object_get_boolean(val));
		break;
	case json_type_double:
		*(double *)data = json_object_get_double(val);
		LOGD("json_type_double (%s)          value: %p", key, (double *)data);
		break;
	case json_type_int:
		if (m_type == MUSE_TYPE_ANY || m_type == MUSE_TYPE_INT) {
			*(int32_t *)data = json_object_get_int(val);
			LOGD("json_type_int (%s)          value: %d", key, *(int32_t *)data);
		} else if (m_type == MUSE_TYPE_INT64) {
			*(int64_t *)data = json_object_get_int64(val);
			LOGD("json_type_int (%s)          value: %" G_GINT64_FORMAT "", key, *(int64_t *)data);
		} else if (m_type == MUSE_TYPE_POINTER) {
			if (sizeof(intptr_t) == 8)
				*(intptr_t *)data = json_object_get_int64(val);
			else
				*(intptr_t *)data = json_object_get_int(val);
			LOGD("json_type_int (%s)          value: %p", key, *(intptr_t *)data);
		} else if (m_type == MUSE_TYPE_DOUBLE) {
			*(double *)data = json_object_get_double(val);
			LOGD("json_type_double (%s)          value: %.20lf", key, *(double *)data);
		}
		break;
	case json_type_object:
		LOGD("json_type_object (%s)          value: %d", key, json_object_get_object(val));
		break;
	case json_type_string:
		strncpy((char *)data, json_object_get_string(val), strlen(json_object_get_string(val)));
		LOGD("json_type_string (%s)          value: %s", key, (char *)data);
		break;
	case json_type_array:
		LOGD("json_type_array (%s)", key);
		int i, len;
		int *int_data = (int *)data;
		LOGD("array length: %d", len = json_object_array_length(val));
		for (i = 0; i < len; i++)
			int_data[i] = json_object_get_int(json_object_array_get_idx(val, i));
		break;
	default:
		LOGW("type is not yet implemented");
		break;
	}
	json_object_put(jobj);
	return TRUE;
}
