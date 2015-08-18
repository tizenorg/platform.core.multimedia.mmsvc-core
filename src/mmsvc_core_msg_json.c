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

#include <json.h>
#include <json_tokener.h>
#include "mmsvc_core_msg_json.h"
#include "mmsvc_core_log.h"
#include "mmsvc_core_internal.h"

static json_object *_mmsvc_core_msg_json_find_obj(json_object * jobj, char *find_key)
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

static void _mmsvc_core_msg_json_set_error(mused_msg_parse_err_e *err, int jerr)
{
	if (err != NULL) {
		switch (jerr) {
		case json_tokener_success:
			*err = MUSED_MSG_PARSE_ERROR_NONE;
			break;
		case json_tokener_continue:
			*err = MUSED_MSG_PARSE_ERROR_CONTINUE;
			break;
		default:
			*err = MUSED_MSG_PARSE_ERROR_OTHER;
			break;
		}
	}
}

static json_object *_mmsvc_core_msg_json_tokener_parse_len(const char *str, int *len, mused_msg_parse_err_e *err)
{
	struct json_tokener *tok;
	struct json_object *obj;

	g_return_val_if_fail(str != NULL, NULL);
	g_return_val_if_fail(len != NULL, NULL);

	tok = json_tokener_new();

	g_return_val_if_fail(tok != NULL, NULL);

	obj = json_tokener_parse_ex(tok, str, *len);
	g_return_val_if_fail(obj != NULL, NULL);

	*len = tok->char_offset;

	if (tok->err != json_tokener_success) {
		LOGE("Json Error(%d) : %s", tok->err, json_tokener_error_desc(tok->err));
		json_object_put(obj);
		obj = NULL;
	}
	_mmsvc_core_msg_json_set_error(err, tok->err);

	json_tokener_free(tok);
	return obj;
}

static void _mmsvc_core_msg_json_factory_args(json_object *jobj, va_list ap)
{
	int type;
	char *name;

	while ((type = va_arg(ap, int)) != 0) {
		name = va_arg(ap, char *);
		LOGD("name: %s ", name);
		switch (type) {
		case MUSED_TYPE_INT:
			json_object_object_add(jobj, name, json_object_new_int(va_arg(ap, int32_t)));
			break;
		case MUSED_TYPE_INT64:
			json_object_object_add(jobj, name, json_object_new_int64(va_arg(ap, int64_t)));
			break;
		case MUSED_TYPE_POINTER:
			if(sizeof(intptr_t) == 8)
				json_object_object_add(jobj, name, json_object_new_int64(va_arg(ap, intptr_t)));
			else
				json_object_object_add(jobj, name, json_object_new_int(va_arg(ap, intptr_t)));
			break;
		case MUSED_TYPE_DOUBLE:
			json_object_object_add(jobj, name, json_object_new_double(va_arg(ap, double)));
			break;
		case MUSED_TYPE_STRING:
			json_object_object_add(jobj, name, json_object_new_string(va_arg(ap, char *)));
			break;
		case MUSED_TYPE_ARRAY:
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

char *mmsvc_core_msg_json_factory_new(int api, const char *arg_name, int64_t arg, ...)
{
	json_object *jobj;
	const char *jsonMsg;
	char *sndMsg;
	va_list ap;

	jobj = json_object_new_object();

	g_return_val_if_fail(jobj != NULL, NULL);

	json_object_object_add(jobj, "api", json_object_new_int(api));
	if (arg_name)
		json_object_object_add(jobj, arg_name, json_object_new_int64(arg));
	else
		LOGE("Error - null arg_name");

	va_start(ap, arg);
	_mmsvc_core_msg_json_factory_args(jobj, ap);
	va_end(ap);

	jsonMsg = json_object_to_json_string(jobj);
	sndMsg = g_strdup(jsonMsg);
	mmsvc_core_log_get_instance()->set_msg(sndMsg);
	LOGD("json msg : %s\n", sndMsg);

	json_object_put(jobj);

	return sndMsg;
}

void mmsvc_core_msg_json_factory_free(char *msg)
{
	MMSVC_FREE(msg);
}

gboolean mmsvc_core_msg_json_deserialize(char *key, char* buf, void *data, mused_msg_parse_err_e *err)
{
	int len = 0;

	g_return_val_if_fail(buf != NULL, FALSE);
	g_return_val_if_fail(data != NULL, FALSE);

	len = strlen(buf);
	return mmsvc_core_msg_json_deserialize_len(key, buf, &len, data, err, MUSED_TYPE_ANY);
}

gboolean mmsvc_core_msg_json_deserialize_type(
		char *key, char* buf, void *data,
		mused_msg_parse_err_e *err, mused_type_e m_type)
{
	int len = 0;

	g_return_val_if_fail(buf != NULL, FALSE);
	g_return_val_if_fail(data != NULL, FALSE);

	len = strlen(buf);
	return mmsvc_core_msg_json_deserialize_len(key, buf, &len, data, err, m_type);
}

gboolean mmsvc_core_msg_json_deserialize_len(
		char *key, char* buf, int *parse_len, void *data,
		mused_msg_parse_err_e *err, mused_type_e m_type)
{
	int j_type;
	json_object *val, *jobj;

	g_return_val_if_fail(key != NULL, FALSE);
	g_return_val_if_fail(buf != NULL, FALSE);
	g_return_val_if_fail(data != NULL, FALSE);
	g_return_val_if_fail(parse_len != NULL, FALSE);

	jobj = _mmsvc_core_msg_json_tokener_parse_len(buf, parse_len, err);
	g_return_val_if_fail(jobj != NULL, FALSE);

	val = _mmsvc_core_msg_json_find_obj(jobj, key);
	if (!val) {
		LOGE("\"%s\" key is not founded", key);
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
		if(m_type == MUSED_TYPE_ANY || m_type == MUSED_TYPE_INT) {
			*(int32_t *)data = json_object_get_int(val);
			LOGD("json_type_int (%s)          value: %d (32)", key, *(int32_t *)data);
		}
		else if(m_type == MUSED_TYPE_INT64) {
			*(int64_t *)data = json_object_get_int64(val);
			LOGD("json_type_int (%s)          value: %" G_GINT64_FORMAT "(64)", key, *(int64_t *)data);
		}
		else if(m_type == MUSED_TYPE_POINTER) {
			if(sizeof(intptr_t) == 8)
				*(intptr_t *)data = json_object_get_int64(val);
			else
				*(intptr_t *)data = json_object_get_int(val);
			LOGD("json_type_int (%s)          value: %p", key, *(intptr_t *)data);
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
		len = json_object_array_length(val);
		for (i = 0; i < len; i++)
			int_data[i] = json_object_get_int(json_object_array_get_idx(val, i));
		break;
	}
	json_object_put(jobj);
	return TRUE;
}
