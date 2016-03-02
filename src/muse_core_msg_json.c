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
#include <json_tokener.h>
#include "muse_core_msg_json.h"
#include "muse_core_log.h"
#include "muse_core_ipc.h"
#include "muse_core_internal.h"

typedef struct muse_core_msg_json {
	struct json_object *jso;
	struct json_tokener *tok;
	int parsed_len;
} muse_core_msg_json_t;

static muse_core_msg_json_t *g_muse_core_msg_json = NULL;

static void _muse_core_msg_json_init()
{
	if (g_muse_core_msg_json == NULL) {
		LOGD("Init g_muse_core_msg_json");
		g_muse_core_msg_json = calloc(1, sizeof(*g_muse_core_msg_json));
		g_return_if_fail(g_muse_core_msg_json != NULL);
	}
}

static void _muse_core_msg_json_tokener_new()
{
	LOGD("Enter");

	if (g_muse_core_msg_json->tok == NULL) {
		g_muse_core_msg_json->tok = json_tokener_new();
		LOGD("Init json_tokener: %p", g_muse_core_msg_json->tok);
	}

	LOGD("Leave");
}

static void _muse_core_msg_json_object_new()
{
	LOGD("Enter");

	if (g_muse_core_msg_json == NULL)
		_muse_core_msg_json_init();

	if (g_muse_core_msg_json->jso != NULL) {
		LOGD("free jso: %p", g_muse_core_msg_json->jso);
		json_object_put(g_muse_core_msg_json->jso);
		LOGD("json_tokener_reset: %p", g_muse_core_msg_json->tok);
		json_tokener_reset(g_muse_core_msg_json->tok);
		g_muse_core_msg_json->jso = NULL;
		g_muse_core_msg_json->parsed_len = 0;
	}

	LOGD("Leave");
}

static json_object *_muse_core_msg_json_find_obj(const char *find_key)
{
	size_t key_len = 0;

	g_return_val_if_fail(g_muse_core_msg_json != NULL, NULL);
	g_return_val_if_fail(g_muse_core_msg_json->jso != NULL, NULL);

	g_return_val_if_fail(find_key != NULL, NULL);

	key_len = strlen(find_key);

	json_object_object_foreach(g_muse_core_msg_json->jso, key, val) {
		if (strlen(key) == key_len && !memcmp(key, find_key, key_len)) {
			LOGD("[%s] : %s", key, json_object_to_json_string(val));
			return val;
		}
	}

	return NULL;
}

static void _muse_core_msg_json_set_error(muse_core_msg_parse_err_e *err, enum json_tokener_error *jerr)
{
	if (err != NULL) {
		switch (*jerr) {
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

static void _muse_core_msg_json_get_object_value(const char *key, void *data, muse_core_type_e m_type)
{
	int j_type;
	json_object *val;

	g_return_if_fail(g_muse_core_msg_json != NULL);
	g_return_if_fail(g_muse_core_msg_json->jso != NULL);

	LOGD("current json_object: %p", g_muse_core_msg_json->jso);

	val = _muse_core_msg_json_find_obj(key);
	if (!val) {
		LOGE("\"%s\" key is not founded", key);
		return;
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
}

static json_object *_muse_core_msg_json_tokener_parse_len(const char *str, enum json_tokener_error *jerr, muse_core_msg_parse_err_e *err)
{
	struct json_object *obj;
	int str_len;

	g_return_val_if_fail(str != NULL, NULL);

	LOGD("Enter");

	_muse_core_msg_json_tokener_new();
	str_len = strlen(str);

	obj = json_tokener_parse_ex(g_muse_core_msg_json->tok, str, str_len);
	*jerr = json_tokener_get_error(g_muse_core_msg_json->tok);

	g_muse_core_msg_json->parsed_len += g_muse_core_msg_json->tok->char_offset;

	LOGD("[parse length : %d] Parse Result : %s", g_muse_core_msg_json->tok->char_offset, json_tokener_error_desc(*jerr));

	if (*jerr == json_tokener_success)
		_muse_core_msg_json_set_error(err, jerr);

	LOGD("Leave");

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

	_muse_core_msg_json_object_new(); /* muse module object */
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
	enum json_tokener_error jerr = json_tokener_error_size;

	g_return_val_if_fail(key != NULL, FALSE);
	g_return_val_if_fail(buf != NULL, FALSE);
	g_return_val_if_fail(data != NULL, FALSE);

	_muse_core_msg_json_init(); /* muse core object */

	if (strcmp(key, MUSE_API) == 0) {
		g_muse_core_msg_json->jso = _muse_core_msg_json_tokener_parse_len(buf, &jerr, err);
		if (g_muse_core_msg_json->jso) LOGD("created json_object: %p", g_muse_core_msg_json->jso);
	} else {
		LOGD("reuse json_object: %p", g_muse_core_msg_json->jso);
	}

	if (g_muse_core_msg_json->jso) {
		if (parse_len)
			*parse_len = g_muse_core_msg_json->parsed_len;
		else
			g_muse_core_msg_json->parsed_len = 0;

		_muse_core_msg_json_get_object_value(key, data, m_type);
		return TRUE;
	} else {
		return FALSE;
	}
}

void muse_core_msg_json_object_free(void)
{
	if (g_muse_core_msg_json->jso) {
		LOGD("json_object_put");
		json_object_put(g_muse_core_msg_json->jso);
	}

	if (g_muse_core_msg_json->tok) {
		LOGD("json_tokener_free");
		json_tokener_free(g_muse_core_msg_json->tok);
	}

	MUSE_FREE(g_muse_core_msg_json);

}
