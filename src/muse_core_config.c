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

#include "muse_core_config.h"
#include "muse_core_internal.h"

static muse_core_config_t *g_muse_core_conf = NULL;

static int _muse_core_config_parser(void);
static void _muse_core_config_free(void);
static char *_muse_core_config_get_path(int api_client);
static int _muse_core_config_get_gst_param_cnt(void);
static char *_muse_core_config_get_host(int);
static char *_muse_core_config_get_gst_param_str(int idx);
static void _muse_core_config_init_instance(void (*free)(void), char* (*get_path)(int), char* (*get_preloaded)(int), int (*get_gst_param_cnt)(void),
	char* (*get_gst_param_str)(int), char* (*get_host)(int), int (*get_host_cnt)(void));

static int _muse_core_config_parser(void)
{
	char *host;
	char *str;
	int idx;
	int ret = -1;
	char *ptr = NULL;

	g_return_val_if_fail(g_muse_core_conf != NULL, ret);

	g_muse_core_conf->muse_dict = iniparser_load(CONFFILE);
	g_return_val_if_fail(g_muse_core_conf->muse_dict != NULL, ret);

	str = iniparser_getstring(g_muse_core_conf->muse_dict, MUSEHOST, NULL);
	g_return_val_if_fail(str != NULL, ret);

	g_muse_core_conf->hosts = strdup(str);
	if (!g_muse_core_conf->hosts) {
		LOGE("Error - hosts allocation");
		_muse_core_config_free();
	}

	str = iniparser_getstring(g_muse_core_conf->muse_dict, MUSELOG, NULL);
	g_return_val_if_fail(str != NULL, ret);

	g_muse_core_conf->logfile = strdup(str);
	if (!g_muse_core_conf->logfile) {
		LOGE("Error - logfile allocation");
		_muse_core_config_free();
	}

	g_muse_core_conf->gst_param_cnt = 0;
	for (idx = 0 ; idx < MUSE_MAX_PARAM_NUM; idx++) {
		char gst_param_value[MUSE_MAX_PARAM_STRLEN];
		memset(gst_param_value, 0, MUSE_MAX_PARAM_STRLEN);
		snprintf(gst_param_value, strlen(MUSEGST) + 2, "%s%d", MUSEGST, idx + 1);

		str = iniparser_getstring(g_muse_core_conf->muse_dict, gst_param_value, NULL);
		g_strstrip(str);
		if (str == NULL || strlen(str) == 0) {
			LOGD("updated gst_param #: %d", g_muse_core_conf->gst_param_cnt);
			break;
		}

		g_muse_core_conf->gst_param_str[idx] = strdup(str);
		if (!g_muse_core_conf->gst_param_str[idx]) {
			LOGE("Error - gst param allocation");
			_muse_core_config_free();
		}
		LOGD("gstparam%d: %s", (g_muse_core_conf->gst_param_cnt)++, g_muse_core_conf->gst_param_str[idx]);
	}

	g_muse_core_conf->type = 0;
	host = strtok_r(g_muse_core_conf->hosts, COMMA, &ptr);

	while (host != NULL) {
		g_muse_core_conf->host[g_muse_core_conf->type] = strdup(host);
		LOGD("host: %s", g_muse_core_conf->host[g_muse_core_conf->type]);
		char *host_name = (char *) malloc(HOST_MAX_COUNT);
		if (!host_name) {
			LOGE("Error - null host_name");
			_muse_core_config_free();
			MUSE_FREE(host_name);
			return ret;
		}

		/* path */
		strncpy(host_name, host, strlen(host) + 1);
		strncat(host_name, COLON, strlen(COLON));
		strncat(host_name, PATH, strlen(PATH));
		g_strstrip(host_name); /*Removes leading and trailing whitespace from a string*/

		g_muse_core_conf->host_infos[g_muse_core_conf->type] = (host_info_t *) malloc(sizeof(host_info_t));
		if (!g_muse_core_conf->host_infos[g_muse_core_conf->type]) {
			LOGE("Error - null type");
			_muse_core_config_free();
			MUSE_FREE(host_name);
			return ret;
		}

		g_muse_core_conf->host_infos[g_muse_core_conf->type]->path = strdup(iniparser_getstring(g_muse_core_conf->muse_dict, host_name, NULL));
		if (!g_muse_core_conf->host_infos[g_muse_core_conf->type]->path) {
			LOGE("Error - null path");
			_muse_core_config_free();
			MUSE_FREE(host_name);
			return ret;
		}

		LOGD("[%d] %s", g_muse_core_conf->type, g_muse_core_conf->host_infos[g_muse_core_conf->type]->path);

		/* path */
		strncpy(host_name, host, strlen(host) + 1);
		strncat(host_name, COLON, strlen(COLON));
		strncat(host_name, PRELOADED, strlen(PRELOADED));
		g_strstrip(host_name); /*Removes leading and trailing whitespace from a string*/

		g_muse_core_conf->host_infos[g_muse_core_conf->type]->preloaded= strdup(iniparser_getstring(g_muse_core_conf->muse_dict, host_name, NULL));
		if (!g_muse_core_conf->host_infos[g_muse_core_conf->type]->preloaded) {
			LOGE("Error - null preloaded");
			_muse_core_config_free();
			MUSE_FREE(host_name);
			return ret;
		}

		host = strtok_r(NULL, COMMA, &ptr);
		g_muse_core_conf->type++;
		MUSE_FREE(host_name);
	}

	return MM_ERROR_NONE;
}

static void _muse_core_config_free(void)
{
	char *host;
	int i = 0;
	char *ptr = NULL;

	g_return_if_fail(g_muse_core_conf != NULL);

	if (g_muse_core_conf->muse_dict)
		iniparser_freedict(g_muse_core_conf->muse_dict);

	host = strtok_r(g_muse_core_conf->hosts, COMMA, &ptr);
	g_muse_core_conf->type = 0;

	while (host != NULL) {
		LOGD("host: %s", host);
		MUSE_FREE(g_muse_core_conf->host_infos[g_muse_core_conf->type]->path);
		MUSE_FREE(g_muse_core_conf->host_infos[g_muse_core_conf->type]->preloaded);
		MUSE_FREE(g_muse_core_conf->host_infos[g_muse_core_conf->type]);
		host = strtok_r(NULL, COMMA, &ptr);
		g_muse_core_conf->type++;
	}
	MUSE_FREE(g_muse_core_conf->hosts);
	for (i = 0; i <= g_muse_core_conf->type; i++)
		MUSE_FREE(g_muse_core_conf->host[i]);

	MUSE_FREE(g_muse_core_conf->logfile);
	for (i = 0; i <= g_muse_core_conf->gst_param_cnt; i++)
		MUSE_FREE(g_muse_core_conf->gst_param_str[i]);

	MUSE_FREE(g_muse_core_conf);
}

static void _muse_core_config_init_instance(void (*free)(void), char* (*get_path)(int), char* (*get_preloaded)(int), int (*get_gst_param_cnt)(void),
	char* (*get_gst_param_str)(int), char* (*get_host)(int), int (*get_host_cnt)(void))
{
	g_return_if_fail(free != NULL);
	g_return_if_fail(get_path != NULL);
	g_return_if_fail(g_muse_core_conf == NULL);

	g_muse_core_conf = calloc(1, sizeof(*g_muse_core_conf));
	g_return_if_fail(g_muse_core_conf != NULL);
	g_muse_core_conf->hosts = NULL;
	g_muse_core_conf->type = 0;
	g_muse_core_conf->logfile = NULL;
	g_muse_core_conf->muse_dict = NULL;
	g_muse_core_conf->free = free;
	g_muse_core_conf->get_path = get_path;
	g_muse_core_conf->get_preloaded = get_preloaded;
	g_muse_core_conf->get_gst_param_cnt = get_gst_param_cnt;
	g_muse_core_conf->get_gst_param_str = get_gst_param_str;
	g_muse_core_conf->get_host = get_host;
	g_muse_core_conf->get_host_cnt = get_host_cnt;
	LOGD("conf: %0x2x", g_muse_core_conf);

	if (_muse_core_config_parser() != MM_ERROR_NONE)
		LOGE("parser() error");
}

static char *_muse_core_config_get_host(int index)
{
	g_return_val_if_fail(g_muse_core_conf->host != NULL, NULL);
	return g_muse_core_conf->host[index];
}

static int _muse_core_config_get_host_cnt(void)
{
	g_return_val_if_fail(g_muse_core_conf != NULL, 0);
	return g_muse_core_conf->type;
}

static int _muse_core_config_get_gst_param_cnt(void)
{
	g_return_val_if_fail(g_muse_core_conf != NULL, 0);
	return g_muse_core_conf->gst_param_cnt;
}

static char *_muse_core_config_get_gst_param_str(int idx)
{
	g_return_val_if_fail(g_muse_core_conf->gst_param_str[idx] != NULL, NULL);
	return g_muse_core_conf->gst_param_str[idx];
}

static char *_muse_core_config_get_path(int api_client)
{
	g_return_val_if_fail(g_muse_core_conf->host_infos[api_client]->path != NULL, NULL);

	LOGD("%s", g_muse_core_conf->host_infos[api_client]->path);
	return g_muse_core_conf->host_infos[api_client]->path;
}

static char *_muse_core_config_get_preloaded(int api_client)
{
	g_return_val_if_fail(g_muse_core_conf->host_infos[api_client]->preloaded!= NULL, NULL);

	return g_muse_core_conf->host_infos[api_client]->preloaded;
}

muse_core_config_t *muse_core_config_get_instance(void)
{
	if (g_muse_core_conf == NULL)
		_muse_core_config_init_instance(_muse_core_config_free, _muse_core_config_get_path, _muse_core_config_get_preloaded,
					_muse_core_config_get_gst_param_cnt, _muse_core_config_get_gst_param_str,
					_muse_core_config_get_host, _muse_core_config_get_host_cnt);

	return g_muse_core_conf;
}

void muse_core_config_init(void)
{
	LOGD("Enter");
	if (g_muse_core_conf == NULL)
		_muse_core_config_init_instance(_muse_core_config_free, _muse_core_config_get_path, _muse_core_config_get_preloaded,
					_muse_core_config_get_gst_param_cnt, _muse_core_config_get_gst_param_str,
					_muse_core_config_get_host, _muse_core_config_get_host_cnt);
	LOGD("Leave");
}
