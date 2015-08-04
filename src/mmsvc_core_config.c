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

#include "mmsvc_core_config.h"
#include "mmsvc_core_internal.h"

static config_t *g_conf = NULL;

static int _mmsvc_core_config_parser(void);
static void _mmsvc_core_config_free(void);
static char *_mmsvc_core_config_get_path(int api_client);
static int _mmsvc_core_config_get_gst_param_cnt(void);
static char *_mmsvc_core_config_get_gst_param_str(int idx);
static void _mmsvc_core_config_init_instance(void (*free)(void), char* (*get_path)(int), int (*get_gst_param_cnt)(void), char* (*get_gst_param_str)(int));

static int _mmsvc_core_config_parser(void)
{
	char *host;
	char *str;
	int idx;
	int ret = -1;

	LOGD("Enter");
	g_return_val_if_fail(g_conf != NULL, ret);

	g_conf->mmsvc_dict = iniparser_load(CONFFILE);
	g_return_val_if_fail(g_conf->mmsvc_dict != NULL, ret);

	str = iniparser_getstring(g_conf->mmsvc_dict, MUSEDHOST, NULL);
	g_return_val_if_fail(str != NULL, ret);

	g_conf->hosts = (char *) malloc(1 + strlen(str));
	if (!g_conf->hosts) {
		LOGE("Error - hosts allocation");
		iniparser_freedict(g_conf->mmsvc_dict);
		MMSVC_FREE(g_conf);
	}
	strcpy(g_conf->hosts, str);

	str = iniparser_getstring(g_conf->mmsvc_dict, MUSEDLOG, NULL);
	g_return_val_if_fail(str != NULL, ret);

	g_conf->logfile = (char *) malloc(1 + strlen(str));
	if (!g_conf->logfile) {
		LOGE("Error - logfile allocation");
		iniparser_freedict(g_conf->mmsvc_dict);
		MMSVC_FREE(g_conf->hosts);
		MMSVC_FREE(g_conf);
	}
	strcpy(g_conf->logfile, str);

	g_conf->gst_param_cnt = 0;
	for (idx = 0 ; idx < 10; idx++) {
		char gst_param_value[MUSED_MAX_PARAM_STRLEN];
		memset(gst_param_value, 0, MUSED_MAX_PARAM_STRLEN);
		sprintf(gst_param_value, "%s%d", MUSEDGST, idx+1);

		str = iniparser_getstring(g_conf->mmsvc_dict, gst_param_value, NULL);
		g_strstrip(str);
		if (str == NULL || strlen(str) == 0) {
			LOGD("updated gst_param #: %d", g_conf->gst_param_cnt);
			break;
		}

		g_conf->gst_param_str[idx] = (char *) malloc(1 + strlen(str));
		if (!g_conf->gst_param_str[idx]) {
			LOGE("Error - gst param allocation");
			iniparser_freedict(g_conf->mmsvc_dict);
			MMSVC_FREE(g_conf->hosts);
			MMSVC_FREE(g_conf);
		}

		strcpy(g_conf->gst_param_str[idx], str);
		LOGD("gst_param%d: %s", (g_conf->gst_param_cnt)++, g_conf->gst_param_str[idx]);
	}

	g_conf->type = 0;
	host = strtok(g_conf->hosts, COMMA);

	while (host != NULL) {
		char *host_name = (char *) malloc(HOST_MAX_COUNT);
		if (!host_name) {
			LOGE("Error - null host_name");
			iniparser_freedict(g_conf->mmsvc_dict);
			MMSVC_FREE(g_conf->hosts);
			MMSVC_FREE(g_conf);
			return ret;
		}

		LOGD("host: %s", host);
		/* path */
		strcpy(host_name, host);
		strcat(host_name, COLON);
		strcat(host_name, PATH);
		g_strstrip(host_name); /*Removes leading and trailing whitespace from a string*/

		g_conf->host_infos[g_conf->type] = (host_info_t *) malloc(sizeof(host_info_t));
		if (!g_conf->host_infos[g_conf->type]) {
			LOGE("Error - null type");
			iniparser_freedict(g_conf->mmsvc_dict);
			MMSVC_FREE(g_conf->hosts);
			MMSVC_FREE(host_name);
			MMSVC_FREE(g_conf->host_infos[g_conf->type]);
			MMSVC_FREE(g_conf);
			return ret;
		}

		g_conf->host_infos[g_conf->type]->path = (char *) malloc(1 + strlen(iniparser_getstring(g_conf->mmsvc_dict, host_name, NULL)));
		if(!g_conf->host_infos[g_conf->type]->path) {
			LOGE("Error - null path");
			iniparser_freedict(g_conf->mmsvc_dict);
			MMSVC_FREE(g_conf->hosts);
			MMSVC_FREE(host_name);
			MMSVC_FREE(g_conf->host_infos[g_conf->type]);
			MMSVC_FREE(g_conf);
			return ret;
		}

		strcpy(g_conf->host_infos[g_conf->type]->path, iniparser_getstring(g_conf->mmsvc_dict, host_name, NULL));
		LOGD("[%d] %s", g_conf->type, g_conf->host_infos[g_conf->type]->path);

		host = strtok(NULL, COMMA);
		g_conf->type++;
		MMSVC_FREE(host_name);
	}

	iniparser_freedict(g_conf->mmsvc_dict);
	return 0;
}

static void _mmsvc_core_config_free(void)
{
	char *host;
	int i = 0;

	g_return_if_fail(g_conf != NULL);

	host = strtok(g_conf->hosts, COMMA);
	g_conf->type = 0;

	while (host != NULL) {
		LOGD("host: %s", host);
		MMSVC_FREE(g_conf->host_infos[g_conf->type]->path);
		MMSVC_FREE(g_conf->host_infos[g_conf->type]);
		host = strtok(NULL, COMMA);
		g_conf->type++;
	}
	MMSVC_FREE(g_conf->hosts);
	MMSVC_FREE(g_conf->logfile);
	for (i = 0; i <= g_conf->gst_param_cnt; i++) {
		MMSVC_FREE(g_conf->gst_param_str[i]);
	}

	MMSVC_FREE(g_conf);
}

static void _mmsvc_core_config_init_instance(void (*free)(void), char* (*get_path)(int), int (*get_gst_param_cnt)(void), char* (*get_gst_param_str)(int))
{
	g_return_if_fail(free != NULL);
	g_return_if_fail(get_path != NULL);
	g_return_if_fail(g_conf == NULL);

	g_conf = calloc(1, sizeof(*g_conf));
	g_conf->hosts = NULL;
	g_conf->type = 0;
	g_conf->logfile = NULL;
	g_conf->mmsvc_dict = NULL;
	g_conf->free = free;
	g_conf->get_path = get_path;
	g_conf->get_gst_param_cnt= get_gst_param_cnt;
	g_conf->get_gst_param_str = get_gst_param_str;
	LOGD("conf: %0x2x", g_conf);

	if (_mmsvc_core_config_parser() != 0)
		LOGE("parser() error");
}

static int _mmsvc_core_config_get_gst_param_cnt(void)
{
	return g_conf->gst_param_cnt;
}

static char *_mmsvc_core_config_get_gst_param_str(int idx)
{
	g_return_val_if_fail(g_conf->gst_param_str[idx] != NULL, NULL);
	return g_conf->gst_param_str[idx];
}

static char *_mmsvc_core_config_get_path(int api_client)
{
	g_return_val_if_fail(g_conf->host_infos[api_client]->path != NULL, NULL);

	LOGD("%s", g_conf->host_infos[api_client]->path);
	return g_conf->host_infos[api_client]->path;
}

config_t *mmsvc_core_config_get_instance(void)
{
	if (g_conf == NULL)
		_mmsvc_core_config_init_instance(_mmsvc_core_config_free, _mmsvc_core_config_get_path, _mmsvc_core_config_get_gst_param_cnt, _mmsvc_core_config_get_gst_param_str);

	return g_conf;
}

void mmsvc_core_config_init(void)
{
	LOGD("Enter");
	if (g_conf == NULL)
		_mmsvc_core_config_init_instance(_mmsvc_core_config_free, _mmsvc_core_config_get_path, _mmsvc_core_config_get_gst_param_cnt, _mmsvc_core_config_get_gst_param_str);
	LOGD("Leave");
}
