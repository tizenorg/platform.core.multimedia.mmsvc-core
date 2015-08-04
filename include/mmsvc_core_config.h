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

#ifndef __MMSVC_CORE_CONFIG_H__
#define __MMSVC_CORE_CONFIG_H__

#ifdef _cplusplus
extern "C" {
#endif

#include <iniparser.h>

#define CONFFILE "/usr/share/mused/mused.conf"
#define HOST_MAX_COUNT 1024
#define MUSED_MAX_PARAM_STRLEN 256
#define MUSEDHOST "mused:hosts"
#define MUSEDLOG "mused:logfile"
#define MUSEDGST "mused:gstparam"
#define COLON ":"
#define COMMA ","
#define PATH "path"

typedef struct host_info
{
	char *path;
} host_info_t;

typedef struct config
{
	char *hosts;
	int type;
	char *logfile;
	char *gst_param_str[MUSED_MAX_PARAM_STRLEN];
	int gst_param_cnt;
	host_info_t *host_infos[HOST_MAX_COUNT];
	dictionary *mmsvc_dict;
	void (*free)(void);
	char* (*get_path)(int);
	int (*get_gst_param_cnt)(void);
	char* (*get_gst_param_str)(int);
} config_t;

/*mmsvc_core_config_init must be called before mmsvc_core_config_get_instance*/
config_t *mmsvc_core_config_get_instance(void);
void mmsvc_core_config_init(void);

#ifdef __cplusplus
}
#endif
#endif /* __MMSVC_CORE_CONFIG_H__ */
