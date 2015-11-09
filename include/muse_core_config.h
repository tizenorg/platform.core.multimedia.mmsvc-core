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

#ifndef __MUSE_CORE_CONFIG_H__
#define __MUSE_CORE_CONFIG_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <iniparser.h>

#define CONFFILE "/usr/share/mused/mused.conf"
#define HOST_MAX_COUNT 1024
#define MUSE_MAX_PARAM_NUM 10
#define MUSE_MAX_PARAM_STRLEN 256
#define MUSEHOST "muse:hosts"
#define MUSELOG "muse:logfile"
#define MUSEGST "muse:gstparam"
#define COLON ":"
#define COMMA ","
#define PATH "path"
#define PRELOADED "preloaded"

typedef struct host_info
{
	char *path;
	char *preloaded;
} host_info_t;

typedef struct muse_core_config
{
	char *hosts;
	int type;
	char *logfile;
	char *gst_param_str[MUSE_MAX_PARAM_NUM];
	int gst_param_cnt;
	host_info_t *host_infos[HOST_MAX_COUNT];
	dictionary *muse_dict;
	void (*free)(void);
	char* (*get_path)(int);
	char* (*get_preloaded)(int);
	int (*get_gst_param_cnt)(void);
	char* (*get_gst_param_str)(int);
	char* (*get_hosts)(void);
	int (*get_host_cnt)(void);
} muse_core_config_t;

/*muse_core_config_init must be called before muse_core_config_get_instance*/
muse_core_config_t *muse_core_config_get_instance(void);
void muse_core_config_init(void);

#ifdef __cplusplus
}
#endif
#endif /* __MUSE_CORE_CONFIG_H__ */
