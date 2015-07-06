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
#ifndef __MMSVC_CORE_LOG_H__
#define __MMSVC_CORE_LOG_H__

#ifdef _cplusplus
extern "C" {
#endif

#include <time.h>
#include <gmodule.h>
#include "mmsvc_core_msg_json.h"

typedef struct mmsvc_core_log {
	int type;
	unsigned refs;
	char *buf;
	size_t len;
	int log_fd;
	int count;
	GTimer *timer;
	void (*log)(char *);
	void (*fatal)(char *);
	void (*set_module_value) (int, GModule *, gboolean);
	gboolean (*get_module_opened) (int);
	GModule* (*get_module_value) (int);
	gboolean module_opened[MMSVC_CLIENT_MAX];
	GModule *module[MMSVC_CLIENT_MAX];
} mmsvc_core_log_t;

/*mmsvc_core_log_init must be called before mmsvc_core_log_get_instance*/
mmsvc_core_log_t *mmsvc_core_log_get_instance(void);
void mmsvc_core_log_init(void);

#ifdef _cplusplus
}
#endif

#endif	/*__MMSVC_CORE_LOG_H__*/