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
#ifndef __MUSE_CORE_LOG_H__
#define __MUSE_CORE_LOG_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/time.h>
#include "muse_core.h"
#include "muse_core_msg_json.h"

typedef struct muse_core_log {
	int type;
	char *buf;
	size_t size;
	char cache[MUSE_MSG_MAX_LENGTH];
	int log_fd;
	int count;
	void (*log)(char *);
	void (*fatal)(char *);
	void (*set_msg) (char *);
	char* (*get_msg) (void);
	void (*flush_msg) (void);
	void (*free) (void);
} muse_core_log_t;

/*muse_core_log_init must be called before muse_core_log_get_instance*/
muse_core_log_t *muse_core_log_get_instance(void);
void muse_core_log_init(void);

#ifdef __cplusplus
}
#endif

#endif	/*__MUSE_CORE_LOG_H__*/
