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
#ifndef __MUSE_CORE_LOG_H__
#define __MUSE_CORE_LOG_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/time.h>
#include "muse_core_msg_json.h"
#define WRITE_DEFAULT_BLOCK_SIZE 4096

typedef struct muse_core_log {
	int type;
	unsigned refs;
	char *buf;
	size_t size;
	char cache[WRITE_DEFAULT_BLOCK_SIZE];
	int log_fd;
	int count;
	GTimer *timer;
	void (*log)(char *);
	void (*fatal)(char *);
	void (*set_msg) (char *);
	char* (*get_msg) (void);
	void (*flush_msg) (void);
} muse_core_log_t;

/*muse_core_log_init must be called before muse_core_log_get_instance*/
muse_core_log_t *muse_core_log_get_instance(void);
void muse_core_log_init(void);

#ifdef __cplusplus
}
#endif

#endif	/*__MUSE_CORE_LOG_H__*/
