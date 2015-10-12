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

#ifndef __MUSE_CORE_SECURITY_H__
#define __MUSE_CORE_SECURITY_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "muse_core_internal.h"
#include <cynara-client.h>
#include <cynara-session.h>
#include <cynara-creds-socket.h>

#define CYNARA_CACHE_SIZE 1000U

typedef struct muse_core_security {
	cynara *p_cynara;
	int (*new)(void);
	void (*free)(void);
} muse_core_security_t;

muse_core_security_t *muse_core_security_get_instance(void);
void muse_core_security_init(void);
int muse_core_security_check_cynara(int fd, const char *privilege);

#ifdef __cplusplus
}
#endif
#endif	/*__MUSE_CORE_SECURITY_H__*/
