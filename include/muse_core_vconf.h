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

#ifndef __MUSE_CORE_VCONF_H__
#define __MUSE_CORE_VCONF_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "muse_core_internal.h"

bool muse_core_vconf_get_int(const char *key, int *value);
bool muse_core_vconf_set_int(const char *key, int value);
bool muse_core_vconf_get_bool(const char *key, int *value);
bool muse_core_vconf_notify_key_changed(const char *key, void *vconf_cb, void *usr_data);
bool muse_core_vconf_ignore_key_changed(const char *key, void *vconf_cb);

#ifdef __cplusplus
}
#endif
#endif	/*__MUSE_CORE_VCONF_H__*/
