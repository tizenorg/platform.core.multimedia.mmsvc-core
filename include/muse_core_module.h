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
#ifndef __MUSE_CORE_MODULE_H__
#define __MUSE_CORE_MODULE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "muse_core.h"
#include "muse_core_internal.h"

typedef gboolean (*muse_module_dispatchfunc) (muse_module_h module);
typedef gboolean (*muse_module_cmd_dispatchfunc) (muse_module_h module);

typedef enum {
	MUSE_PLAYER,
	MUSE_CAMERA,
	MUSE_RECORDER,
	MUSE_MODULE_MAX
} muse_core_api_module_e;

typedef struct muse_core_module {
	GModule* (*load) (int);
	void (*dispatch) (int, muse_module_h);
	gboolean (*close) (muse_module_h);
	void (*set_dllsymbol_loaded_value) (int, GModule *, gboolean);
	gboolean (*get_dllsymbol_loaded_value) (int);
	GModule* (*get_dllsymbol_value) (int);
	void (*set_module_state) (int, int);
	int (*get_module_state) (int);
	void (*set_flash_state) (int);
	int (*get_flash_state) (void);
	gboolean module_loaded[MUSE_MODULE_MAX];
	GModule *module[MUSE_MODULE_MAX];
	int module_state[MUSE_MODULE_MAX];
	int flash_state;
} muse_core_module_t;

muse_core_module_t *muse_core_module_get_instance(void);
void muse_core_module_init(void);
#ifdef __cplusplus
}
#endif

#endif	/*__MUSE_CORE_MODULE_H__*/
