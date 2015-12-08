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

typedef gboolean (*MUSE_MODULE_DispatchFunc) (muse_module_h module);
typedef gboolean (*MUSE_MODULE_CMD_DispatchFunc) (muse_module_h module);

GModule * muse_core_module_load(int disp_api);
void muse_core_module_dll_symbol_dispatch(int cmd, muse_module_h module);
gboolean muse_core_module_close(muse_module_h module);

#ifdef __cplusplus
}
#endif

#endif	/*__MUSE_CORE_MODULE_H__*/