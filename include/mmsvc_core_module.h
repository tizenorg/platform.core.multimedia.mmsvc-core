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
#ifndef __MMSVC_CORE_MODULE_H__
#define __MMSVC_CORE_MODULE_H__

#ifdef _cplusplus
extern "C" {
#endif

#include "mmsvc_core.h"
#include "mmsvc_core_internal.h"

typedef gboolean (*MMSVC_MODULE_DispatchFunc) (Client client);
typedef gboolean (*MMSVC_MODULE_CMD_DispatchFunc) (Client client);

GModule * mmsvc_core_module_load(int api_client);
void mmsvc_core_module_dll_symbol_dispatch(int cmd, Client client);
gboolean mmsvc_core_module_close(Client client);

#ifdef _cplusplus
}
#endif

#endif	/*__MMSVC_CORE_MODULE_H__*/
