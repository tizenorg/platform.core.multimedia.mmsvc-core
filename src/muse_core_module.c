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

#include "muse_core_config.h"
#include "muse_core_log.h"
#include "muse_core_internal.h"
#include "muse_core_module.h"
#include "muse_core_private.h"

GModule *muse_core_module_load(int disp_api)
{
	GModule *module = NULL;

	if (muse_core_log_get_instance()->get_module_opened(disp_api) == false) {
		LOGD("dispatch api: %d", disp_api);
		module = g_module_open(muse_core_config_get_instance()->get_path(disp_api), G_MODULE_BIND_LAZY);

		if (!module) {
			LOGE("%s", g_module_error());
			return NULL;
		} else {
			muse_core_log_get_instance()->set_module_value(disp_api, module, true);
		}
	} else if (muse_core_log_get_instance()->get_module_opened(disp_api) == true) {
		module = muse_core_log_get_instance()->get_module_value(disp_api);
		LOGW("already module is opened: %p", module);
	}

	return module;
}

void muse_core_module_dll_symbol_dispatch(int cmd, muse_module_h module)
{
	MUSE_MODULE_DispatchFunc *dispatcher = NULL;

	g_return_if_fail(module->ch[MUSE_CHANNEL_MSG].dll_handle != NULL);

	LOGD("cmd: %d\t module->dll_handle: %p", cmd, module->ch[MUSE_CHANNEL_MSG].dll_handle);
	g_module_symbol(module->ch[MUSE_CHANNEL_MSG].dll_handle, DISPATCHER, (gpointer *)&dispatcher);

	if (dispatcher && dispatcher[cmd]) {
		LOGD("dispatcher: %p", dispatcher);
		dispatcher[cmd](module);
	} else {
		LOGE("error - dispatcher");
		return;
	}
}

gboolean muse_core_module_close(muse_module_h module)
{
	g_return_val_if_fail(module != NULL, FALSE);

	muse_core_log_get_instance()->set_module_value(module->disp_api, module->ch[MUSE_CHANNEL_MSG].dll_handle, false);

	LOGD("Closing module %s", g_module_name(module->ch[MUSE_CHANNEL_MSG].dll_handle));
	if (!g_module_close(module->ch[MUSE_CHANNEL_MSG].dll_handle)) {
		LOGE("Couldn't close dll_handle %s: %s", g_module_name(module->ch[MUSE_CHANNEL_MSG].dll_handle), g_module_error());
		return FALSE;
	}

	return TRUE;
}
