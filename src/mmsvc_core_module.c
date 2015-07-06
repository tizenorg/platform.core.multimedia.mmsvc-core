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

#include "mmsvc_core_config.h"
#include "mmsvc_core_log.h"
#include "mmsvc_core_internal.h"
#include "mmsvc_core_module.h"
#include "mmsvc_core_private.h"

GModule *mmsvc_core_module_load(int api_client)
{
	GModule *module = NULL;

	if (mmsvc_core_log_get_instance()->get_module_opened(api_client) == false) {
		LOGD("api client : %d", api_client);
		module = g_module_open(mmsvc_core_config_get_instance()->get_path(api_client), G_MODULE_BIND_LAZY);

		if (!module) {
			LOGE("%s", g_module_error());
			return NULL;
		} else {
			mmsvc_core_log_get_instance()->set_module_value(api_client, module, true);
		}
	} else if (mmsvc_core_log_get_instance()->get_module_opened(api_client) == true) {
		module = mmsvc_core_log_get_instance()->get_module_value(api_client);
		LOGW("already module is opened: %p", module);
	}

	return module;
}

void mmsvc_core_module_dll_symbol(int cmd, Client client)
{
	MMSVC_MODULE_DispatchFunc *dispatcher = NULL;

	g_return_if_fail(client->ch[MUSED_CHANNEL_MSG].module != NULL);

	LOGD("cmd: %d\t client->module: %p", cmd, client->ch[MUSED_CHANNEL_MSG].module);
	g_module_symbol(client->ch[MUSED_CHANNEL_MSG].module, DISPATCHER, (gpointer *)&dispatcher);

	if (dispatcher && dispatcher[cmd]) {
		LOGD("dispatcher: %p", dispatcher);
		dispatcher[cmd](client);
	} else {
		LOGE("error - dispatcher");
		return;
	}
}

gboolean mmsvc_core_module_close(Client client)
{
	g_return_val_if_fail(client != NULL, FALSE);

	mmsvc_core_log_get_instance()->set_module_value(client->api_client, client->ch[MUSED_CHANNEL_MSG].module, false);

	LOGD("Closing module %s", g_module_name(client->ch[MUSED_CHANNEL_MSG].module));
	if (!g_module_close(client->ch[MUSED_CHANNEL_MSG].module)) {
		LOGE("Couldn't close module %s: %s", g_module_name(client->ch[MUSED_CHANNEL_MSG].module), g_module_error());
		return FALSE;
	}

	return TRUE;
}