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

static muse_core_module_t *g_muse_core_module = NULL;

static GModule * _muse_core_module_load(int api_module);
static void _muse_core_module_dispatch(int cmd, muse_module_h module);
static gboolean _muse_core_module_close(muse_module_h module);
static GModule *_muse_core_module_get_dllsymbol(int api_module);
static void _muse_core_module_set_dllsymbol_loaded_value(int api_module, GModule *module, gboolean value);
static gboolean _muse_core_module_get_dllsymbol_loaded_value(int api_module);
static void _muse_core_module_set_dllsymbol_state_value(muse_module_h, muse_module_state_e);
static int _muse_core_module_get_dllsymbol_state_value(muse_module_h);
static void _muse_core_module_set_dllsymbol_flash_state_value(muse_module_h module, muse_module_cam_flash_state_e flash_state);
static int _muse_core_module_get_dllsymbol_flash_state_value(muse_module_h module);
static void _muse_core_module_set_dllsymbol_shutter_sound_policy_value(muse_module_h module,
	muse_module_cam_shutter_sound_policy_e shutter_sound_policy);
static int _muse_core_module_get_dllsymbol_shutter_sound_policy_value(muse_module_h module);
static void _muse_core_module_init_instance(GModule* (*load) (int), void (*dispatch) (int, muse_module_h), gboolean (*close) (muse_module_h),
	GModule * (*get_dllsymbol_value) (int), void (*set_dllsymbol_loaded_value) (int, GModule *, gboolean), gboolean(*get_dllsymbol_loaded_value) (int),
	void (*set_module_state) (muse_module_h, muse_module_state_e), int (*get_module_state) (muse_module_h),
	void (*set_flash_state) (muse_module_h, muse_module_cam_flash_state_e), int (*get_flash_state) (muse_module_h),
	void (*set_shutter_sound_policy) (muse_module_h, muse_module_cam_shutter_sound_policy_e),int (*get_shutter_sound_policy) (muse_module_h));


static GModule *_muse_core_module_load(int api_module)
{
	GModule *module = NULL;

	if (_muse_core_module_get_dllsymbol_loaded_value(api_module) == false) {
		module = g_module_open(muse_core_config_get_instance()->get_path(api_module), G_MODULE_BIND_LAZY);

		if (!module) {
			LOGE("%s", g_module_error());
			return NULL;
		} else {
			_muse_core_module_set_dllsymbol_loaded_value(api_module, module, true);
		}
	} else if (_muse_core_module_get_dllsymbol_loaded_value(api_module) == true) {
		module = _muse_core_module_get_dllsymbol(api_module);
		LOGW("already module is opened: %p", module);
	}

	return module;
}

static void _muse_core_module_dispatch(int cmd, muse_module_h module)
{
	muse_module_dispatchfunc *dispatcher = NULL;

	g_return_if_fail(module->ch[MUSE_CHANNEL_MSG].dll_handle != NULL);

	LOGD("cmd: %d\t module's dll_handle: %p", cmd, module->ch[MUSE_CHANNEL_MSG].dll_handle);
	g_module_symbol(module->ch[MUSE_CHANNEL_MSG].dll_handle, DISPATCHER, (gpointer *)&dispatcher);

	if (dispatcher && dispatcher[cmd]) {
		LOGD("dispatcher: %p", dispatcher);
		dispatcher[cmd](module);
	} else {
		LOGE("error - dispatcher");
		return;
	}
}

static gboolean _muse_core_module_close(muse_module_h module)
{
	g_return_val_if_fail(module != NULL, FALSE);

	_muse_core_module_set_dllsymbol_loaded_value(module->api_module, module->ch[MUSE_CHANNEL_MSG].dll_handle, false);

	LOGD("Closing module %s", g_module_name(module->ch[MUSE_CHANNEL_MSG].dll_handle));
	if (!g_module_close(module->ch[MUSE_CHANNEL_MSG].dll_handle)) {
		LOGE("Couldn't close dll_handle %s: %s", g_module_name(module->ch[MUSE_CHANNEL_MSG].dll_handle), g_module_error());
		return FALSE;
	}

	return TRUE;
}
static GModule *_muse_core_module_get_dllsymbol(int api_module)
{
	g_return_val_if_fail(g_muse_core_module != NULL, NULL);

	return g_muse_core_module->module[api_module];
}

static void _muse_core_module_set_dllsymbol_loaded_value(int api_module, GModule *module, gboolean value)
{
	g_return_if_fail(g_muse_core_module!= NULL);
	g_return_if_fail(module != NULL);

	g_muse_core_module->module_loaded[api_module] = value;
	g_muse_core_module->module[api_module] = module;
	LOGD("module: %p", g_muse_core_module->module[api_module]);
}
static gboolean _muse_core_module_get_dllsymbol_loaded_value(int api_module)
{
	g_return_val_if_fail(g_muse_core_module != NULL, false);

	return g_muse_core_module->module_loaded[api_module];
}

static void _muse_core_module_set_dllsymbol_state_value(muse_module_h module, muse_module_state_e module_state)
{
	g_return_if_fail(g_muse_core_module!= NULL);
	g_return_if_fail(module != NULL);

	module->module_state[module->api_module] = module_state;
}

static int _muse_core_module_get_dllsymbol_state_value(muse_module_h module)
{
	g_return_val_if_fail(g_muse_core_module!= NULL, MM_ERROR_INVALID_ARGUMENT);
	g_return_val_if_fail(module != NULL, MM_ERROR_INVALID_ARGUMENT);
	return module->module_state[module->api_module];
}

static void _muse_core_module_set_dllsymbol_flash_state_value(muse_module_h module, muse_module_cam_flash_state_e flash_state)
{
	g_return_if_fail(g_muse_core_module!= NULL);
	g_return_if_fail(module != NULL);

	module->flash_state = flash_state;
}

static int _muse_core_module_get_dllsymbol_flash_state_value(muse_module_h module)
{
	g_return_val_if_fail(g_muse_core_module!= NULL, MM_ERROR_INVALID_ARGUMENT);
	g_return_val_if_fail(module != NULL, MM_ERROR_INVALID_ARGUMENT);
	return module->flash_state;
}

static void _muse_core_module_set_dllsymbol_shutter_sound_policy_value(muse_module_h module,
	muse_module_cam_shutter_sound_policy_e shutter_sound_policy)
{
	g_return_if_fail(g_muse_core_module!= NULL);
	g_return_if_fail(module != NULL);

	module->shutter_sound_policy = shutter_sound_policy;
}

static int _muse_core_module_get_dllsymbol_shutter_sound_policy_value(muse_module_h module)
{
	g_return_val_if_fail(g_muse_core_module!= NULL, MM_ERROR_INVALID_ARGUMENT);
	g_return_val_if_fail(module != NULL, MM_ERROR_INVALID_ARGUMENT);
	return module->shutter_sound_policy;
}

static void _muse_core_module_init_instance(GModule* (*load) (int), void (*dispatch) (int, muse_module_h), gboolean (*close) (muse_module_h),
	GModule * (*get_dllsymbol_value) (int), void (*set_dllsymbol_loaded_value) (int, GModule *, gboolean), gboolean(*get_dllsymbol_loaded_value) (int),
	void (*set_module_state) (muse_module_h, muse_module_state_e), int (*get_module_state) (muse_module_h),
	void (*set_flash_state) (muse_module_h, muse_module_cam_flash_state_e), int (*get_flash_state) (muse_module_h),
	void (*set_shutter_sound_policy) (muse_module_h, muse_module_cam_shutter_sound_policy_e),int (*get_shutter_sound_policy) (muse_module_h))
{
	g_return_if_fail(g_muse_core_module == NULL);

	int idx = 0;
	g_muse_core_module = calloc(1, sizeof(*g_muse_core_module));
	g_return_if_fail(g_muse_core_module != NULL);

	g_muse_core_module->load = load;
	g_muse_core_module->dispatch= dispatch;
	g_muse_core_module->close= close;
	g_muse_core_module->set_dllsymbol_loaded_value = set_dllsymbol_loaded_value;
	g_muse_core_module->get_dllsymbol_loaded_value = get_dllsymbol_loaded_value;
	g_muse_core_module->get_dllsymbol_value = get_dllsymbol_value;
	g_muse_core_module->set_module_state = set_module_state;
	g_muse_core_module->get_module_state = get_module_state;
	g_muse_core_module->set_flash_state = set_flash_state;
	g_muse_core_module->get_flash_state = get_flash_state;
	g_muse_core_module->set_shutter_sound_policy = set_shutter_sound_policy;
	g_muse_core_module->get_shutter_sound_policy = get_shutter_sound_policy;

	for (idx = 0; idx < MUSE_MODULE_MAX; idx++)
		g_muse_core_module->module_loaded[idx] = false;
}

muse_core_module_t *muse_core_module_get_instance(void)
{
	if (g_muse_core_module == NULL)
		_muse_core_module_init_instance(_muse_core_module_load, _muse_core_module_dispatch, _muse_core_module_close,
		_muse_core_module_get_dllsymbol, _muse_core_module_set_dllsymbol_loaded_value, _muse_core_module_get_dllsymbol_loaded_value,
		_muse_core_module_set_dllsymbol_state_value, _muse_core_module_get_dllsymbol_state_value,
		_muse_core_module_set_dllsymbol_flash_state_value, _muse_core_module_get_dllsymbol_flash_state_value,
		_muse_core_module_set_dllsymbol_shutter_sound_policy_value, _muse_core_module_get_dllsymbol_shutter_sound_policy_value);

	return g_muse_core_module;
}

void muse_core_module_init(void)
{
	LOGD("Enter");

	if (g_muse_core_module == NULL)
		_muse_core_module_init_instance(_muse_core_module_load, _muse_core_module_dispatch, _muse_core_module_close,
		_muse_core_module_get_dllsymbol, _muse_core_module_set_dllsymbol_loaded_value, _muse_core_module_get_dllsymbol_loaded_value,
		_muse_core_module_set_dllsymbol_state_value, _muse_core_module_get_dllsymbol_state_value,
		_muse_core_module_set_dllsymbol_flash_state_value, _muse_core_module_get_dllsymbol_flash_state_value,
		_muse_core_module_set_dllsymbol_shutter_sound_policy_value, _muse_core_module_get_dllsymbol_shutter_sound_policy_value);

	LOGD("Leave");
}
