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

#include "muse_core_vconf.h"
#include <vconf.h>

bool muse_core_vconf_get_int(const char *key, int *value)
{
	int err;

	g_return_val_if_fail(key != NULL, false);
	g_return_val_if_fail(value != NULL, false);

	err = vconf_get_int(key, value);
	if (err == 0)
		return true;
	else if (err == -1)
		return false;
	else
		LOGE("Unexpected error code: %d", err);

	return false;
}

bool muse_core_vconf_set_int(const char *key, int value)
{
	int err;

	g_return_val_if_fail(key != NULL, false);

	err = vconf_set_int(key, value);
	if (err == 0)
		return true;
	else if (err == -1)
		return false;
	else
		LOGE("Unexpected error code: %d", err);

	return false;
}

bool muse_core_vconf_get_bool(const char *key, int *value)
{
	int err;

	g_return_val_if_fail(key != NULL, false);
	g_return_val_if_fail(value != NULL, false);

	err = vconf_get_bool(key, value);
	if (err == 0)
		return true;
	else if (err == -1)
		return false;
	else
		LOGE("Unexpected error code: %d", err);

	return false;
}

bool muse_core_vconf_notify_key_changed(const char *key, void *vconf_cb, void *usr_data)
{
	int err;

	g_return_val_if_fail(key != NULL, false);
	g_return_val_if_fail(vconf_cb != NULL, false);

	err = vconf_notify_key_changed(key, (vconf_callback_fn) vconf_cb, usr_data);
	if (err == 0)
		return true;
	else if (err == -1)
		return false;
	else
		LOGE("Unexpected error code: %d", err);

	return false;
}

bool muse_core_vconf_ignore_key_changed(const char *key, void *vconf_cb)
{
	int err;

	g_return_val_if_fail(key != NULL, false);
	g_return_val_if_fail(vconf_cb != NULL, false);

	err = vconf_ignore_key_changed(key, (vconf_callback_fn) vconf_cb);
	if (err == 0)
		return true;
	else if (err == -1)
		return false;
	else
		LOGE("Unexpected error code: %d", err);

	return false;
}