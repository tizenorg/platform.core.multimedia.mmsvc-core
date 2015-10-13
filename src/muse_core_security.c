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

#include "muse_core_security.h"
#include <cynara-client.h>
#include <cynara-session.h>
#include <cynara-creds-socket.h>

static muse_core_security_t *g_muse_core_security = NULL;
static void _muse_core_security_cynara_log_error(const char *function, int errorCode);
static int _muse_core_security_cynara_new(void);
static void _muse_core_security_cynara_free(void);
static bool _muse_core_security_cynara_check(int fd, const char *privilege);
static void _muse_core_security_init_instance(int (*new)(void), void (*free)(void));

static void _muse_core_security_cynara_log_error(const char *function, int errorCode)
{
	char buffer[BUFSIZ] = {0};
	cynara_strerror(errorCode, buffer, sizeof(buffer));
	LOGE("[CYNARA] %s function failed with error %d : %s", function, errorCode, buffer);
}

static int _muse_core_security_cynara_new(void)
{
	int ret, error = -1;
	cynara_configuration *p_conf = NULL;

	if (g_muse_core_security->p_cynara) {
		LOGE("[CYNARA] Improper usage of cynara");
		goto end;
	}

	ret = cynara_configuration_create(&p_conf);
	if (ret != CYNARA_API_SUCCESS) {
		_muse_core_security_cynara_log_error("cynara_configuration_create", ret);
		goto end;
	}

	ret = cynara_configuration_set_cache_size(p_conf, CYNARA_CACHE_SIZE);
	if (ret != CYNARA_API_SUCCESS) {
		_muse_core_security_cynara_log_error("cynara_configuration_set_cache_size", ret);
		goto end;
	}

	ret = cynara_initialize((cynara **)&g_muse_core_security->p_cynara, p_conf);
	if (ret != CYNARA_API_SUCCESS) {
		_muse_core_security_cynara_log_error("cynara_initialize", ret);
		goto end;
	}

	error = 0;

end:
	cynara_configuration_destroy(p_conf);
	return error;
}

static void _muse_core_security_cynara_free(void)
{
	if (g_muse_core_security->p_cynara) {
		cynara_finish((cynara *)g_muse_core_security->p_cynara);
		g_muse_core_security->p_cynara = NULL;
	}
}

static bool _muse_core_security_cynara_check(int fd, const char *privilege)
{
	int ret = 0;
	pid_t pid = 0;
	char *user = NULL;
	char *client = NULL;
	char *session = NULL;

	ret = cynara_creds_socket_get_user(fd, USER_METHOD_DEFAULT, &user);
	if (ret != CYNARA_API_SUCCESS) {
		_muse_core_security_cynara_log_error("cynara_creds_socket_get_user", ret);
		goto CLEANUP;
	}

	ret = cynara_creds_socket_get_client(fd, CLIENT_METHOD_DEFAULT, &client);
	if (ret != CYNARA_API_SUCCESS) {
		_muse_core_security_cynara_log_error("cynara_creds_socket_get_client", ret);
		goto CLEANUP;
	}

	ret = cynara_creds_socket_get_pid(fd, &pid);
	if (ret != CYNARA_API_SUCCESS) {
		_muse_core_security_cynara_log_error("cynara_creds_socket_get_pid", ret);
		goto CLEANUP;
	}

	session = cynara_session_from_pid(pid);
	if (!session) {
		LOGE("[CYNARA] cynara_session_from_pid() failed");
		ret = CYNARA_API_UNKNOWN_ERROR;
		goto CLEANUP;
	}

	ret = cynara_check((cynara *)g_muse_core_security->p_cynara, client, session, user, privilege);
	switch (ret) {
	case CYNARA_API_ACCESS_ALLOWED:
		LOGD("[CYNARA] Check (client = %s, session = %s, user = %s, privilege = %s )"
		"=> access allowed", client, session, user, privilege);
		break;
	case CYNARA_API_ACCESS_DENIED:
		LOGD("[CYNARA] Check (client = %s, session = %s, user = %s, privilege = %s )"
		"=> access denied", client, session, user, privilege);
		break;
	default:
		_muse_core_security_cynara_log_error("cynara_check", ret);
	}

CLEANUP:
	if (user)
		MUSE_FREE(user);
	if (session)
		MUSE_FREE(session);
	if (client)
		MUSE_FREE(client);

	if (ret == CYNARA_API_ACCESS_ALLOWED)
		return true;
	else
		return false;
}

static void _muse_core_security_init_instance(int (*new)(void), void (*free)(void))
{
	g_return_if_fail(new != NULL);
	g_return_if_fail(free != NULL);

	g_muse_core_security = calloc(1, sizeof(*g_muse_core_security));
	g_return_if_fail(g_muse_core_security != NULL);
	g_muse_core_security->p_cynara= NULL;
	g_muse_core_security->new= new;
	g_muse_core_security->free = free;
}

muse_core_security_t *muse_core_security_get_instance(void)
{
	if (g_muse_core_security == NULL)
		_muse_core_security_init_instance(_muse_core_security_cynara_new, _muse_core_security_cynara_free);

	return g_muse_core_security;
}

void muse_core_security_init(void)
{
	LOGD("Enter");

	if (g_muse_core_security == NULL)
		_muse_core_security_init_instance(_muse_core_security_cynara_new, _muse_core_security_cynara_free);

	LOGD("Leave");
}

bool muse_core_security_check_cynara(int fd, const char *privilege)
{
	return _muse_core_security_cynara_check(fd, privilege);
}
