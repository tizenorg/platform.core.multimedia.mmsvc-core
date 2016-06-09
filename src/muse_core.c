/*
 * muse-core
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
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

#include "muse_core.h"
#include "muse_core_private.h"
#include "muse_core_config.h"
#include "muse_core_internal.h"
#include "muse_core_ipc.h"
#include "muse_core_log.h"
#include "muse_core_module.h"
#include "muse_core_workqueue.h"
#include "muse_core_security.h"

#define MUSE_LOG_SLEEP_TIMER 10

static GMainLoop *g_loop;
static GThread *g_thread;
static const char *UDS_files[MUSE_CHANNEL_MAX] = {SOCKFILE0, SOCKFILE1};

static gboolean (*job_functions[MUSE_CHANNEL_MAX])
	(muse_core_workqueue_job_t *job) = {
		muse_core_ipc_job_function,
		muse_core_ipc_data_job_function
	};

static int _muse_core_set_nonblocking(int fd, bool value);
static int _muse_core_check_server_is_running(void);
static muse_core_t *_muse_core_create_new_server_from_fd(int fd[], int type);
static int _muse_core_free(muse_core_t *server);
static int _muse_core_server_new(muse_core_channel_e channel);
static gboolean _muse_core_connection_handler(GIOChannel *source, GIOCondition condition, gpointer data);
static int _muse_core_client_new(muse_core_channel_e channel);

static int _muse_core_set_nonblocking(int fd, bool value)
{
	int flags = fcntl(fd, F_GETFL, NULL);
	char err_msg[MAX_ERROR_MSG_LEN] = {'\0',};

	if (flags >= 0) {
		flags = value ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);

		if (fcntl(fd, F_SETFL, flags) == -1) {
			strerror_r(errno, err_msg, MAX_ERROR_MSG_LEN);
			LOGE("fcntl (%d, F_SETFL) %s", fd, err_msg);
			return -1;
		} else {
			LOGD("fcntl (%d, F_SETFL)", fd);
		}
	}

	return MM_ERROR_NONE;
}

static int _muse_core_check_server_is_running(void)
{
	int fd, already_running;
	int ret = -1;

	/* First, check whether the existing file is locked. */
	fd = open(LOCKFILE, O_RDONLY);
	if (fd == -1 && errno != ENOENT) {
		/* Cannot open file, but it's not because the file doesn't exist. */
		char msg[1024];
		snprintf(msg, sizeof(msg), "datserver: Cannot open lock file %s", LOCKFILE);
		LOGE("open failed: %s ", msg);
		return ret;
	} else if (fd != -1) {
		already_running = flock(fd, LOCK_EX | LOCK_NB) == -1;
		close(fd);
		if (already_running) {
			LOGE("File already locked. There's already a server running");
			return MM_ERROR_NONE;
		}
	}

	/* Lock file does not exist, or is not locked. Create a new lockfile and lock it. */
	fd = open(LOCKFILE, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd == -1) {
		LOGE("dataserver: Cannot create lock file");
		return ret;
	}

	if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
		LOGE("Can't lock the lock file \"%s\". " "Is another instance running?", LOCKFILE);
		close(fd);
		return ret;
	}

	close(fd);
	/* Close out the standard file descriptors */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);

	return 1;
}

static bool _muse_core_attach_server(int fd, muse_module_callback callback, gpointer param)
{
	GIOChannel *channel;
	GSource *src = NULL;

	channel = g_io_channel_unix_new(fd);
	if (!channel)
		return false;

	src = g_io_create_watch(channel, G_IO_IN);
	if (!src) {
		g_io_channel_unref(channel);
		channel = NULL;
		return false;
	}

	g_source_set_callback(src, (GSourceFunc) callback, param, NULL);
	g_source_attach(src, g_main_loop_get_context(g_loop));
	g_source_unref(src);

	g_io_channel_unref(channel);

	return true;
}

static muse_core_t *_muse_core_create_new_server_from_fd(int fd[], int type)
{
	muse_core_t *server;
	int i;

	LOGD("Enter");
	server = malloc(sizeof(muse_core_t));
	g_return_val_if_fail(server != NULL, NULL);

	server->fd = fd[MUSE_CHANNEL_MSG];
	server->data_fd = fd[MUSE_CHANNEL_DATA];
	server->type = type;
	server->stop = 0;
	server->retval = 0;

	/*initiate server */
	g_atomic_int_set(&server->running, 1);

	for (i = 0; i < MUSE_CHANNEL_MAX; i++) {
		if (!_muse_core_attach_server(fd[i], _muse_core_connection_handler, (gpointer)(intptr_t) i)) {
			LOGD("Fail to attach server fd %d", fd[i]);
			muse_core_client_free(server->fd);
			muse_core_client_free(server->data_fd);
			MUSE_FREE(server);
			return NULL;
		}
	}

	LOGD("Leave");
	return server;
}

static int _muse_core_free(muse_core_t *server)
{
	int retval = -1;
	int i;
	LOGD("Enter");

	g_return_val_if_fail(server != NULL, retval);

	retval = server->retval;
	close(server->fd);
	for (i = 0; i < MUSE_CHANNEL_MAX; i++)
		remove(UDS_files[i]);
	remove(LOCKFILE);
	MUSE_FREE(server);
	muse_core_workqueue_get_instance()->shutdown();
	muse_core_config_get_instance()->free();
	muse_core_module_get_instance()->free();
	muse_core_ipc_get_instance()->free();
	muse_core_security_get_instance()->free();
	LOGD("Leave");
	return retval;
}

static int _muse_core_server_new(muse_core_channel_e channel)
{
	int fd;
	struct sockaddr_un addr_un;
	socklen_t address_len;
	char err_msg[MAX_ERROR_MSG_LEN] = {'\0',};

	if (channel >= MUSE_CHANNEL_MAX)
		return -1;

	unlink(UDS_files[channel]);

	/* Create Socket */
	fd = socket(AF_UNIX, SOCK_STREAM, 0); /* Unix Domain Socket */
	if (fd < 0) {
		strerror_r(errno, err_msg, MAX_ERROR_MSG_LEN);
		LOGE("socket failed sock: %s", err_msg);
		return -1;
	} else {
		LOGD("fd: %d", fd);
	}

	memset(&addr_un, 0, sizeof(addr_un));
	addr_un.sun_family = AF_UNIX;
	strncpy(addr_un.sun_path, UDS_files[channel], sizeof(addr_un.sun_path));
	address_len = sizeof(addr_un);

	/* Bind to filename */
	if (bind(fd, (struct sockaddr *)&addr_un, sizeof(addr_un)) < 0) {
		strerror_r(errno, err_msg, MAX_ERROR_MSG_LEN);
		LOGE("bind failed sock: %s", err_msg);
		if (errno == EADDRINUSE)
			unlink(addr_un.sun_path);
		close(fd);
		return -1;
	}

	/* Setup listen queue */
	if (listen(fd, 5) == -1) {
		LOGE("listen failed");
		close(fd);
		return -1;
	}

	if (_muse_core_set_nonblocking(fd, false) < 0) /* blocking */
		LOGE("failed to set server socket to non-blocking");

	return fd;
}

static gboolean _muse_core_connection_handler(GIOChannel *source, GIOCondition condition, gpointer data)
{
	int client_sockfd, server_sockfd;
	socklen_t client_len;
	struct sockaddr_un client_address;
	muse_core_channel_e channel = (muse_core_channel_e)data;
	char err_msg[MAX_ERROR_MSG_LEN] = {'\0',};

	LOGD("Enter");

	muse_module_h module = NULL;
	muse_core_workqueue_job_t *job = NULL;

	server_sockfd = g_io_channel_unix_get_fd(source);

	client_len = sizeof(client_address);
	client_sockfd = accept(server_sockfd, (struct sockaddr *)&client_address, &client_len);
	LOGD("server: %d client: %d", server_sockfd, client_sockfd);

	if (client_sockfd < 0) {
		strerror_r(errno, err_msg, MAX_ERROR_MSG_LEN);
		LOGE("accept: %s\n", err_msg);
		return FALSE;
	}

	if (channel == MUSE_CHANNEL_MSG) {
		if ((module = malloc(sizeof(muse_module_t))) == NULL) {
			LOGE("failed to allocated memory for muse_module_t");
			goto out;
		}

		memset(module, 0, sizeof(muse_module_t));
		module->ch[channel].fd = client_sockfd;
	}

	if ((job = malloc(sizeof(muse_core_workqueue_job_t))) == NULL) {
		LOGE("failed to allocate memory for job state");
		goto out;
	}

	job->job_function = job_functions[channel];
	if (channel == MUSE_CHANNEL_MSG)
		job->user_data = module;
	else
		job->user_data = (void *)(intptr_t)client_sockfd;

	muse_core_workqueue_get_instance()->add_job(job);

	LOGD("Leave");
	return TRUE;
out:
	close(client_sockfd);
	MUSE_FREE(module);
	MUSE_FREE(job);

	LOGE("FALSE");
	return FALSE;
}

static int _muse_core_client_new(muse_core_channel_e channel)
{
	struct sockaddr_un address;
	int len, ret = -1;
	int sockfd;
	char err_msg[MAX_ERROR_MSG_LEN] = {'\0',};

	LOGD("Enter");
	g_return_val_if_fail(channel < MUSE_CHANNEL_MAX, -1);

	/*Create socket*/
	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		strerror_r(errno, err_msg, MAX_ERROR_MSG_LEN);
		LOGE("[socket failure] sock: %s", err_msg);
		return ret;
	} else {
		LOGD("sockfd: %d", sockfd);
		if (fcntl(sockfd, F_SETFD, FD_CLOEXEC) < 0) {
			strerror_r(errno, err_msg, MAX_ERROR_MSG_LEN);
			LOGE("unable to set on ctrls socket fd %d: %s", sockfd, err_msg);
			(void) close(sockfd);
			return -1;
		}
		LOGD("fcntl");
	}

	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	strncpy(address.sun_path, UDS_files[channel], sizeof(address.sun_path));
	len = sizeof(address);

	if (_muse_core_set_nonblocking(sockfd, false) != MM_ERROR_NONE)
		LOGE("Error - fd (%d) set nonblocking", sockfd);

	if ((ret = connect(sockfd, (struct sockaddr *)&address, len)) < 0) {
		LOGE("connect failure");
		(void) close(sockfd);
		return ret;
	}

	LOGD("Leave");
	return sockfd;
}

static muse_client_h _muse_core_client_new_ext(muse_core_channel_e channel)
{
	muse_client_h muse_client;

	g_return_val_if_fail(channel < MUSE_CHANNEL_MAX, NULL);

	muse_client = malloc(sizeof(muse_client_t));
	g_return_val_if_fail(muse_client, NULL);

	memset(muse_client, 0, sizeof(muse_client_t));
	memset(muse_client->cache, 0, MUSE_MSG_MAX_LENGTH * 2);
	muse_client->fd = _muse_core_client_new(channel);

	return muse_client;
}

gpointer muse_core_main_loop(gpointer data)
{
	#if 0
	while (1) {
		sleep(MUSE_LOG_SLEEP_TIMER);
		LOGD("polling %d\n", g_main_loop_is_running(loop));
	}
	#endif

	return NULL;
}

muse_core_t *muse_core_new()
{
	int fd[MUSE_CHANNEL_MAX];
	int i;

	for (i = 0; i < MUSE_CHANNEL_MAX; i++) {
		fd[i] = _muse_core_server_new(i);
		if (fd[i] < 0) {
			LOGE("Failed to create socket server %d", i);
			return NULL;
		}
	}

	/* Initialize work queue */
	if (muse_core_workqueue_init(MUSE_WORK_THREAD_NUM)) {
		LOGE("muse_core_new : Failed to initialize the workqueue");
		for (i = 0; i < MUSE_CHANNEL_MAX; i++)
			close(fd[i]);
		muse_core_workqueue_get_instance()->shutdown();
		return NULL;
	}

	return _muse_core_create_new_server_from_fd(fd, READ | PERSIST);
}

int muse_core_run()
{
	int ret = -1;
	muse_core_t *server;
	GMainContext *context;

	LOGD("Enter");

	ret = _muse_core_check_server_is_running();
	if (ret == -1) {
		return -1;
	} else if (ret == 0) {
		LOGE("Server is already running");
		return 2;
	}

	context = g_main_context_new();
	g_return_val_if_fail(context, MM_ERROR_INVALID_ARGUMENT);
	LOGD("context: %p", context);
	#if 0
	g_loop = g_main_loop_new(context, FALSE);
	#else
	g_loop = g_main_loop_new(NULL, FALSE);
	#endif
	g_main_context_unref(context);

	g_thread = g_thread_new("muse_core_thread", muse_core_main_loop, g_loop);

	server = muse_core_new();
	if (!server) {
		g_main_loop_unref(g_loop);
		return 1;
	}

	LOGD("g_main_loop_run");
	g_main_loop_run(g_loop);

	LOGD("Leave");
	return _muse_core_free(server);
}

void muse_core_cmd_dispatch(muse_module_h module, muse_module_command_e cmd)
{
	muse_module_cmd_dispatchfunc *cmd_dispatcher = NULL;

	g_return_if_fail(module->ch[MUSE_CHANNEL_MSG].dll_handle != NULL);

	g_module_symbol(module->ch[MUSE_CHANNEL_MSG].dll_handle, CMD_DISPATCHER, (gpointer *)&cmd_dispatcher);

	if (cmd_dispatcher && cmd_dispatcher[cmd])
		cmd_dispatcher[cmd](module);
}

int muse_core_client_new(void)
{
	return _muse_core_client_new(MUSE_CHANNEL_MSG);
}

muse_client_h muse_core_client_new_ext(void)
{
	return _muse_core_client_new_ext(MUSE_CHANNEL_MSG);
}

int muse_core_client_get_fd(muse_client_h muse_client)
{
	g_return_val_if_fail(muse_client, MM_ERROR_INVALID_ARGUMENT);

	return muse_client->fd;
}

int muse_core_client_new_data_ch(void)
{
	return _muse_core_client_new(MUSE_CHANNEL_DATA);
}

int muse_core_client_get_msg_fd(muse_module_h module)
{
	g_return_val_if_fail(module, MM_ERROR_INVALID_ARGUMENT);

	return module->ch[MUSE_CHANNEL_MSG].fd;
}

int muse_core_client_get_data_fd(muse_module_h module)
{
	g_return_val_if_fail(module, MM_ERROR_INVALID_ARGUMENT);

	return module->ch[MUSE_CHANNEL_DATA].fd;
}
void muse_core_client_set_cust_data(muse_module_h module, void *data)
{
	g_return_if_fail(module);
	module->usr_data= data;
}

void *muse_core_client_get_cust_data(muse_module_h module)
{
	g_return_val_if_fail(module, NULL);
	return module->usr_data;
}

char *muse_core_client_get_msg(muse_module_h module)
{
	g_return_val_if_fail(module, NULL);
	return (module->recvMsg + module->msg_offset);
}

int muse_core_client_get_capi(muse_module_h module)
{
	g_return_val_if_fail(module, MM_ERROR_INVALID_ARGUMENT);
	return module->disp_api;
}

int muse_core_client_set_value(muse_module_h module, const char *value_name, int set_value)
{
	g_return_val_if_fail(module, MM_ERROR_INVALID_ARGUMENT);
	g_return_val_if_fail(value_name, MM_ERROR_INVALID_ARGUMENT);
	muse_core_module_get_instance()->set_value(module->api_module, value_name, set_value);
	return MM_ERROR_NONE;
}

int muse_core_client_get_value(muse_module_h module, const char *value_name, int *get_value)
{
	g_return_val_if_fail(module, MM_ERROR_INVALID_ARGUMENT);
	g_return_val_if_fail(value_name, MM_ERROR_INVALID_ARGUMENT);
	g_return_val_if_fail(get_value, MM_ERROR_INVALID_ARGUMENT);

	return muse_core_module_get_instance()->get_value(module->api_module, value_name, get_value);
}

void muse_core_client_free(int sock_fd)
{
	if (sock_fd > 0) {
		LOGD("[sock_fd: %d] shutdown", sock_fd);
		shutdown(sock_fd, SHUT_RDWR);
		close(sock_fd);
	}
}

void muse_core_client_free_ext(muse_client_h muse_client)
{
	g_return_if_fail(muse_client);
	MUSE_FREE(muse_client);
}

void muse_core_worker_exit(muse_module_h module)
{
	LOGD("Enter");
	g_return_if_fail(module);

	muse_core_client_free(module->ch[MUSE_CHANNEL_MSG].fd);
	muse_core_client_free(module->ch[MUSE_CHANNEL_DATA].fd);

	LOGD("%p thread exit", module->ch[MUSE_CHANNEL_MSG].p_gthread);
	if (module->ch[MUSE_CHANNEL_MSG].p_gthread)
		g_thread_unref(module->ch[MUSE_CHANNEL_MSG].p_gthread);

	if (module->ch[MUSE_CHANNEL_DATA].p_gthread)
		g_thread_unref(module->ch[MUSE_CHANNEL_DATA].p_gthread);
	MUSE_FREE(module);

	LOGD("Leave");
	g_thread_exit(NULL);
}

unsigned muse_core_get_atomic_uint(void)
{
	static guint atom = 0;

	g_atomic_int_inc(&atom);

	return atom;
}